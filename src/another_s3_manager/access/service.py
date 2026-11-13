"""Application API for access policies, independent of transports."""

import hashlib
import logging
import time
from typing import Any, Dict

from another_s3_manager.access import passwords, policies, sessions, tokens, users
from another_s3_manager.access.errors import AccessDenied, AuthenticationError
from another_s3_manager.access.principal import BearerAuthentication, Principal, account_identity
from another_s3_manager.constants import BAN_DURATION_MINUTES, MAX_LOGIN_ATTEMPTS

logger = logging.getLogger("another_s3_manager.auth")
_login_attempts: Dict[str, Dict[str, Any]] = {}

_WRITE_MESSAGES = {
    "writes_disabled": "Server config disables MCP writes",
    "read_only_token": "This token is read-only",
    "deletion_disabled": "Deletion is disabled in server config",
}


def allowed_roles(user: dict, config: dict) -> list[str]:
    return policies.granted_roles(user, config)


def require_role_name(role: str | None) -> str:
    if role is None or not role.strip():
        raise AccessDenied("role_required", "A role is required for this request.")
    return role


def require_role(role: str | None, user: dict, config: dict) -> str:
    role = require_role_name(role)
    if not policies.role_is_granted(role, user, config):
        raise AccessDenied("role_not_allowed", f"Access denied: You don't have permission to use role '{role}'")
    return role


def require_bucket(role: str, bucket: str, user: dict, config: dict) -> None:
    """Check the bucket after the caller's role and role-existence checks.

    Keep these checks separate: legacy adapters load configuration between
    them, and role existence has adapter-specific error handling.
    """
    role_config = next((r for r in config.get("roles", []) if r.get("name") == role), None)
    if role_config is None:
        # Callers check existence first; fail closed if one ever does not.
        raise AccessDenied("role_not_found", f"Role '{role}' not found in configuration")
    if not policies.bucket_is_allowed(role_config, bucket):
        raise AccessDenied("bucket_not_allowed", f"bucket '{bucket}' not in allowed_buckets for role '{role}'")


def require_transfer(user: dict, role: str, source_bucket: str, dest_bucket: str, config: dict) -> None:
    """Authorize both ends of a transfer without requiring deletion permission."""
    role = require_role(role, user, config)
    require_bucket(role, source_bucket, user, config)
    require_bucket(role, dest_bucket, user, config)


def require_delete(role_name: str | None, config: dict) -> None:
    if not policies.deletion_allowed(config, None):
        raise AccessDenied("DELETION_DISABLED", _WRITE_MESSAGES["deletion_disabled"])
    if not policies.deletion_allowed(config, role_name):
        raise AccessDenied("DELETION_DISABLED_FOR_ROLE", f"Deleting is turned off for role '{role_name}'")


def require_destructive(user: dict, role: str, bucket: str, config: dict) -> None:
    """Authorize a destructive operation using one supplied state snapshot."""
    role = require_role(role, user, config)
    require_bucket(role, bucket, user, config)
    require_delete(role, config)


def require_not_deletion_disabled(config: dict) -> None:
    """Compatibility API for callers that only know the instance-wide gate."""
    try:
        require_delete(None, config)
    except AccessDenied as error:
        raise AccessDenied("deletion_disabled", error.message) from None


def require_write(token_is_read_only: bool, tool_name: str, config: dict) -> None:
    reason = policies.write_denial(token_is_read_only, tool_name, config)
    if reason is not None:
        raise AccessDenied(reason, _WRITE_MESSAGES[reason], {"tool": tool_name})


def check_ban(username: str) -> bool:
    """Check if user is banned."""
    # Import here to avoid circular dependency
    from another_s3_manager.access.users import load_bans, save_bans

    bans = load_bans()
    if username in bans:
        ban_data = bans[username]
        banned_until = ban_data.get("banned_until", 0)
        if time.time() < banned_until:
            return True
        else:
            # Ban expired, remove it
            del bans[username]
            save_bans(bans)
    return False


def record_login_attempt(username: str, success: bool) -> None:
    """Record a login attempt and ban user if too many failures.

    Admins are exempt from auto-ban: the `admin` username is predictable, and a
    drive-by attacker could lock the only admin out of the system with three
    wrong-password requests. Brute-force defense for admin accounts must come
    from the deployment layer (Cloudflare Access / WAF / strong password / 2FA),
    not from auto-ban.
    """
    # Import here to avoid circular dependency
    from datetime import datetime

    from another_s3_manager.access.users import count_users, get_user_by_username, load_bans, load_users, save_bans

    if username not in _login_attempts:
        _login_attempts[username] = {"attempts": [], "failed_count": 0}

    user_attempts = _login_attempts[username]
    current_time = time.time()

    # Remove attempts older than 1 hour
    user_attempts["attempts"] = [
        attempt_time for attempt_time in user_attempts["attempts"] if current_time - attempt_time < 3600
    ]

    if success:
        # Reset on successful login
        user_attempts["failed_count"] = 0
        user_attempts["attempts"] = []
    else:
        # Record failed attempt
        user_attempts["attempts"].append(current_time)
        user_attempts["failed_count"] = len(user_attempts["attempts"])

        # Ban if too many failures — but never ban an admin (DoS-on-admin protection).
        if user_attempts["failed_count"] >= MAX_LOGIN_ATTEMPTS:
            # Targeted lookup — this only needs to know whether the ONE username
            # being banned belongs to an admin, not every user in the system.
            # Falls back to load_users() only in the genuinely empty-table case
            # (mirrors login()'s identical fallback): load_users() lazily seeds
            # the default admin, and without this a fresh deployment's very
            # first failed "admin" login would incorrectly get banned instead
            # of hitting the admin exemption below.
            user_record = get_user_by_username(username)
            if user_record is None and count_users() == 0:
                load_users()
                user_record = get_user_by_username(username)
            if user_record and user_record.get("is_admin"):
                # Admin — log the burst but don't ban.
                logger.warning(
                    "%d failed login attempts for admin '%s' (not banning)",
                    user_attempts["failed_count"],
                    username,
                )
                return

            bans = load_bans()
            banned_until = current_time + (BAN_DURATION_MINUTES * 60)
            bans[username] = {
                "banned_until": banned_until,
                "banned_at": current_time,
                "reason": "Too many failed login attempts",
            }
            save_bans(bans)
            from another_s3_manager.metrics import auth_bans_total

            auth_bans_total.inc()
            logger.warning("User %s banned until %s", username, datetime.fromtimestamp(banned_until))


def authenticate_session(token: str) -> Principal:
    payload = sessions.decode_session_payload(token)
    if payload is None or payload.get("sub") is None:
        raise AuthenticationError("invalid_session", "Invalid authentication credentials")
    user = users.get_user_by_username(payload["sub"])
    if user is None:
        raise AuthenticationError("user_not_found", "User not found")
    user["csrf_token"] = payload.get("csrf_token")
    return Principal(user)


def session_token_is_wellformed(token: str) -> bool:
    """Signature/expiry/sub prefilter only; never an account authorization."""
    payload = sessions.decode_session_payload(token)
    return payload is not None and payload.get("sub") is not None


def principal_for(user_id: int, *, expected_identity=None) -> Principal:
    user = users.get_user_by_id(user_id)
    if user is None:
        raise AuthenticationError("user_not_found", "User not found")
    if expected_identity is not None and account_identity(user) != expected_identity:
        raise AuthenticationError("account_replaced", "User not found")
    return Principal(user)


def authenticate_bearer(authorization: str, config: dict) -> BearerAuthentication:
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("malformed_bearer", "Missing or malformed Bearer token")
    plaintext = authorization[len("Bearer ") :]
    if not plaintext.startswith("as3m_"):
        raise AuthenticationError("wrong_token_prefix", "Token does not start with as3m_")
    token = tokens.find_active_token_by_hash(hashlib.sha256(plaintext.encode()).hexdigest())
    if token is None:
        raise AuthenticationError("invalid_token", "Invalid or revoked token")
    # Keep the existing separate token and owner reads; generation binding is PR 2.
    user = users.get_user_by_id(token.user_id)
    if user is None:
        raise AuthenticationError("orphan_token", "Token's user no longer exists")
    principal = Principal(user)
    tokens.touch_last_used(token.id)
    return BearerAuthentication(token, principal)


def authenticate_local(username: str, password: str, config: dict) -> Principal:
    if check_ban(username):
        ban_data = users.load_bans().get(username, {})
        remaining = int((ban_data.get("banned_until", 0) - time.time()) / 60)
        raise AuthenticationError("banned", f"Account is banned. Try again in {remaining} minutes.")
    user = users.get_user_by_username(username)
    if user is None and users.count_users() == 0:
        users.load_users()
        user = users.get_user_by_username(username)
    if user is None or not passwords.verify_password(password, user.get("password_hash", "")):
        record_login_attempt(username, False)
        raise AuthenticationError("invalid_password", "Incorrect username or password")
    record_login_attempt(username, True)
    return Principal(user)
