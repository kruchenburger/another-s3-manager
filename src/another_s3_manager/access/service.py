"""Application API for access policies, independent of transports."""

import hashlib
import logging
import time
from collections.abc import Callable
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


def authenticate_session(token: str, *, require_subject: bool = False) -> Principal:
    payload = sessions.required_session_payload(token)
    if payload is None:
        raise AuthenticationError("invalid_session", "Invalid authentication credentials")
    principal = principal_for(payload["uid"], expected_identity=(payload["uid"], payload["ugen"]))
    if principal.username != payload["sub"]:
        raise AuthenticationError("ACCOUNT_REPLACED", "Invalid authentication credentials")
    if principal.user["session_epoch"] != payload["sv"]:
        raise AuthenticationError("SESSION_EPOCH_MISMATCH", "Invalid authentication credentials")
    return Principal(
        {**principal.user, "csrf_token": payload["csrf_token"], "amr": payload["amr"], "sid": payload["sid"]}
    )


def session_token_is_wellformed(token: str) -> bool:
    """DB-free, nonauthoritative upload prefilter."""
    return sessions.required_session_payload(token) is not None


_NO_SNAPSHOT = object()


def principal_for(user_id: int, *, expected_identity=None, _snapshot=_NO_SNAPSHOT) -> Principal:
    """Resolve status once, optionally within an existing trusted fresh snapshot.

    The private seam is only for serialized Access transactions and Storage's
    freshly loaded per-attempt state. It must never receive request-cached data.
    An explicit missing snapshot stays missing; it cannot adopt a replacement.
    """
    user = users.get_user_by_id(user_id) if _snapshot is _NO_SNAPSHOT else _snapshot
    if user is None:
        raise AuthenticationError("user_not_found", "User not found")
    if expected_identity is not None and account_identity(user) != expected_identity:
        raise AuthenticationError("ACCOUNT_REPLACED", "Invalid authentication credentials")
    if user.get("is_disabled"):
        raise AuthenticationError("ACCOUNT_DISABLED", "Invalid authentication credentials")
    # Applied-sync freshness is introduced by PR 3, not inferred from NULL here.
    return Principal(user)


def authenticate_bearer(authorization: str, config_loader: Callable[[], dict]) -> BearerAuthentication:
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("malformed_bearer", "Missing or malformed Bearer token")
    plaintext = authorization[len("Bearer ") :]
    if not plaintext.startswith("as3m_"):
        raise AuthenticationError("wrong_token_prefix", "Token does not start with as3m_")
    result = tokens.find_active_token_with_owner(hashlib.sha256(plaintext.encode()).hexdigest())
    if result is None:
        raise AuthenticationError("invalid_token", "Invalid or revoked token")
    token, user = result
    if user is None:
        raise AuthenticationError("orphan_token", "Token's user no longer exists")
    principal = principal_for(user["id"], expected_identity=account_identity(user))
    config = config_loader()
    projected_roles = allowed_roles(principal.to_user_dict(), config)
    tokens.touch_last_used(token.id)
    return BearerAuthentication(token, principal, projected_roles)


def authenticate_local(username: str, password: str, config: dict) -> Principal:
    if check_ban(username):
        ban_data = users.load_bans().get(username, {})
        remaining = int((ban_data.get("banned_until", 0) - time.time()) / 60)
        raise AuthenticationError("banned", f"Account is banned. Try again in {remaining} minutes.")
    user = users.get_user_by_username(username)
    if user is None and users.count_users() == 0:
        users.load_users()
        user = users.get_user_by_username(username)
    try:
        if user is None:
            raise AuthenticationError("invalid_password", "Incorrect username or password")
        principal_for(user["id"], expected_identity=account_identity(user))
        if user["auth_source"] != "local" or not passwords.verify_password(password, user.get("password_hash", "")):
            raise AuthenticationError("invalid_password", "Incorrect username or password")
        principal = _confirm_password_snapshot(user)
    except AuthenticationError:
        # The login door must not reveal account status or a concurrent revocation.
        record_login_attempt(username, False)
        raise AuthenticationError("invalid_password", "Incorrect username or password") from None
    record_login_attempt(username, True)
    return principal


def _password_snapshot(user):
    return (*account_identity(user), user["session_epoch"], user["password_hash"])


def _confirm_password_snapshot(snapshot, *, new_hash=None):
    """A proof of one hash never acquires a later generation or epoch."""
    from sqlalchemy import select

    from another_s3_manager.models import User

    with users.write_scope() as session:
        row = session.execute(select(User).where(User.id == snapshot["id"])).scalar_one_or_none()
        if row is None:
            raise AuthenticationError("ACCOUNT_REPLACED", "Invalid authentication credentials")
        current = users._user_to_dict(users.materialize_generation(session, row))
        principal = principal_for(row.id, expected_identity=account_identity(snapshot), _snapshot=current)
        if current["auth_source"] != "local" or _password_snapshot(current) != _password_snapshot(snapshot):
            raise AuthenticationError("SESSION_EPOCH_MISMATCH", "Invalid authentication credentials")
        if new_hash is not None:
            users.write_password(row, new_hash, "ui")
            row.must_change_password = False
        return principal


def change_own_password(actor, current_password, new_password, *, policy=None):
    principal = principal_for(actor["id"], expected_identity=account_identity(actor))
    snapshot = principal.user
    if not passwords.verify_password(current_password, snapshot["password_hash"]):
        raise AuthenticationError("incorrect_current_password", "Current password is incorrect")
    if current_password == new_password:
        raise AccessDenied("same_password", "New password must differ from the current one")
    from another_s3_manager.utils import validate_password

    failures = validate_password(new_password, policy or {})
    if failures:
        raise AccessDenied("password_policy", "Password does not meet policy", {"failed_requirements": failures})
    _confirm_password_snapshot(snapshot, new_hash=passwords.hash_password(new_password))


def _lifecycle(actor, username, changes, *, deleting=False):
    from sqlalchemy import func, select

    from another_s3_manager.models import User

    with users.write_scope() as session:
        acting = session.execute(select(User).where(User.id == actor["id"])).scalar_one_or_none()
        if acting is None:
            raise AuthenticationError("ACCOUNT_REPLACED", "Invalid authentication credentials")
        current_actor = users._user_to_dict(users.materialize_generation(session, acting))
        principal_for(acting.id, expected_identity=account_identity(actor), _snapshot=current_actor)
        if current_actor["session_epoch"] != actor["session_epoch"]:
            raise AuthenticationError("SESSION_EPOCH_MISMATCH", "Invalid authentication credentials")
        if not acting.is_admin:
            raise AccessDenied("admin_required", "Admin privileges required")
        row = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if row is None:
            if deleting:
                return None
            raise AccessDenied("account_not_found", "User not found")
        if row.id == acting.id:
            if deleting:
                raise AccessDenied("self_delete", "Cannot delete yourself")
            if changes.get("is_admin") is False:
                raise AccessDenied("self_demote", "You can't remove your own admin rights.")
            if changes.get("is_disabled") is True:
                raise AccessDenied("self_disable", "Cannot disable yourself")
        removes_admin = deleting or changes.get("is_admin") is False or changes.get("is_disabled") is True
        if removes_admin and row.is_admin and not row.is_disabled and row.auth_source == "local":
            count = session.scalar(
                select(func.count())
                .select_from(User)
                .where(User.is_admin.is_(True), User.is_disabled.is_(False), User.auth_source == "local")
            )
            if count <= 1:
                raise AccessDenied("LAST_LOCAL_ADMIN", "Cannot remove the last enabled local administrator")
        if deleting:
            session.delete(row)
            return None
        return users.update_user(username, _session=session, **changes)


def update_account(actor, username, changes):
    return _lifecycle(actor, username, changes)


def delete_account(actor, username):
    return _lifecycle(actor, username, {}, deleting=True)
