"""
Authentication and authorization module
"""

import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from another_s3_manager.constants import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    BAN_DURATION_MINUTES,
    JWT_ALGORITHM,
    MAX_LOGIN_ATTEMPTS,
)

logger = logging.getLogger(__name__)

# Initialize password context with bcrypt, fallback to pbkdf2_sha256 if bcrypt fails
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception as e:
    print(f"Warning: bcrypt initialization failed: {e}. Using pbkdf2_sha256 instead.")
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Login attempts tracking (in-memory, resets on restart)
_login_attempts: Dict[str, Dict[str, Any]] = {}


def get_jwt_secret_key() -> str:
    """Get JWT secret key. Raises error if not set."""
    jwt_secret_key = os.getenv("JWT_SECRET_KEY", None)
    if not jwt_secret_key or jwt_secret_key.strip() == "" or jwt_secret_key == "your-secret-key-change-in-production":
        raise ValueError("JWT_SECRET_KEY environment variable is required and must be set")
    return jwt_secret_key


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        # Truncate password if too long for bcrypt
        password_bytes = plain_password.encode("utf-8")
        if len(password_bytes) > 72:
            plain_password = password_bytes[:72].decode("utf-8", errors="ignore")
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as primary_exc:
        # Try pbkdf2_sha256 fallback before giving up — historical migration path.
        try:
            pwd_context_fallback = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
            return pwd_context_fallback.verify(plain_password, hashed_password)
        except Exception as fallback_exc:
            # Both schemes failed — the hash is likely corrupted. Return False so
            # the user gets a normal "wrong password" response, but warn so
            # operators can spot data corruption in the logs.
            logger.warning(
                "verify_password: both bcrypt and pbkdf2_sha256 raised; treating as failure (primary=%s, fallback=%s)",
                primary_exc,
                fallback_exc,
            )
            return False


def hash_password(password: str) -> str:
    """Hash a password."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode("utf-8", errors="ignore")

    try:
        return pwd_context.hash(password)
    except ValueError as e:
        if "password cannot be longer than 72 bytes" in str(e):
            pwd_context_fallback = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
            return pwd_context_fallback.hash(password)
        raise


def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(32)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token with CSRF token."""
    to_encode = data.copy()
    # Add CSRF token to JWT
    if "csrf_token" not in to_encode:
        to_encode["csrf_token"] = generate_csrf_token()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, get_jwt_secret_key(), algorithm=JWT_ALGORITHM)
    return encoded_jwt


def _decode_session_payload(request: Request) -> Optional[Dict[str, Any]]:
    """Read the `access_token` cookie and decode it as a JWT session payload.

    Returns None if the cookie is missing, or if decoding fails for any
    reason (bad signature, malformed token, expired `exp` claim — jose raises
    `JWTError`/`ExpiredSignatureError` for all of these). Pure JWT decode,
    no DB access. Shared by `has_valid_session` (cheap, DB-free check) and
    `get_current_user` (authoritative check) so the two can never drift on
    secret/algorithm/expiry handling.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        return jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def has_valid_session(request: Request) -> bool:
    """Cheap, DB-free check that the request carries a valid, unexpired JWT
    session cookie. Used by the upload body-guard to reject unauthenticated
    uploads BEFORE the body is read, WITHOUT the synchronous load_users() DB
    query that get_current_user does (which must not run on the event loop).
    A valid JWT whose user was since deleted still passes here; the handler's
    Depends(get_current_user) does the authoritative user lookup and rejects
    it — that is an authenticated actor, not an unauthenticated DoS vector.
    """
    payload = _decode_session_payload(request)
    return payload is not None and payload.get("sub") is not None


def get_current_user(request: Request) -> Dict[str, Any]:
    """Get current authenticated user from JWT token in httpOnly cookie.

    Uses the targeted `get_user_by_username` lookup (a single indexed query)
    rather than loading every user row — this dependency runs on every
    authenticated request, so an O(N) `load_users()` scan would mean loading
    the entire users table (plus a roles join) just to find the one user who
    made the request.
    """
    # Import here to avoid circular dependency
    from another_s3_manager.users import get_user_by_username

    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = _decode_session_payload(request)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    username: Optional[str] = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # Add CSRF token from JWT to user dict for validation
    user["csrf_token"] = payload.get("csrf_token")

    return user


def verify_csrf_token(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)) -> bool:
    """Verify CSRF token from request header."""
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    expected_token = current_user.get("csrf_token")
    if not expected_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token not found in session")

    if not secrets.compare_digest(csrf_token, expected_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")

    return True


def get_current_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get current user and verify admin privileges."""
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


def check_ban(username: str) -> bool:
    """Check if user is banned."""
    # Import here to avoid circular dependency
    from another_s3_manager.users import load_bans, save_bans

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

    from another_s3_manager.users import count_users, get_user_by_username, load_bans, load_users, save_bans

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
