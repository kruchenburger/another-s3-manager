"""Transport-independent HS256 session signing and decoding."""

import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from another_s3_manager.constants import ACCESS_TOKEN_EXPIRE_MINUTES, JWT_ALGORITHM


def get_jwt_secret_key() -> str:
    """Get JWT secret key. Raises error if not set."""
    jwt_secret_key = os.getenv("JWT_SECRET_KEY", None)
    if not jwt_secret_key or jwt_secret_key.strip() == "" or jwt_secret_key == "your-secret-key-change-in-production":
        raise ValueError("JWT_SECRET_KEY environment variable is required and must be set")
    return jwt_secret_key


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


def decode_session_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode only the credential, without reading account state."""
    if not token:
        return None
    secret = get_jwt_secret_key()
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except (JWTError, TypeError, ValueError):
        # python-jose can raise TypeError for malformed numeric claim containers.
        # Configuration errors above remain visible instead of becoming a 401.
        return None


def validate_lifetime_minutes(value=None):
    """None inherits the configured local TTL; invalid values never fall back."""
    if value is None:
        # Empty counts as unset, like constants.py: compose "${VAR:-}" yields "".
        raw = os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES") or "180"
        try:
            if not re.fullmatch(r"[0-9]+", raw):
                raise ValueError("Invalid decimal lifetime")
            value = int(raw)
        except (ValueError, TypeError):
            raise ValueError("Invalid session lifetime") from None
    if type(value) is not int or not 1 <= value <= 10080:
        raise ValueError("Session lifetime must be an integer between 1 and 10080")
    return value


def issue_session(principal, *, method: str, lifetime_minutes: int) -> str:
    lifetime = validate_lifetime_minutes(lifetime_minutes)
    if method not in {"pwd", "oidc"}:
        raise ValueError("Unknown authentication method")
    user = principal.user
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {
            "sub": principal.username,
            "uid": principal.id,
            "ugen": user["auth_generation"],
            "sv": user["session_epoch"],
            "amr": method,
            "sid": secrets.token_urlsafe(16),
            "csrf_token": generate_csrf_token(),
            "iat": now,
            "exp": now + lifetime * 60,
        },
        get_jwt_secret_key(),
        algorithm="HS256",
    )


def required_session_payload(token):
    payload = decode_session_payload(token)
    if payload is None:
        return None
    if any(
        not isinstance(payload.get(key), str) or not payload[key] for key in ("sub", "ugen", "csrf_token", "sid", "amr")
    ):
        return None
    if any(type(payload.get(key)) is not int for key in ("uid", "sv", "iat", "exp")):
        return None
    if payload["uid"] <= 0 or payload["sv"] < 0 or payload["amr"] not in {"pwd", "oidc"}:
        return None
    if payload["iat"] > int(datetime.now(UTC).timestamp()) or payload["exp"] <= payload["iat"]:
        return None
    return payload
