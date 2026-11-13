"""Transport-independent HS256 session signing and decoding."""

import os
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
    try:
        return jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
