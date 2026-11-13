"""Password hashing and historical fallback behavior."""

import logging

from passlib.context import CryptContext

logger = logging.getLogger("another_s3_manager.auth")

# Initialize password context with bcrypt, fallback to pbkdf2_sha256 if bcrypt fails
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception as e:
    print(f"Warning: bcrypt initialization failed: {e}. Using pbkdf2_sha256 instead.")
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


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
