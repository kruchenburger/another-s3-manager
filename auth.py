"""
Authentication and authorization module
"""
import os
import secrets
import time
from datetime import datetime, timedelta, UTC
from typing import Dict, Any, Optional

from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

try:
    from constants import (
        JWT_ALGORITHM,
        ACCESS_TOKEN_EXPIRE_MINUTES,
        MAX_LOGIN_ATTEMPTS,
        BAN_DURATION_MINUTES,
    )
except ImportError:
    # Fallback for direct execution
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
    MAX_LOGIN_ATTEMPTS = 3
    BAN_DURATION_MINUTES = 60


# Initialize password context with bcrypt, fallback to pbkdf2_sha256 if bcrypt fails
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception as e:
    print(f"Warning: bcrypt initialization failed: {e}. Using pbkdf2_sha256 instead.")
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

security = HTTPBearer()

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
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72:
            plain_password = password_bytes[:72].decode('utf-8', errors='ignore')
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # If verification fails, try with pbkdf2_sha256 context
        try:
            pwd_context_fallback = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
            return pwd_context_fallback.verify(plain_password, hashed_password)
        except Exception:
            return False


def hash_password(password: str) -> str:
    """Hash a password."""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode('utf-8', errors='ignore')

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


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user from JWT token."""
    # Import here to avoid circular dependency
    from users import load_users, save_users

    try:
        token = credentials.credentials
        payload = jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Add CSRF token from JWT to user dict for validation
    user["csrf_token"] = payload.get("csrf_token")

    # Ensure theme field exists (migration for old users)
    if "theme" not in user:
        user["theme"] = "auto"
        # Update in users file
        for u in users.get("users", []):
            if u.get("username") == username:
                u["theme"] = "auto"
        save_users(users)

    return user


def verify_csrf_token(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> bool:
    """Verify CSRF token from request header."""
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing"
        )

    expected_token = current_user.get("csrf_token")
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token not found in session"
        )

    if not secrets.compare_digest(csrf_token, expected_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token"
        )

    return True


def get_current_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get current user and verify admin privileges."""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def check_ban(username: str) -> bool:
    """Check if user is banned."""
    # Import here to avoid circular dependency
    from users import load_bans, save_bans

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
    """Record a login attempt and ban user if too many failures."""
    # Import here to avoid circular dependency
    from users import load_bans, save_bans
    from datetime import datetime

    if username not in _login_attempts:
        _login_attempts[username] = {"attempts": [], "failed_count": 0}

    user_attempts = _login_attempts[username]
    current_time = time.time()

    # Remove attempts older than 1 hour
    user_attempts["attempts"] = [
        attempt_time for attempt_time in user_attempts["attempts"]
        if current_time - attempt_time < 3600
    ]

    if success:
        # Reset on successful login
        user_attempts["failed_count"] = 0
        user_attempts["attempts"] = []
    else:
        # Record failed attempt
        user_attempts["attempts"].append(current_time)
        user_attempts["failed_count"] = len(user_attempts["attempts"])

        # Ban if too many failures
        if user_attempts["failed_count"] >= MAX_LOGIN_ATTEMPTS:
            bans = load_bans()
            banned_until = current_time + (BAN_DURATION_MINUTES * 60)
            bans[username] = {
                "banned_until": banned_until,
                "banned_at": current_time,
                "reason": "Too many failed login attempts"
            }
            save_bans(bans)
            print(f"User {username} banned until {datetime.fromtimestamp(banned_until)}")

