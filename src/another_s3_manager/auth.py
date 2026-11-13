"""Web authentication dependencies and compatibility helper exports."""

import secrets
from typing import Any, Dict

from fastapi import Depends, HTTPException, Request, status

from another_s3_manager import access
from another_s3_manager.access import (
    check_ban as check_ban,
)
from another_s3_manager.access import (
    create_access_token as create_access_token,
)
from another_s3_manager.access import (
    generate_csrf_token as generate_csrf_token,
)
from another_s3_manager.access import (
    get_jwt_secret_key as get_jwt_secret_key,
)
from another_s3_manager.access import (
    hash_password as hash_password,
)
from another_s3_manager.access import (
    pwd_context as pwd_context,
)
from another_s3_manager.access import (
    record_login_attempt as record_login_attempt,
)
from another_s3_manager.access import (
    verify_password as verify_password,
)
from another_s3_manager.constants import MAX_LOGIN_ATTEMPTS as MAX_LOGIN_ATTEMPTS

_SESSION_ERRORS = {
    "invalid_session": (401, "Invalid authentication credentials"),
    "user_not_found": (401, "User not found"),
}


def _decode_session_payload(request: Request):
    return access.decode_session_payload(request.cookies.get("access_token", ""))


def has_valid_session(request: Request) -> bool:
    return access.session_token_is_wellformed(request.cookies.get("access_token", ""))


def get_current_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return access.authenticate_session(token).to_user_dict()
    except access.AuthenticationError as error:
        code, detail = _SESSION_ERRORS[error.code]
        raise HTTPException(status_code=code, detail=detail) from None


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
