"""Web authentication dependencies and compatibility helper exports."""

import secrets
from typing import Any, Dict, Literal

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

_WEB_AUTH_ERRORS = {
    "cookie": {
        "missing_credentials": (401, "Not authenticated", None),
        "invalid_session": (401, "Invalid authentication credentials", None),
        "user_not_found": (401, "User not found", None),
    },
    "login": {
        "LOCAL_LOGIN_DISABLED": (403, lambda error: {"code": error.code, "message": error.message}, "invalid_password"),
        "banned": (403, None, "banned"),
        "invalid_password": (401, None, "invalid_password"),
    },
    "download": {"refused": (401, "Authentication required", None)},
    "account": {
        "password_policy": (422, lambda error: {"error": error.message, **error.details}, None),
        "MANAGED_BY_SSO": (409, lambda error: {"code": error.code, "message": error.message}, None),
        "NO_LOCAL_PASSWORD": (409, lambda error: {"code": error.code, "message": error.message}, None),
        "LAST_LOCAL_ADMIN": (409, lambda error: {"code": error.code, "message": error.message}, None),
        "self_delete": (400, None, None),
        "self_demote": (400, None, None),
        "self_disable": (400, None, None),
        "admin_required": (403, None, None),
        "account_not_found": (404, None, None),
        "incorrect_current_password": (401, None, None),
        "same_password": (400, None, None),
        "user_not_found": (401, "User not found", None),
    },
}

for _door in ("cookie", "login", "account"):
    _WEB_AUTH_ERRORS[_door].update(
        {
            code: (
                401,
                "Incorrect username or password" if _door == "login" else "Invalid authentication credentials",
                "invalid_password" if _door == "login" else None,
            )
            for code in access.CURRENT_ACCOUNT_DENIALS
        }
    )
_WEB_AUTH_ERRORS["cookie"]["incorrect_current_password"] = (401, "Current password is incorrect", None)


def map_web_auth_error(
    door: Literal["cookie", "login", "download", "account"], error: access.AccessDenied | None = None
) -> tuple[int, Any, str | None]:
    """Preserve each web door's legacy status, detail and metric reason."""
    code = error.code if error is not None else "missing_credentials"
    status_code, detail, reason = _WEB_AUTH_ERRORS[door]["refused" if door == "download" else code]
    if callable(detail):
        detail = detail(error)
    return status_code, detail if detail is not None else error.message, reason


def _decode_session_payload(request: Request):
    return access.decode_session_payload(request.cookies.get("access_token", ""))


def has_valid_session(request: Request) -> bool:
    return access.session_token_is_wellformed(request.cookies.get("access_token", ""))


def get_current_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get("access_token")
    if not token:
        status_code, detail, _ = map_web_auth_error("cookie")
        raise HTTPException(status_code=status_code, detail=detail)
    try:
        return access.authenticate_session(token).to_user_dict()
    except access.AuthenticationError as error:
        status_code, detail, _ = map_web_auth_error("cookie", error)
        raise HTTPException(status_code=status_code, detail=detail) from None


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
