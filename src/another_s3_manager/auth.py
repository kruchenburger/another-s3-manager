"""Web authentication dependencies and compatibility helper exports."""

import logging
import secrets
from typing import Any, Dict, Literal

from fastapi import Depends, HTTPException, Request, status

from another_s3_manager import access, constants
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

_WEB_OIDC_ERRORS = {
    "start": {"OIDC_DISABLED": 404, "default": 503},
    "callback": {"OIDC_DISABLED": 404, "default": None},
}


def map_web_oidc_error(door: Literal["start", "callback"], code: str | None) -> int | None:
    """Map OIDC refusals; None keeps the callback's normal redirect/session path."""
    mapping = _WEB_OIDC_ERRORS[door]
    return mapping.get(code, mapping["default"])


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


# The one home for browser cookie names, paths and attributes. With Secure cookies
# (the default) both cookies carry the __Host- prefix: Secure, Path=/, no Domain, so a
# sibling subdomain cannot plant them. COOKIE_SECURE=false (plain HTTP on local or
# trusted networks) keeps the historical names and paths.
_HOST_PREFIX = "__Host-"
_LEGACY_SESSION_COOKIE = "access_token"
_OIDC_TX_PREFIX = "oidc_tx_"
_OIDC_TX_LEGACY_PATH = "/api/auth/oidc/"
_logger = logging.getLogger(__name__)


def cookies_secure() -> bool:
    return constants.COOKIE_SECURE


def session_cookie_name() -> str:
    return _HOST_PREFIX + _LEGACY_SESSION_COOKIE if cookies_secure() else _LEGACY_SESSION_COOKIE


def session_cookie(request: Request) -> str | None:
    """The session token; in Secure mode a leftover plain access_token is not a session."""
    return request.cookies.get(session_cookie_name())


def _delete_legacy_session_cookie(response) -> None:
    if cookies_secure():
        response.delete_cookie(_LEGACY_SESSION_COOKIE, path="/")


def set_session_cookie(response, token: str, max_age: int) -> None:
    secure = cookies_secure()
    _delete_legacy_session_cookie(response)
    response.set_cookie(
        session_cookie_name(),
        token,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
        max_age=max_age,
    )


def clear_session_cookie(response) -> None:
    secure = cookies_secure()
    response.delete_cookie(session_cookie_name(), path="/", httponly=True, secure=secure, samesite="strict")
    _delete_legacy_session_cookie(response)


def oidc_transaction_cookies(request: Request) -> Dict[str, str]:
    """Transaction cookies under Access's names; cookies of the other mode are ignored."""
    prefix = _HOST_PREFIX if cookies_secure() else ""
    return {
        name[len(prefix) :]: value
        for name, value in request.cookies.items()
        if name.startswith(prefix + _OIDC_TX_PREFIX)
    }


def apply_oidc_cookie_operations(response, operations) -> None:
    secure = cookies_secure()
    prefix, path = (_HOST_PREFIX, "/") if secure else ("", _OIDC_TX_LEGACY_PATH)
    for operation in operations:
        if operation.max_age:
            response.set_cookie(
                prefix + operation.name,
                operation.value,
                max_age=operation.max_age,
                httponly=True,
                secure=secure,
                samesite="lax",
                path=path,
            )
        else:
            response.delete_cookie(prefix + operation.name, path=path, httponly=True, secure=secure, samesite="lax")


def log_cookie_mode() -> None:
    if not cookies_secure():
        _logger.warning(
            "COOKIE_SECURE=false: cookies lack the Secure flag and the __Host- prefix. "
            "Plain HTTP is for local or trusted networks only."
        )


def _decode_session_payload(request: Request):
    return access.decode_session_payload(session_cookie(request) or "")


def has_valid_session(request: Request) -> bool:
    return access.session_token_is_wellformed(session_cookie(request) or "")


def get_current_user(request: Request) -> Dict[str, Any]:
    token = session_cookie(request)
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
