"""
Another S3 Manager - Lightweight S3 file management interface
Provides file browsing, upload, and deletion capabilities for S3 buckets
"""

from another_s3_manager.logging_setup import configure_logging

configure_logging()

import base64
import json
import logging
import os
import secrets as _secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from alembic import command
from alembic.config import Config

# Load environment variables from .env file (if it exists)
# This must be done before importing modules that use environment variables
try:
    from dotenv import load_dotenv

    # Load .env file from the same directory as this file
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Also try to load from current working directory
        load_dotenv()
except ImportError:
    # python-dotenv is optional, continue without it
    pass

from io import BytesIO

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

import another_s3_manager.config as config_module
from another_s3_manager.api_tokens import count_active_tokens
from another_s3_manager.auth import (
    check_ban,
    create_access_token,
    generate_csrf_token,
    get_current_admin_user,
    get_current_user,
    get_jwt_secret_key,
    hash_password,
    record_login_attempt,
    verify_csrf_token,
    verify_password,
)
from another_s3_manager.config import load_config, resolve_presigned_ttls, save_config
from another_s3_manager.constants import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    COOKIE_SECURE,
    PRESIGNED_STS_WARNING_THRESHOLD,
    PRESIGNED_URL_HARD_CEILING,
    PRESIGNED_URL_MIN_TTL,
    STATIC_DIR,
)
from another_s3_manager.errors import S3OperationError
from another_s3_manager.metrics import (
    REGISTRY,
    auth_bans_active,
    auth_logins_total,
    http_request_duration_seconds,
    http_requests_in_flight,
    http_requests_total,
    mcp_active_tokens,
    upload_rejected_total,
)
from another_s3_manager.s3_client import (
    clear_s3_clients_cache,
    delete_object_for_role,
    iter_object_for_role,
    list_buckets_for_role,
    list_objects_client_load_for_role,
    list_objects_for_role,
    list_objects_paginated_for_role,
    put_object_for_role,
    role_uses_temporary_credentials,
)
from another_s3_manager.s3_client import (
    generate_presigned_url_for_role as s3_generate_presigned_url_for_role,
)
from another_s3_manager.users import (
    get_users_for_admin,
    load_bans,
    load_users,
    save_bans,
    save_users,
)
from another_s3_manager.utils import (
    format_boto_error,
    format_content_disposition,
    sanitize_bucket_name,
    sanitize_path,
    sanitize_search_prefix,
    validate_password,
)

# Validate required environment variables at startup
try:
    get_jwt_secret_key()
except ValueError as e:
    print(f"ERROR: {e}")
    print("Please set the JWT_SECRET_KEY environment variable.")
    print("Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    sys.exit(1)

# Set up logging
logger = logging.getLogger(__name__)


def _run_alembic_upgrade() -> None:
    """Run `alembic upgrade head` programmatically.

    Looks for alembic.ini and migrations/ in the current working directory.
    Local dev: run from repo root, both are present.
    Docker: WORKDIR /app, Dockerfile copies migrations/ + alembic.ini to /app.
    """
    cwd = Path.cwd()
    alembic_cfg_path = cwd / "alembic.ini"
    if not alembic_cfg_path.exists():
        # Fallback for environments where cwd isn't repo root: try resolving from __file__
        repo_root = Path(__file__).resolve().parent.parent.parent
        alembic_cfg_path = repo_root / "alembic.ini"
        cwd = repo_root
    cfg = Config(str(alembic_cfg_path))
    cfg.set_main_option("script_location", str(cwd / "migrations"))
    command.upgrade(cfg, "head")


from contextlib import asynccontextmanager

from another_s3_manager.mcp_server import mcp as _mcp_instance


@asynccontextmanager
async def lifespan(app_: FastAPI):
    """App startup + MCP session manager lifecycle.

    Phase 5 added MCP via FastMCP (SDK 1.12.x). FastMCP's session_manager
    needs an async task group that's only created inside its run() context
    manager — without entering it during startup, every request to /mcp/*
    fails with 'Task group is not initialized.' (We learned the hard way.)

    Migration from on_event('startup') to lifespan also resolves the
    deprecation warning that's been firing since the FastAPI 0.136 bump.
    """
    # 1. DB migrations — must complete before any request hits a model
    try:
        _run_alembic_upgrade()
    except Exception:
        logger.critical("alembic upgrade failed", exc_info=True)
        raise

    # 2. Legacy JSON → SQLite migration (idempotent)
    try:
        from another_s3_manager.migration import migrate_json_if_needed

        migrate_json_if_needed()
    except json.JSONDecodeError:
        logger.critical(
            "Legacy users.json or bans.json is corrupt. Fix or delete the file manually, then restart.",
            exc_info=True,
        )
        sys.exit(1)
    except Exception:
        logger.warning("JSON migration failed; DB is still usable", exc_info=True)

    # 3. One-time migration: legacy global config.default_role → per-user records
    try:
        _migrate_legacy_default_role()
    except Exception:
        logger.warning("Legacy default_role migration failed; continuing startup", exc_info=True)

    # 4. Default-password security warning
    if os.getenv("ADMIN_PASSWORD", "change_me_pls") == "change_me_pls":
        logger.warning(
            "ADMIN_PASSWORD is the default 'change_me_pls'. CHANGE IT before exposing this app — "
            "admin is exempt from auto-ban and there is no application-level rate limit on /api/login."
        )

    # 5. Enter FastMCP session manager — REQUIRED for /mcp/* to work.
    async with _mcp_instance.session_manager.run():
        yield


app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, lifespan=lifespan)

# No application-level rate limiting. Brute-force defense lives in the
# username-based ban (auth.record_login_attempt: 3 fails → 1h ban, admins exempt).
# For production deployments expecting public exposure, put the app behind
# Cloudflare Access / WAF (or any reverse proxy with auth) — that is the right
# layer for IP-level rate limiting and DoS protection.


# Exception handler to ensure all errors return JSON
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# HTTP metrics middleware — registered late so it sees the final response status
# (after exception handlers have run and converted exceptions to proper HTTP responses).
@app.middleware("http")
async def _http_metrics(request: Request, call_next):
    start = time.perf_counter()
    http_requests_in_flight.inc()
    try:
        response = await call_next(request)
    finally:
        # Decrement even if call_next raised, so an unhandled exception
        # never leaks the gauge upward.
        http_requests_in_flight.dec()
    duration = time.perf_counter() - start
    # path_template — bounded cardinality. Falls back to actual path on no-route 404.
    route = request.scope.get("route")
    path_template = route.path if route is not None else request.url.path
    method = request.method
    status_code = str(response.status_code)
    http_requests_total.labels(method=method, path_template=path_template, status_code=status_code).inc()
    http_request_duration_seconds.labels(method=method, path_template=path_template).observe(duration)
    return response


# MCP kill-switch middleware — must be registered BEFORE the MCP sub-app is
# mounted so Starlette evaluates it on every /mcp/* request.
@app.middleware("http")
async def _mcp_kill_switch(request: Request, call_next):
    """Return 503 for all /mcp paths when mcp_enabled=False in config.

    Match both /mcp (without trailing slash — Starlette would 307-redirect
    this to /mcp/ unless we intercept first) and /mcp/* so the kill-switch
    can't be bypassed via the no-slash form.
    """
    path = request.url.path
    if path == "/mcp" or path.startswith("/mcp/"):
        cfg = config_module.load_config(force_reload=False)
        if not cfg.get("mcp_enabled", True):
            return JSONResponse(
                {"error": "MCP_DISABLED", "message": "MCP API is disabled"},
                status_code=503,
            )
    return await call_next(request)


def _check_metrics_auth(request: Request) -> None:
    """Enforce optional basic auth on /metrics. Open when METRICS_PASSWORD is unset."""
    expected = os.getenv("METRICS_PASSWORD")
    if not expected:
        return  # endpoint is open
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        raise HTTPException(
            status_code=401,
            detail="Basic auth required",
            headers={"WWW-Authenticate": 'Basic realm="metrics"'},
        )
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed basic auth")
    if username != "metrics" or not _secrets.compare_digest(password, expected):
        raise HTTPException(status_code=401, detail="Invalid credentials")


# Scrape-time callbacks. Computing at scrape time (rather than hooking every
# mutation) means the gauge can never drift out of sync with the database.
auth_bans_active.set_function(lambda: float(len(load_bans())))
mcp_active_tokens.set_function(lambda: float(count_active_tokens()))


@app.get("/metrics")
async def metrics_endpoint(request: Request):
    """Prometheus metrics exposition endpoint. Optional METRICS_PASSWORD basic auth."""
    _check_metrics_auth(request)
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# Health endpoint (no auth required)
@app.get("/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


def _migrate_legacy_default_role() -> None:
    """Copy the legacy global `config.default_role` into compatible user records.

    Runs at startup. Idempotent. Only updates users whose `default_role IS NULL`
    AND who have the legacy role in their `allowed_roles`. Skips silently if
    config has no legacy default. After this migration, `config.default_role`
    is silently ignored on read (the field may still appear in config.json on
    disk — that's fine, harmless legacy data).
    """
    config = load_config()
    legacy_default = config.get("default_role")
    if not legacy_default:
        return

    from another_s3_manager import users  # avoid circular imports

    updated_count = 0
    all_users = users.load_users().get("users", [])
    for user in all_users:
        if user.get("default_role") is None and legacy_default in user.get("allowed_roles", []):
            users.update_user(user["username"], default_role=legacy_default)
            updated_count += 1

    if updated_count > 0:
        logger.info(
            "Migrated legacy config.default_role='%s' to %d user records",
            legacy_default,
            updated_count,
        )


def _enforce_password_policy(password: str) -> None:
    """Reject the request if the password fails the configured policy.

    Raises HTTPException(422) with a structured detail so the frontend can
    render per-requirement checkmarks. Loads the policy from the cached
    config (no file IO unless the cache is cold).
    """
    config = config_module.load_config(force_reload=False)
    failures = validate_password(password, config)
    if failures:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Password does not meet policy", "failed_requirements": failures},
        )


# ============================================================================
# Routes
# ============================================================================


@app.post("/api/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Login endpoint — issues an httpOnly cookie carrying the JWT."""
    try:
        # Check if user is banned
        if check_ban(username):
            bans = load_bans()
            ban_data = bans.get(username, {})
            banned_until = ban_data.get("banned_until", 0)
            import time

            remaining = int((banned_until - time.time()) / 60)
            auth_logins_total.labels(result="banned").inc()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is banned. Try again in {remaining} minutes.",
            )

        users = load_users()
        user = next((u for u in users.get("users", []) if u.get("username") == username), None)

        if user is None:
            record_login_attempt(username, False)
            # Same label as a wrong password — metrics must not enumerate usernames.
            auth_logins_total.labels(result="invalid_password").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )

        # Verify password
        if not verify_password(password, user.get("password_hash", "")):
            record_login_attempt(username, False)
            auth_logins_total.labels(result="invalid_password").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )

        # Successful login
        record_login_attempt(username, True)
        auth_logins_total.labels(result="success").inc()

        # Generate CSRF token and embed in the signed JWT (defence-in-depth).
        # The JWT itself is delivered as an httpOnly cookie so JS cannot read it;
        # the CSRF token is exposed via /api/me for the client to echo back in
        # the X-CSRF-Token header on mutating requests.
        csrf_token = generate_csrf_token()
        access_token = create_access_token(data={"sub": username, "csrf_token": csrf_token})

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="strict",
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            path="/",
        )

        return {"user": {"username": username, "is_admin": user.get("is_admin", False)}}
    except HTTPException:
        raise
    except Exception:
        # Log the full exception server-side; never echo str(e) back to the client
        # (SQLAlchemy errors include SQL text + table names, requests / boto / etc
        # may include URLs, credentials, or internal paths).
        logger.exception("Login failed unexpectedly for username=%s", username)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed",
        )


@app.post("/api/logout")
async def logout(response: Response):
    """Clear the auth cookie. No auth required — clearing an already-invalid cookie is harmless."""
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@app.get("/api/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    is_admin = current_user.get("is_admin", False)
    config = load_config()
    # Admins can access every role in the config — surface the full list so the
    # React sidebar matches admin permissions without an extra /api/config call.
    if is_admin:
        allowed_roles = [r["name"] for r in config.get("roles", []) if r.get("name")]
    else:
        allowed_roles = current_user.get("allowed_roles", [])
    # disable_deletion: env var OR config (env wins). Mirrors the same combined
    # check used in /api/config so the two endpoints don't disagree.
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)
    disable_deletion = disable_deletion_env or disable_deletion_config
    # Computed default_role: explicit choice if still valid, else first of
    # allowed_roles, else null. Helper lives in users.py so the rule lives
    # next to the data layer that stores explicit_default.
    from another_s3_manager.users import compute_default_role

    default_role = compute_default_role(current_user.get("default_role"), allowed_roles)
    # max_file_size: surface to client so it can validate sizes BEFORE the
    # multipart POST and show a useful error per file. Without this, the
    # browser uploads up to the limit, the backend rejects with 400, and the
    # user sees a generic toast that doesn't say "this file is N MB, limit is M".
    max_file_size_from_config = config.get("max_file_size")
    if max_file_size_from_config is None:
        max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    else:
        max_file_size = int(max_file_size_from_config)
    return {
        "username": current_user.get("username"),
        "is_admin": is_admin,
        "csrf_token": current_user.get("csrf_token"),  # Return CSRF token for client
        "theme": current_user.get("theme", "auto"),  # Return user's theme preference
        "allowed_roles": allowed_roles,
        "default_role": default_role,
        "must_change_password": bool(current_user.get("must_change_password", False)),
        "disable_deletion": disable_deletion,
        "max_file_size": max_file_size,
        "app_name": APP_NAME,  # Return app name for client
        "app_version": APP_VERSION,
    }


@app.get("/api/app-info")
async def get_app_info():
    """Get application information (public endpoint)"""
    return {
        "app_name": APP_NAME,
        "app_description": APP_DESCRIPTION,
        "app_version": APP_VERSION,
    }


@app.get("/api/admin/users")
async def list_users(current_user: Dict[str, Any] = Depends(get_current_admin_user)):
    """List all users (admin only)"""
    # Always reload config to get latest roles
    config = load_config(force_reload=True)
    available_roles = [role.get("name") for role in config.get("roles", [])]
    # Returns user list including id field (used by admin token creation)
    user_list = get_users_for_admin()
    return {"users": user_list, "available_roles": available_roles}


@app.post("/api/admin/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    allowed_roles: str = Form("", description="Comma-separated list of allowed role names"),
    must_change_password: bool = Form(True, description="Force user to change password on next login"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Create a new user (admin only)"""
    users = load_users()

    # Check if user already exists
    if any(u.get("username") == username for u in users.get("users", [])):
        raise HTTPException(status_code=400, detail="User already exists")

    _enforce_password_policy(password)

    # Hash password
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode("utf-8", errors="ignore")

    # Hash password using auth module
    hashed_password = hash_password(password)

    # Parse allowed roles
    roles_list = [r.strip() for r in allowed_roles.split(",") if r.strip()] if allowed_roles else []

    # Import datetime for timestamp
    from datetime import datetime

    new_user = {
        "username": username,
        "password_hash": hashed_password,
        "is_admin": is_admin,
        "allowed_roles": roles_list,
        "theme": "auto",  # Default to auto (system preference)
        "must_change_password": must_change_password,
        "created_at": datetime.now().isoformat(),
    }

    users.setdefault("users", []).append(new_user)
    save_users(users)

    return {"message": "User created successfully", "username": username}


class AdminResetPasswordRequest(BaseModel):
    """Body for PUT /api/admin/users/{username}/password."""

    password: str = Field(..., min_length=1, description="New password")
    must_change_password: bool = Field(
        default=True,
        description=(
            "Force the user to change this password on next login. "
            "Default True (paranoid). Set False for service accounts."
        ),
    )


class AdminResetPasswordResponse(BaseModel):
    """Response for PUT /api/admin/users/{username}/password."""

    message: str


@app.put("/api/admin/users/{username}/password", response_model=AdminResetPasswordResponse)
async def update_user_password(
    request: Request,
    username: str,
    payload: AdminResetPasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
) -> AdminResetPasswordResponse:
    """Update user password (admin only)"""
    # Pydantic's min_length=1 catches empty strings (returns 422). This catches
    # whitespace-only passwords like "   " which pass min_length but are invalid.
    if len(payload.password.strip()) == 0:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    _enforce_password_policy(payload.password)

    # Hash password using auth module
    hashed_password = hash_password(payload.password)

    user["password_hash"] = hashed_password
    user["must_change_password"] = payload.must_change_password
    save_users(users)

    return AdminResetPasswordResponse(message=f"Password updated successfully for user {username}")


class ChangePasswordRequest(BaseModel):
    """Body for self-service password change at PUT /api/me/password."""

    current_password: str = Field(..., min_length=1, description="The user's current password")
    new_password: str = Field(..., min_length=1, description="The new password to set")


class CreateTokenRequest(BaseModel):
    """Body for POST /api/me/tokens — create an API token for the current user."""

    name: str = Field(..., min_length=1, max_length=100)
    is_read_only: bool = True
    max_read_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)


class AdminCreateTokenRequest(CreateTokenRequest):
    """Body for POST /api/admin/tokens — admin creates a token on behalf of a user."""

    user_id: int = Field(..., gt=0)


class UpdateTokenRequest(BaseModel):
    """Body for PUT /api/me/tokens/{id} and PUT /api/admin/tokens/{id}.

    All fields optional — the service rejects empty bodies with 400
    'no fields to update' and out-of-range max_read_bytes with 400
    'max_read_bytes out of range'. Range bounds intentionally NOT enforced at
    the Pydantic layer so the contract is a single 400 error from the service,
    not a 422 from validation.
    """

    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_read_only: Optional[bool] = None
    max_read_bytes: Optional[int] = None


@app.put("/api/me/password")
async def change_my_password(
    payload: ChangePasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Self-service password change.

    Requires the user's current password in addition to a valid auth cookie + CSRF
    token, so an attacker who steals the cookie still cannot lock the user out
    without also knowing the current password.
    """
    # Re-fetch the password hash from storage — current_user dict from the JWT
    # path doesn't carry it (and shouldn't).
    username = current_user.get("username")
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)
    if not user:
        # Defensive: should be unreachable since get_current_user already resolved the user.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not verify_password(payload.current_password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current one",
        )

    _enforce_password_policy(payload.new_password)

    # Local import to avoid the top-level name collision with the admin
    # update_user endpoint defined below.
    from another_s3_manager.users import update_user as users_update_user

    users_update_user(
        username,
        password_hash=hash_password(payload.new_password),
        must_change_password=False,
    )
    return {"ok": True}


class UpdateDefaultRolePayload(BaseModel):
    role: Optional[str] = None


class UpdateDefaultRoleResponse(BaseModel):
    default_role: Optional[str]


def _effective_allowed_roles(current_user: Dict[str, Any]) -> list[str]:
    """Same admin-vs-user role resolution used by GET /api/me.

    Admins see every configured role; regular users see only their assigned
    `allowed_roles`. Extracted so the PUT endpoint validates against the same
    set the GET endpoint reports.
    """
    if current_user.get("is_admin", False):
        config = load_config()
        return [r["name"] for r in config.get("roles", []) if r.get("name")]
    return current_user.get("allowed_roles", [])


@app.put("/api/me/default-role", response_model=UpdateDefaultRoleResponse)
async def update_my_default_role(
    payload: UpdateDefaultRolePayload,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
) -> UpdateDefaultRoleResponse:
    """Set the authenticated user's default role.

    Payload: {"role": "<role-name>" | null}. `null` clears the explicit choice
    so the computed fallback applies (first of allowed_roles, or null).
    Returns 400 if the role is not in the user's allowed set.
    """
    from another_s3_manager.users import (
        update_user as users_update_user_role,
    )
    from another_s3_manager.users import (
        validate_default_role_choice,
    )

    try:
        validate_default_role_choice(payload.role, _effective_allowed_roles(current_user))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        users_update_user_role(current_user["username"], default_role=payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return UpdateDefaultRoleResponse(default_role=payload.role)


# ---------------------------------------------------------------------------
# Token CRUD helpers
# ---------------------------------------------------------------------------

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from another_s3_manager import api_tokens as token_svc
from another_s3_manager.models import User as UserModel


def _get_user_id_by_username(username: str) -> int:
    """Return the DB primary-key id for the given username.

    Raises HTTPException 404 if the user is not found.
    """
    from another_s3_manager.database import session_scope

    with session_scope() as session:
        row = session.execute(select(UserModel).where(UserModel.username == username)).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        return row.id


def _serialize_token(t, owner_username: Optional[str] = None) -> dict:
    """Serialize an ApiToken ORM row to a plain dict (no token_hash, no plaintext)."""

    # SQLite drops tzinfo on storage even though our DateTime columns declare
    # timezone=True; values come back naive. Since we always *write* UTC
    # (api_tokens._utcnow → datetime.now(UTC)), force a 'Z' suffix on the
    # serialized ISO so the browser parses it as UTC instead of local time.
    # Without this, the React UI showed "Last used 2 hours ago" right after
    # using a token from a UTC+2 browser.
    def _iso_utc(d):
        if d is None:
            return None
        if d.tzinfo is not None:
            return d.isoformat()
        return d.isoformat() + "Z"

    out = {
        "id": t.id,
        "name": t.name,
        "is_read_only": t.is_read_only,
        "max_read_bytes": t.max_read_bytes,
        "created_at": _iso_utc(t.created_at),
        "last_used_at": _iso_utc(t.last_used_at),
        "revoked_at": _iso_utc(t.revoked_at),
    }
    if owner_username is not None:
        out["owner_username"] = owner_username
    return out


# ---------------------------------------------------------------------------
# /api/me/tokens  (self-service)
# ---------------------------------------------------------------------------


@app.get("/api/me/tokens")
async def get_my_tokens(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List active API tokens for the authenticated user.

    Returns tokens, used count, and per-user limit. Never returns token_plaintext.
    """
    user_id = _get_user_id_by_username(current_user["username"])
    tokens = token_svc.list_tokens_for_user(user_id, include_revoked=False)
    used = token_svc.count_active_tokens_for_user(user_id)
    return {
        "tokens": [_serialize_token(t) for t in tokens],
        "used": used,
        "limit": token_svc.PER_USER_TOKEN_LIMIT,
    }


@app.post("/api/me/tokens")
async def create_my_token(
    payload: CreateTokenRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Create a new API token for the authenticated user.

    Returns token metadata + token_plaintext exactly once. Store it immediately —
    it cannot be retrieved again.
    """
    user_id = _get_user_id_by_username(current_user["username"])
    try:
        token, plaintext = token_svc.create_token(user_id, payload.name, payload.is_read_only, payload.max_read_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"Token name '{payload.name}' already exists")
    return {**_serialize_token(token), "token_plaintext": plaintext}


@app.delete("/api/me/tokens/{token_id}")
async def delete_my_token(
    token_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Revoke one of the authenticated user's own tokens.

    Returns 403 if the token belongs to another user, 404 if not found.
    """
    user_id = _get_user_id_by_username(current_user["username"])
    try:
        token_svc.revoke_token(token_id, by_user_id=user_id, by_is_admin=False)
    except PermissionError:
        raise HTTPException(status_code=403, detail="You can only revoke your own tokens")
    except ValueError:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"ok": True}


@app.put("/api/me/tokens/{token_id}")
async def update_my_token(
    token_id: int,
    payload: UpdateTokenRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update editable metadata (name, is_read_only, max_read_bytes) on the user's own token.

    Returns 400 on empty body or out-of-range max_read_bytes, 403 for non-owner,
    404 for missing or revoked tokens, 409 on name collision.
    """
    user_id = _get_user_id_by_username(current_user["username"])
    try:
        updated = token_svc.update_token(
            token_id=token_id,
            by_user_id=user_id,
            by_is_admin=False,
            name=payload.name,
            is_read_only=payload.is_read_only,
            max_read_bytes=payload.max_read_bytes,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="You can only update your own tokens")
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"Token name '{payload.name}' already exists")
    except ValueError as exc:
        msg = str(exc)
        if "no fields to update" in msg or "out of range" in msg:
            raise HTTPException(status_code=400, detail=msg)
        # "not found" or "is revoked" -> 404 (revoked tokens are treated as gone)
        raise HTTPException(status_code=404, detail=msg)
    return _serialize_token(updated)


# ---------------------------------------------------------------------------
# /api/admin/tokens  (admin-only)
# ---------------------------------------------------------------------------


@app.get("/api/admin/tokens")
async def admin_list_tokens(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List all active API tokens across all users (admin only).

    Each entry includes owner_username for display in the admin panel.
    """
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    rows = token_svc.list_all_tokens(include_revoked=False)
    return {"tokens": [_serialize_token(t, owner_username=u.username) for t, u in rows]}


@app.post("/api/admin/tokens")
async def admin_create_token(
    payload: AdminCreateTokenRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Create an API token on behalf of any user (admin only).

    Requires user_id (not username) in the request body; the caller (SPA)
    must resolve username→id from the users list before calling this endpoint.
    """
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    # Validate that the target user exists before attempting to create the token.
    # Without this check, a bogus user_id triggers an FK IntegrityError which
    # the except-block below would incorrectly map to 409 "Token name already exists".
    from another_s3_manager.database import session_scope

    with session_scope() as _session:
        user_exists = _session.execute(select(UserModel.id).where(UserModel.id == payload.user_id)).scalar_one_or_none()
    if user_exists is None:
        raise HTTPException(status_code=404, detail=f"User with id {payload.user_id} not found")
    try:
        token, plaintext = token_svc.create_token(
            payload.user_id, payload.name, payload.is_read_only, payload.max_read_bytes
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"Token name '{payload.name}' already exists for this user")
    return {**_serialize_token(token), "token_plaintext": plaintext}


@app.delete("/api/admin/tokens/{token_id}")
async def admin_delete_token(
    token_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Revoke any token regardless of owner (admin only)."""
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        # by_is_admin=True bypasses owner check; by_user_id is irrelevant when admin.
        token_svc.revoke_token(token_id, by_user_id=0, by_is_admin=True)
    except ValueError:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"ok": True}


@app.put("/api/admin/tokens/{token_id}")
async def admin_update_token(
    token_id: int,
    payload: UpdateTokenRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Admin endpoint: update any token's editable metadata regardless of owner.

    Returns the same shape as the admin list (`owner_username` included) so the
    SPA can patch its cache in place. 400 on bad input, 404 on missing/revoked,
    409 on name collision.
    """
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    actor_user_id = _get_user_id_by_username(current_user["username"])
    try:
        updated = token_svc.update_token(
            token_id=token_id,
            by_user_id=actor_user_id,
            by_is_admin=True,
            name=payload.name,
            is_read_only=payload.is_read_only,
            max_read_bytes=payload.max_read_bytes,
        )
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"Token name '{payload.name}' already exists for this user")
    except ValueError as exc:
        msg = str(exc)
        if "no fields to update" in msg or "out of range" in msg:
            raise HTTPException(status_code=400, detail=msg)
        # "not found" or "is revoked" -> 404 (revoked tokens are treated as gone)
        raise HTTPException(status_code=404, detail=msg)

    # Mirror admin_list_tokens shape: include owner_username for the admin SPA.
    # owner_username is part of the admin response contract — we 404 explicitly
    # if the user vanished between update and lookup (extremely rare given FK
    # CASCADE + single-worker SQLite, but the alternative — silently omitting
    # the key from the JSON — would mislead the SPA cache patch logic).
    from another_s3_manager.database import session_scope

    with session_scope() as session:
        owner_username = session.execute(
            select(UserModel.username).where(UserModel.id == updated.user_id)
        ).scalar_one_or_none()
    if owner_username is None:
        raise HTTPException(
            status_code=404,
            detail=f"Owner of token {token_id} no longer exists",
        )
    return _serialize_token(updated, owner_username=owner_username)


@app.put("/api/admin/users/{username}")
async def update_user(
    request: Request,
    username: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update user permissions (admin only).

    Reads multipart form fields manually via request.form() instead of
    `is_admin: Optional[str] = Form(None)` because FastAPI coerces an
    EMPTY field value to None, making it impossible to distinguish
    "field omitted" from "field present but empty" — which broke
    "clear all roles for a user" (the empty string fell through the
    `if allowed_roles is not None` guard and the row never updated).
    """
    form = await request.form()

    is_admin_raw = form.get("is_admin")
    allowed_roles_raw = form.get("allowed_roles")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Coerce only when the form value is a non-empty string. An empty value
    # ("is_admin=") would otherwise fall through `is not None` and silently
    # demote the target user, since str("").lower() != "true" → False.
    is_admin: Optional[bool] = None
    if is_admin_raw is not None and str(is_admin_raw) != "":
        is_admin = str(is_admin_raw).lower() == "true"

    # Self-demote guard: an admin cannot remove their own admin rights through this
    # endpoint. Frontend disables the toggle on the current-user row, but enforce
    # server-side too (defence in depth, e.g. against a hand-crafted curl request).
    if username == current_user.get("username") and is_admin is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You can't remove your own admin rights.",
        )

    if is_admin is not None:
        user["is_admin"] = is_admin

    # Presence of the form key means the client wants to set roles — possibly
    # to an empty list. Absence means leave the field alone.
    if "allowed_roles" in form:
        raw = str(allowed_roles_raw or "")
        roles_list = [r.strip() for r in raw.split(",") if r.strip()]
        user["allowed_roles"] = roles_list

    save_users(users)
    return {"message": f"User {username} updated successfully"}


@app.put("/api/user/theme")
async def update_user_theme(
    request: Request,
    theme: str = Body(..., embed=True, description="Theme preference: 'light' or 'dark' (auto only for initial state)"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update user's theme preference"""
    # Allow only 'light' or 'dark' for manual changes (auto is only for initial state)
    if theme not in ["light", "dark"]:
        raise HTTPException(status_code=400, detail="Theme must be 'light' or 'dark'")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user["theme"] = theme
    save_users(users)

    return {"message": f"Theme updated to {theme}", "theme": theme}


@app.delete("/api/admin/users/{username}")
async def delete_user(
    request: Request,
    username: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Delete a user (admin only)"""
    if username == current_user.get("username"):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    users = load_users()
    users["users"] = [u for u in users.get("users", []) if u.get("username") != username]
    save_users(users)

    return {"message": f"User {username} deleted successfully"}


@app.get("/api/admin/bans")
async def list_bans(current_user: Dict[str, Any] = Depends(get_current_admin_user)):
    """List all banned users (admin only)"""
    bans = load_bans()
    ban_list = []
    import time

    current_time = time.time()
    for username, ban_data in bans.items():
        banned_until = ban_data.get("banned_until", 0)
        remaining = int((banned_until - current_time) / 60)
        ban_list.append(
            {
                "username": username,
                "banned_until": banned_until,
                "banned_at": ban_data.get("banned_at"),
                "reason": ban_data.get("reason"),
                "remaining_minutes": remaining if remaining > 0 else 0,
            }
        )
    return {"bans": ban_list}


@app.delete("/api/admin/bans/{username}")
async def unban_user(
    request: Request,
    username: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Unban a user (admin only)"""
    bans = load_bans()
    if username in bans:
        del bans[username]
        save_bans(bans)
        # Login attempts are managed in auth module, no need to reset here
        return {"message": f"User {username} unbanned successfully"}
    else:
        raise HTTPException(status_code=404, detail="User is not banned")


@app.get("/api/config")
async def get_config(
    force_reload: bool = Query(False, description="Force reload from file"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Get current configuration (filtered by user permissions)."""
    config = load_config(force_reload=force_reload)

    # Check if deletion is disabled (from environment variable or config)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)
    disable_deletion = disable_deletion_env or disable_deletion_config

    # Get enable_lazy_loading from config file, fallback to environment variable, then default
    enable_lazy_loading = config.get("enable_lazy_loading")
    if enable_lazy_loading is None:
        enable_lazy_loading = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"
    else:
        enable_lazy_loading = bool(enable_lazy_loading)

    # Get max_file_size from config file, fallback to environment variable, then default
    max_file_size = config.get("max_file_size")
    if max_file_size is None:
        max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    else:
        max_file_size = int(max_file_size)

    # Get max_client_load from config file, fallback to environment variable, then default
    max_client_load = config.get("max_client_load")
    if max_client_load is None:
        max_client_load = int(os.getenv("MAX_CLIENT_LOAD", "10000"))
    else:
        max_client_load = int(max_client_load)

    # Resolve presigned URL TTL bounds (config → env → hardcoded defaults).
    presigned_url_default_ttl, presigned_url_max_ttl = resolve_presigned_ttls(config)

    # Create a safe copy without secret credentials
    def sanitize_role(role: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive secret credentials from role (keep access_key_id as it's not secret)"""
        sanitized = role.copy()
        # Remove secret_access_key completely from API response (don't show it at all)
        if "secret_access_key" in sanitized:
            del sanitized["secret_access_key"]
        # Keep access_key_id, role_arn and profile_name as they're not sensitive
        return sanitized

    # If user is admin, return config but without credentials
    if current_user.get("is_admin", False):
        from another_s3_manager.config import is_config_writable
        from another_s3_manager.constants import get_data_dir

        # default_role removed from config in Phase 6a-4 (now per-user via /api/me).
        # effective_role falls back to the first configured role for the vanilla UI;
        # React UI reads per-user default_role from /api/me instead.
        roles_list = config.get("roles", [])
        effective_role = roles_list[0].get("name", "") if roles_list else ""

        safe_config = {
            "roles": [sanitize_role(role) for role in config.get("roles", [])],
            "current_role": effective_role,  # Computed value for frontend (not stored in config)
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "max_client_load": max_client_load,
            "presigned_url_default_ttl": presigned_url_default_ttl,
            "presigned_url_max_ttl": presigned_url_max_ttl,
            "preview_text_extensions": config.get("preview_text_extensions", []),
            "upload_inline_extensions": config.get("upload_inline_extensions", []),
            "data_dir": str(get_data_dir()),  # Return current DATA_DIR value (read-only)
            "is_read_only": not is_config_writable(),
            "password_min_length": config.get("password_min_length", 0),
            "password_min_uppercase": config.get("password_min_uppercase", 0),
            "password_min_lowercase": config.get("password_min_lowercase", 0),
            "password_min_digits": config.get("password_min_digits", 0),
            "password_min_special": config.get("password_min_special", 0),
            # MCP server fields (Phase 5)
            "mcp_enabled": config.get("mcp_enabled", True),
            "mcp_disable_writes": config.get("mcp_disable_writes", False),
            "mcp_text_extensions": config.get("mcp_text_extensions", []),
            "mcp_global_max_read_bytes": config.get("mcp_global_max_read_bytes", 10_485_760),
        }
        return safe_config

    # For regular users, filter roles by permissions
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get allowed roles for this user
    allowed_roles = user.get("allowed_roles", [])
    if not allowed_roles:
        # No roles allowed, return empty config with all required fields
        return {
            "roles": [],
            "current_role": "",
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "max_client_load": max_client_load,
            "presigned_url_default_ttl": presigned_url_default_ttl,
            "presigned_url_max_ttl": presigned_url_max_ttl,
            "preview_text_extensions": config.get("preview_text_extensions", []),
            "upload_inline_extensions": config.get("upload_inline_extensions", []),
        }

    # Filter roles and sanitize
    filtered_roles = [sanitize_role(role) for role in config.get("roles", []) if role.get("name") in allowed_roles]

    # default_role removed from config in Phase 6a-4 (now per-user via /api/me).
    # React UI reads per-user default_role from /api/me; vanilla UI falls back to first allowed role.
    effective_role = allowed_roles[0] if allowed_roles else ""

    return {
        "roles": filtered_roles,
        "current_role": effective_role,
        "disable_deletion": disable_deletion,
        "enable_lazy_loading": enable_lazy_loading,
        "max_file_size": max_file_size,
        "max_client_load": max_client_load,
        "presigned_url_default_ttl": presigned_url_default_ttl,
        "presigned_url_max_ttl": presigned_url_max_ttl,
        "preview_text_extensions": config.get("preview_text_extensions", []),
        "upload_inline_extensions": config.get("upload_inline_extensions", []),
    }


@app.get("/api/config/export")
async def export_config(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Export full configuration as JSON (admin only)"""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required to export configuration"
        )

    config = load_config(force_reload=True)

    # Return as JSON response with download headers
    from fastapi.responses import Response

    json_str = json.dumps(config, indent=2, ensure_ascii=False)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=config.json"},
    )


@app.post("/api/config")
async def update_config(
    request: Request,
    config: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update configuration (admin only)"""
    # Only admins can update config
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required to update configuration"
        )

    # Check if config is read-only
    from another_s3_manager.config import is_config_writable

    if not is_config_writable():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The application does not have write access to the configuration file (e.g., mounted as read-only from Kubernetes ConfigMap). Configuration management must be handled externally.",
        )

    try:
        # Validate config structure
        if "roles" not in config:
            raise HTTPException(status_code=400, detail="Invalid config structure: 'roles' is required")

        # Handle enable_lazy_loading - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "enable_lazy_loading" in config:
            # Validate enable_lazy_loading (must be boolean)
            if not isinstance(config["enable_lazy_loading"], bool):
                raise HTTPException(status_code=400, detail="enable_lazy_loading must be a boolean")
        else:
            # Preserve enable_lazy_loading from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "enable_lazy_loading" in current_config:
                config["enable_lazy_loading"] = current_config["enable_lazy_loading"]
            else:
                # Use env var or default if not in config
                config["enable_lazy_loading"] = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"

        # Handle max_file_size - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "max_file_size" in config:
            # Validate max_file_size
            try:
                max_file_size_val = int(config["max_file_size"])
                if max_file_size_val < 1024:  # At least 1KB
                    raise HTTPException(status_code=400, detail="max_file_size must be at least 1024 bytes (1KB)")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="max_file_size must be a valid integer")
        else:
            # Preserve max_file_size from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "max_file_size" in current_config:
                config["max_file_size"] = current_config["max_file_size"]
            else:
                # Use env var or default if not in config
                config["max_file_size"] = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))

        # Handle max_client_load - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "max_client_load" in config:
            # Validate max_client_load (1..200000, matching the s3_client clamp)
            try:
                max_client_load_val = int(config["max_client_load"])
                if max_client_load_val < 1 or max_client_load_val > 200000:
                    raise HTTPException(
                        status_code=400,
                        detail="max_client_load must be between 1 and 200000",
                    )
                config["max_client_load"] = max_client_load_val
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="max_client_load must be a valid integer")
        else:
            # Preserve max_client_load from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "max_client_load" in current_config:
                config["max_client_load"] = current_config["max_client_load"]
            else:
                # Use env var or default if not in config
                config["max_client_load"] = int(os.getenv("MAX_CLIENT_LOAD", "10000"))

        # Handle presigned URL TTLs — validate when provided, preserve when omitted.
        _current_for_ttl = load_config(force_reload=False)

        def _validate_ttl_field(field_name: str) -> None:
            if field_name in config:
                try:
                    val = int(config[field_name])
                except (ValueError, TypeError):
                    raise HTTPException(status_code=400, detail=f"{field_name} must be a valid integer")
                if val < PRESIGNED_URL_MIN_TTL or val > PRESIGNED_URL_HARD_CEILING:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"{field_name} must be between {PRESIGNED_URL_MIN_TTL} "
                            f"and {PRESIGNED_URL_HARD_CEILING} seconds"
                        ),
                    )
                config[field_name] = val
            else:
                preserved = _current_for_ttl.get(field_name)
                if preserved is not None:
                    config[field_name] = preserved

        _validate_ttl_field("presigned_url_default_ttl")
        _validate_ttl_field("presigned_url_max_ttl")

        # Cross-field invariant: default cannot exceed max (when both are known).
        _eff_default = config.get("presigned_url_default_ttl")
        _eff_max = config.get("presigned_url_max_ttl")
        if _eff_default is not None and _eff_max is not None and int(_eff_default) > int(_eff_max):
            raise HTTPException(
                status_code=400,
                detail="presigned_url_default_ttl cannot exceed presigned_url_max_ttl",
            )

        # Extension lists — validate (list of strings) when provided, preserve
        # when omitted. Two independent keys since the 1.0.3 split:
        #   preview_text_extensions → text-preview in the UI
        #   upload_inline_extensions → Content-Disposition: inline on upload
        current_config = load_config(force_reload=False)
        for ext_field in ("preview_text_extensions", "upload_inline_extensions"):
            if ext_field in config:
                if not isinstance(config[ext_field], list):
                    raise HTTPException(status_code=400, detail=f"{ext_field} must be a list")
                for ext in config[ext_field]:
                    if not isinstance(ext, str):
                        raise HTTPException(status_code=400, detail=f"{ext_field} must contain only strings")
                # Normalize: strip leading dots, lowercase, drop blanks.
                config[ext_field] = [ext.lstrip(".").lower() for ext in config[ext_field] if ext.strip()]
            elif ext_field in current_config:
                config[ext_field] = current_config[ext_field]
            else:
                config[ext_field] = []

        # Password policy fields: validate range when provided, preserve when omitted.
        for field in (
            "password_min_length",
            "password_min_uppercase",
            "password_min_lowercase",
            "password_min_digits",
            "password_min_special",
        ):
            if field in config:
                try:
                    val = int(config[field])
                except (ValueError, TypeError):
                    raise HTTPException(status_code=400, detail=f"{field} must be an integer")
                if val < 0 or val > 50:
                    raise HTTPException(status_code=400, detail=f"{field} must be between 0 and 50")
                config[field] = val
            else:
                preserved = load_config(force_reload=False).get(field)
                if preserved is not None:
                    config[field] = preserved

        # MCP server fields (Phase 5): validate types/ranges when provided, preserve when omitted.
        if "mcp_enabled" in config and not isinstance(config["mcp_enabled"], bool):
            raise HTTPException(status_code=422, detail="mcp_enabled must be boolean")
        if "mcp_disable_writes" in config and not isinstance(config["mcp_disable_writes"], bool):
            raise HTTPException(status_code=422, detail="mcp_disable_writes must be boolean")
        if "mcp_text_extensions" in config:
            ext = config["mcp_text_extensions"]
            if not isinstance(ext, list) or not all(isinstance(e, str) for e in ext):
                raise HTTPException(status_code=422, detail="mcp_text_extensions must be list of strings")
        if "mcp_global_max_read_bytes" in config:
            v = config["mcp_global_max_read_bytes"]
            # Explicitly reject booleans (bool is a subclass of int in Python)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1 or v > 10_485_760:
                raise HTTPException(status_code=422, detail="mcp_global_max_read_bytes must be 1..10485760")
        # Preserve MCP fields from current config when omitted in request
        _current_cfg = load_config(force_reload=False)
        for k in ("mcp_enabled", "mcp_disable_writes", "mcp_text_extensions", "mcp_global_max_read_bytes"):
            if k not in config:
                config[k] = _current_cfg.get(k)

        # Validate roles and preserve existing secret_access_key if not provided
        current_config = load_config(force_reload=False)
        current_roles = {r.get("name"): r for r in current_config.get("roles", [])}

        for role in config.get("roles", []):
            if "name" not in role or "type" not in role:
                raise HTTPException(status_code=400, detail="Role must have 'name' and 'type'")

            role_type = role.get("type")
            if role_type == "assume_role" and "role_arn" not in role:
                raise HTTPException(status_code=400, detail="assume_role type requires 'role_arn'")
            elif role_type == "credentials":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="credentials type requires 'access_key_id'")

                # Validate and clean access_key_id
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                # Validate AWS format (should start with AKIA and be 20 characters)
                import re

                if not re.match(r"^AKIA[0-9A-Z]{16}$", access_key_id):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid access_key_id format. AWS access keys should start with AKIA and be 20 characters long",
                    )

                role["access_key_id"] = access_key_id  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(
                                status_code=400,
                                detail=f"secret_access_key is required for role '{role_name}'. Please provide it.",
                            )
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(
                            status_code=400, detail="secret_access_key is required for new credentials role"
                        )
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "s3_compatible":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'access_key_id'")
                if "endpoint_url" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'endpoint_url'")

                # Validate and clean access_key_id (no format validation for S3-compatible services)
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                endpoint_url = role.get("endpoint_url", "").strip()
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="endpoint_url cannot be empty")

                role["access_key_id"] = access_key_id  # Save trimmed value
                role["endpoint_url"] = endpoint_url  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(
                                status_code=400,
                                detail=f"secret_access_key is required for role '{role_name}'. Please provide it.",
                            )
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(
                            status_code=400, detail="secret_access_key is required for new s3_compatible role"
                        )
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "profile":
                if "profile_name" not in role:
                    raise HTTPException(status_code=400, detail="profile type requires 'profile_name'")

        save_config(config)
        clear_s3_clients_cache()
        logger.info("S3 client cache cleared after config save")
        return {"message": "Configuration updated successfully"}
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in update_config")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Failed to update config — see server logs"},
        ) from e


def _s3_error_to_http(error: S3OperationError) -> HTTPException:
    """Map a typed S3 error to an HTTPException with structured detail.

    Detail shape: ``{"code": <boto code>, "message": <human-readable>}``.
    Frontend reads ``message`` for display and ``code`` for per-code UI hints
    (e.g. "Open admin to fix" when code == "InvalidRegion").
    """
    return HTTPException(
        status_code=error.http_status,
        detail={"code": error.code, "message": str(error)},
    )


def validate_role_access(role_name: Optional[str], current_user: Dict[str, Any]) -> Optional[str]:
    """Validate that user has access to the specified role"""
    if role_name is None:
        return None

    # Admins have access to all roles
    if current_user.get("is_admin", False):
        return role_name

    # Check if user has access to this role
    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == current_user.get("username")), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    allowed_roles = user.get("allowed_roles", [])
    if role_name not in allowed_roles:
        raise HTTPException(
            status_code=403, detail=f"Access denied: You don't have permission to use role '{role_name}'"
        )

    return role_name


@app.get("/api/buckets")
async def list_buckets(
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List available S3 buckets - delegates to s3_client.list_buckets_for_role."""
    try:
        return list_buckets_for_role(role, current_user)
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # e.g. malformed allowed_buckets, missing credentials, assume_role failure
        logger.error(f"Configuration error when listing buckets: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    except (ClientError, BotoCoreError) as e:
        # Detect "credentials cannot list all buckets" — common for R2, MinIO scoped tokens,
        # AWS IAM with bucket-scoped policies. Return 403 with actionable guidance pointing
        # the user to the role's "Allowed Buckets" field instead of a raw S3 error.
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") and e.response else ""
        http_status = (
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            if hasattr(e, "response") and e.response
            else 0
        )
        if error_code in {"AccessDenied", "Forbidden"} or http_status == 403:
            # Generic message: this role's credentials cannot list all buckets.
            # Frontend layers the role-appropriate CTA on top — admins get an
            # "open admin to fix" button, non-admins get "contact administrator".
            raise HTTPException(
                status_code=403,
                detail=(
                    "Your credentials don't have permission to list all buckets. "
                    "This is normal for scoped tokens (R2, MinIO, AWS IAM with bucket-scoped policies)."
                ),
            )

        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list buckets: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in list_buckets")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Server error — see server logs"},
        ) from e


@app.get("/api/buckets/{bucket_name}/files")
async def list_files(
    bucket_name: str,
    path: str = Query("", description="Path prefix to list files from"),
    role: Optional[str] = Query(None, description="Role name to use"),
    max_keys: Optional[int] = Query(
        None,
        ge=1,
        le=1000,
        description=(
            "Page size (1..1000). When set, switches the response shape to the "
            "paginated envelope {directories, files, next_token, has_more}."
        ),
    ),
    continuation_token: Optional[str] = Query(
        None,
        max_length=1024,
        description=("Opaque S3 continuation token from a previous response's next_token. Requires max_keys."),
    ),
    client_load: bool = Query(
        False,
        description=(
            "When true, switch to client-load mode: aggregate S3 pages up to "
            "max_client_load (or max_keys if given) and return "
            "{directories, files, truncated, next_token} for the /v2 UI to "
            "paginate client-side."
        ),
    ),
    search: Optional[str] = Query(
        None,
        max_length=1024,
        description=(
            "Server-side name-prefix search (client_load mode only). Lists the "
            "current folder's immediate children whose name starts with this "
            "value. Case-sensitive. Requires client_load=1."
        ),
    ),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List files and directories.

    Three modes (response shape selected by the query params):
      * Legacy (no `max_keys`, no `client_load`): zip every S3 page into one
        flat envelope `{files, path, total_count}`. Used by the vanilla UI at
        `/` and any external HTTP caller that pre-dates the pagination work.
      * Paginated (`max_keys` set): one S3 call per HTTP request (plus one
        directory-discovery call on the first page). Directories return only
        on the first page (when no `continuation_token`); files paginate via
        S3's `NextContinuationToken`.
      * Client-load (`client_load=1`): aggregate S3 pages up to
        `max_client_load` (or `max_keys` as the chunk size if given) and return
        `{directories, files, truncated, next_token}` for the /v2 UI to hold in
        memory and paginate client-side. Directories only on the first chunk.
    """
    try:
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
            search_prefix = sanitize_search_prefix(search) if isinstance(search, str) and search else ""
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if continuation_token is not None and max_keys is None and not client_load:
            raise HTTPException(
                status_code=400,
                detail="continuation_token requires max_keys to be set as well",
            )

        if search_prefix and not client_load:
            raise HTTPException(
                status_code=400,
                detail="search requires client_load=1",
            )

        if client_load:
            cfg = load_config()
            chunk = max_keys if max_keys is not None else int(cfg.get("max_client_load", 10000))
            page = list_objects_client_load_for_role(
                role,
                bucket_name,
                path,
                current_user,
                chunk,
                continuation_token,
                name_prefix=search_prefix,
            )
            return page

        if max_keys is None:
            files = list_objects_for_role(role, bucket_name, path, current_user)
            return {"files": files, "path": path, "total_count": len(files)}

        page = list_objects_paginated_for_role(
            role,
            bucket_name,
            path,
            current_user,
            max_keys,
            continuation_token,
        )
        return page

    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        error_msg = str(e)
        logger.error(f"Configuration error when listing files: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
        if error_code == "NoSuchBucket":
            raise HTTPException(status_code=404, detail=f"Bucket '{bucket_name}' not found")
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list files: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in list_files")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Server error — see server logs"},
        ) from e


@app.post("/api/buckets/{bucket_name}/upload")
async def upload_file(
    request: Request,
    bucket_name: str,
    file: UploadFile = File(...),
    key: str = Form(..., description="S3 object key (path)"),
    role: Optional[str] = Form(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Upload a file to S3 bucket - delegates the put to s3_client.put_object_for_role.

    The route keeps streaming/size-limit enforcement and the upload_inline_extensions
    content-disposition logic. The helper does role validation, bucket-access
    validation, and metric accounting."""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            key = sanitize_path(key)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Get max_file_size from config (with fallback to env var)
        config = load_config(force_reload=False)
        max_file_size = config.get("max_file_size")
        if max_file_size is None:
            max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
        else:
            max_file_size = int(max_file_size)

        # Check file size if available (some clients provide Content-Length)
        # If not available, we'll check during streaming
        file_size = None
        if hasattr(file, "size") and file.size is not None:
            file_size = file.size
        elif hasattr(request, "headers") and "content-length" in request.headers:
            try:
                file_size = int(request.headers["content-length"])
            except (ValueError, TypeError):
                pass

        if file_size and file_size > max_file_size:
            upload_rejected_total.labels(reason="size_limit").inc()
            size_mb = max_file_size / (1024 * 1024)
            raise HTTPException(status_code=400, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

        # Stream file content in chunks to minimize memory usage
        # This allows handling large files without loading entire file into memory at once
        chunk_size = 8 * 1024 * 1024  # 8MB chunks - good balance between memory and performance
        total_read = 0

        # Use BytesIO for efficient memory management
        # This allows us to stream data without keeping all chunks in a list
        content_buffer = BytesIO()

        # Reset file pointer to beginning (in case it was read before)
        await file.seek(0)

        # Read file in chunks and write to buffer
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break

            total_read += len(chunk)

            # Check size limit during streaming (fail fast)
            if total_read > max_file_size:
                upload_rejected_total.labels(reason="size_limit").inc()
                size_mb = max_file_size / (1024 * 1024)
                raise HTTPException(status_code=400, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

            # Write chunk to buffer
            content_buffer.write(chunk)

        # Get content from buffer
        content_buffer.seek(0)
        content = content_buffer.getvalue()
        content_buffer.close()

        # Check if file extension should have Content-Disposition: inline so it
        # opens in the browser (instead of downloading) when served via CDN /
        # presigned URL. Driven by upload_inline_extensions (split from the old
        # auto_inline_extensions in 1.0.3 — preview is a separate concern now).
        upload_inline_extensions = config.get("upload_inline_extensions", [])
        content_disposition: Optional[str] = None
        if upload_inline_extensions:
            # Get file extension from key (path)
            file_ext = Path(key).suffix.lstrip(".").lower()
            if file_ext in upload_inline_extensions:
                content_disposition = "inline"

        # The helper increments s3_bytes_total (direction="upload") internally -
        # do NOT also increment it here, doing so would double-count.
        put_object_for_role(
            role,
            bucket_name,
            key,
            content,
            current_user,
            content_type=file.content_type or "application/octet-stream",
            content_disposition=content_disposition,
        )
        return {"message": "File uploaded successfully", "key": key}
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        error_msg = str(e)
        logger.error(f"Configuration error when uploading file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        # Log error details for debugging (without credentials)
        error_code = ""
        error_msg = ""
        error_type = type(e).__name__
        http_status_code = None
        if hasattr(e, "response") and e.response:
            if isinstance(e.response, dict):
                error_code = e.response.get("Error", {}).get("Code", "")
                error_msg = e.response.get("Error", {}).get("Message", "")
                http_status_code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            elif hasattr(e.response, "get"):
                error_code = (
                    e.response.get("Error", {}).get("Code", "") if hasattr(e.response.get("Error", {}), "get") else ""
                )

        # Special handling for 403/AccessDenied errors
        is_access_denied = error_code == "AccessDenied" or (http_status_code and http_status_code == 403)
        log_level = logger.warning if is_access_denied else logger.error

        log_extra = {
            "bucket": bucket_name,
            "key": key,
            "role": role,
            "error_type": error_type,
            "error_code": error_code,
            "file_size": total_read if "total_read" in locals() else None,
        }
        if error_msg:
            log_extra["error_message"] = error_msg
        if http_status_code:
            log_extra["http_status_code"] = http_status_code

        log_level(
            f"File upload failed (S3 error{' - Access Denied' if is_access_denied else ''})",
            extra=log_extra,
            exc_info=True,
        )

        # Return 403 status for access denied errors
        status_code = 403 if is_access_denied else 500
        raise HTTPException(status_code=status_code, detail=f"Failed to upload file: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        # Log error details for debugging (without credentials)
        logger.exception(
            "File upload failed (unexpected error)",
            extra={
                "bucket": bucket_name,
                "key": key,
                "role": role,
                "error_type": type(e).__name__,
                "file_size": total_read if "total_read" in locals() else None,
            },
        )
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Upload failed — see server logs"},
        ) from e


def get_user_for_download(token: Optional[str] = Query(None), request: Request = None) -> Dict[str, Any]:
    """Get user from token in URL or Bearer header for downloads"""
    from jose import JWTError, jwt

    from another_s3_manager.auth import get_jwt_secret_key
    from another_s3_manager.constants import JWT_ALGORITHM
    from another_s3_manager.users import load_users

    # Try token from URL first (for direct link downloads without buffering)
    if token:
        try:
            payload = jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
            username = payload.get("sub")
            if username:
                users = load_users()
                user = next((u for u in users.get("users", []) if u.get("username") == username), None)
                if user:
                    user["csrf_token"] = payload.get("csrf_token")
                    return user
        except (JWTError, ValueError):
            # Bad JWT or malformed user input — try the next candidate (or fall through to 401).
            pass

    # Fall back to Bearer header (legacy vanilla UI) or access_token cookie (cookie-auth UI)
    if request:
        candidates = []
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            candidates.append(auth_header[7:])
        cookie_token = request.cookies.get("access_token")
        if cookie_token:
            candidates.append(cookie_token)

        for candidate in candidates:
            try:
                payload = jwt.decode(candidate, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
                username = payload.get("sub")
                if username:
                    users = load_users()
                    user = next((u for u in users.get("users", []) if u.get("username") == username), None)
                    if user:
                        user["csrf_token"] = payload.get("csrf_token")
                        return user
            except (JWTError, ValueError):
                # Bad JWT or malformed user input — try the next candidate (or fall through to 401).
                pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


@app.get("/api/buckets/{bucket_name}/download")
async def download_file(
    bucket_name: str,
    path: str = Query(..., description="Path to file to download"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_user_for_download),
):
    """Download a file from S3 - delegates to s3_client.iter_object_for_role for true streaming."""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Stream the object via the helper. The helper increments the
        # s3_bytes_total metric (direction="download") exactly once at
        # metadata-fetch time and returns a lazy iterator — MUST NOT be
        # materialized to bytes here so 100MB downloads don't get buffered
        # in process memory.
        metadata, body_iter = iter_object_for_role(role, bucket_name, path, current_user)
        filename = path.split("/")[-1]

        from fastapi.responses import StreamingResponse

        headers = {"Content-Disposition": format_content_disposition(filename)}
        content_length = metadata.get("content_length", 0)
        if content_length:
            headers["Content-Length"] = str(content_length)

        return StreamingResponse(
            body_iter,
            media_type=metadata["content_type"],
            headers=headers,
        )
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        # Check if it's a configuration error (contains role_arn or assume role related text)
        error_msg = str(e)
        if "role" in error_msg.lower() or "assume" in error_msg.lower() or "credentials" in error_msg.lower():
            logger.error(f"Configuration error when downloading file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
        if error_code in {"404", "NoSuchKey"}:
            raise HTTPException(status_code=404, detail=f"File '{path}' not found")
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to download file: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in download_file")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Download failed — see server logs"},
        ) from e


@app.get("/api/buckets/{bucket_name}/presigned")
async def get_presigned_url(
    bucket_name: str,
    path: str = Query(..., description="Object key to sign"),
    role: str = Query(..., description="Role name to use (required)"),
    op: str = Query("get", description="Presign operation; only 'get' is supported"),
    expires_in: Optional[int] = Query(
        None,
        description="Requested URL lifetime in seconds. Defaults to the configured "
        "default; must be between 60 and the configured maximum.",
    ),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Return a presigned URL for sharing or browser-side display.

    The signed URL embeds the role's credentials. Lifetime is the configured
    default unless `expires_in` is given, which must be between 60s and the
    configured maximum (out-of-range values are rejected with 400, not clamped).
    The response echoes the granted `expires_in` and, for
    STS-backed roles (assume_role / profile) asked for more than 1h, a `warning`
    that the link may expire when the role's session ends.

    `role` is required. The frontend always passes it explicitly. Direct API
    callers that omit it get 422 from FastAPI's query validation.
    """
    from datetime import datetime, timedelta, timezone

    if op != "get":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported op: {op!r} (only 'get' is supported)",
        )

    # Resolve configured TTL bounds (config → env → default, clamped to ceiling).
    # Validate expires_in before bucket/path sanitization so callers get a clean
    # INVALID_EXPIRES_IN error even when bucket name shorthand is used in tests.
    config = load_config(force_reload=False)
    default_ttl, max_ttl = resolve_presigned_ttls(config)

    if expires_in is None:
        granted_ttl = default_ttl
    else:
        if expires_in < PRESIGNED_URL_MIN_TTL or expires_in > max_ttl:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "INVALID_EXPIRES_IN",
                    "message": (f"expires_in must be between {PRESIGNED_URL_MIN_TTL} and {max_ttl} seconds"),
                },
            )
        granted_ttl = expires_in

    try:
        bucket_name = sanitize_bucket_name(bucket_name)
        path = sanitize_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Validate the role belongs to the user; on success, validated_role is the
    # canonical role string the helper expects.
    validated_role = validate_role_access(role, current_user) or role

    try:
        url = s3_generate_presigned_url_for_role(
            validated_role,
            bucket_name,
            path,
            current_user,
            expires_in=granted_ttl,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ClientError, BotoCoreError) as e:
        raise HTTPException(status_code=500, detail=format_boto_error(e))
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in get_presigned_url")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Presigned URL generation failed — see server logs"},
        ) from e

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=granted_ttl)).isoformat()
    response: Dict[str, Any] = {
        "url": url,
        "expires_at": expires_at,
        "expires_in": granted_ttl,
    }
    if granted_ttl > PRESIGNED_STS_WARNING_THRESHOLD and role_uses_temporary_credentials(validated_role):
        response["warning"] = (
            "This role uses temporary credentials — the link may stop working earlier, when the role's session expires."
        )
    return response


@app.delete("/api/buckets/{bucket_name}/files")
async def delete_file(
    request: Request,
    bucket_name: str,
    path: str = Query(..., description="Path to file or directory to delete"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Delete a file or recursively delete a directory from S3"""
    # Check if deletion is disabled (from environment variable or config)
    config = load_config(force_reload=False)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)

    if disable_deletion_env or disable_deletion_config:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="File deletion is disabled by administrator")
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path:
            raise HTTPException(status_code=400, detail="Cannot delete root path")

        # Delegate to s3_client.delete_object_for_role. The helper does its own
        # role/bucket access validation, paginates list_objects_v2, falls back
        # to delete_object for single-file paths, and raises FileNotFoundError
        # when nothing matches. Returns {"message": ..., "count": N}.
        return delete_object_for_role(role, bucket_name, path, current_user)
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        # Check if it's a configuration error (contains role_arn or assume role related text)
        error_msg = str(e)
        if "role" in error_msg.lower() or "assume" in error_msg.lower() or "credentials" in error_msg.lower():
            logger.error(f"Configuration error when deleting file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in delete_file")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Delete failed — see server logs"},
        ) from e


# Mount MCP sub-app at /mcp — must come AFTER all @app.get/@app.post route
# registrations (so the middleware stack is complete) and BEFORE the SPA
# catch-all below: the catch-all is greedy, anything registered after it is
# unreachable. ROUTE ORDERING INVARIANT: API routes -> /mcp mount -> SPA
# catch-all LAST.
from another_s3_manager.mcp_server import get_mcp_app

app.mount("/mcp", get_mcp_app())


# Root React SPA (built by frontend/, bundled into static/app/ by the
# multi-stage Dockerfile). Phase 7 removed the vanilla UI — the SPA owns
# every path, including the old /v2/* URLs (they render the router's 404).
#
# Single catch-all: real files (assets, favicon) are served with the right
# content-type; everything else falls back to index.html so React Router
# handles the URL. Files are read fully into memory and returned via
# Response (not FileResponse) — SPA bundles are <1MB, the cost is
# negligible and it avoids Starlette mount-vs-route ordering bugs
# (https://github.com/encode/starlette/issues/437).
_SPA_DIR = STATIC_DIR / "app"

# Unknown paths under these prefixes 404 as JSON instead of serving
# index.html — an HTML 200 for a typo'd API call reads as success to
# clients and would mask MCP misroutes. (Known routes and the /mcp mount
# win by registration order; this guard covers the UNKNOWN remainder.)
_RESERVED_PREFIXES = ("api/", "mcp/")
_RESERVED_EXACT = {"api", "mcp", "metrics", "health"}


# Pre-Phase-7, bare /mcp worked via Starlette's redirect_slashes (307 to
# /mcp/). The GET catch-all below shadows that mechanism (full match beats
# the redirect fallback; for POST the catch-all's partial match turns into
# a 405). Existing agent configs point at /mcp without a trailing slash, so
# keep the redirect explicit. Methods = MCP streamable-HTTP verbs.
@app.api_route("/mcp", methods=["GET", "POST", "DELETE"], include_in_schema=False)
async def mcp_no_slash_redirect():
    return RedirectResponse(url="/mcp/", status_code=307)


@app.get("/", response_class=HTMLResponse)
async def serve_spa_root():
    """Bare / → index.html."""
    return await serve_spa("")


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """SPA-aware static handler (see block comment above)."""
    import mimetypes

    from fastapi import Response

    if full_path in _RESERVED_EXACT or full_path.startswith(_RESERVED_PREFIXES):
        raise HTTPException(status_code=404, detail="Not found")

    # Block path traversal at the route level (sanitize_path is for S3 keys)
    if ".." in full_path or full_path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")

    if full_path:
        candidate = _SPA_DIR / full_path
        try:
            candidate_resolved = candidate.resolve()
            spa_resolved = _SPA_DIR.resolve()
            if spa_resolved in candidate_resolved.parents and candidate.is_file():
                content_type, _ = mimetypes.guess_type(str(candidate))
                if not content_type:
                    content_type = "application/octet-stream"
                return Response(content=candidate.read_bytes(), media_type=content_type)
        except (OSError, ValueError):
            pass  # fall through to index.html

    index_file = _SPA_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="React SPA not built yet")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    log_level = str(os.getenv("LOG_LEVEL", "info")).lower()
    host = str(os.getenv("UVICORN_HOST", "0.0.0.0"))
    uvicorn.run(app, host=host, port=port, log_level=log_level)
