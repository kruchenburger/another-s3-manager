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
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

import another_s3_manager.config as config_module
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
from another_s3_manager.config import load_config, save_config
from another_s3_manager.constants import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    COOKIE_SECURE,
    STATIC_DIR,
)
from another_s3_manager.errors import S3OperationError
from another_s3_manager.metrics import (
    REGISTRY,
    http_request_duration_seconds,
    http_requests_total,
)
from another_s3_manager.s3_client import clear_s3_clients_cache, execute_with_s3_retry
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
    response = await call_next(request)
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


@app.get("/metrics")
async def metrics_endpoint(request: Request):
    """Prometheus metrics exposition endpoint. Optional METRICS_PASSWORD basic auth."""
    _check_metrics_auth(request)
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# Health endpoint (no auth required)
@app.get("/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# /v2 React SPA (built by frontend/, bundled into static/v2/ by the multi-stage Dockerfile).
# During strangler-fig migration vanilla UI keeps serving /, /login, /admin.
#
# Single catch-all route: real files (JS/CSS/images under /v2/assets, favicon, etc.)
# are served via FileResponse; everything else falls back to index.html so React Router
# can handle client-side navigation. Avoids mount-vs-route ordering bugs in Starlette
# (see https://github.com/encode/starlette/issues/437).
_V2_DIR = STATIC_DIR / "v2"


@app.get("/v2", response_class=HTMLResponse)
@app.get("/v2/", response_class=HTMLResponse)
async def serve_v2_root():
    """Bare /v2 → index.html."""
    return await serve_v2_spa("")


@app.get("/v2/{full_path:path}")
async def serve_v2_spa(full_path: str):
    """SPA-aware static handler:
    - If a real file exists at static/v2/<full_path>, serve it (correct content-type).
    - Otherwise serve index.html so React Router takes over the URL.

    Files are read fully into memory and returned via Response (not FileResponse).
    SPA bundles are tiny enough (~600KB) that this is fine.
    """
    import mimetypes

    from fastapi import Response

    # Block path traversal at the route level too (sanitize_path is for S3 keys, not local FS)
    if ".." in full_path or full_path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")

    if full_path:
        candidate = _V2_DIR / full_path
        # Resolve to absolute path and verify it stays within _V2_DIR (defense-in-depth)
        try:
            candidate_resolved = candidate.resolve()
            v2_resolved = _V2_DIR.resolve()
            if v2_resolved in candidate_resolved.parents and candidate.is_file():
                content_type, _ = mimetypes.guess_type(str(candidate))
                if not content_type:
                    content_type = "application/octet-stream"
                return Response(content=candidate.read_bytes(), media_type=content_type)
        except (OSError, ValueError):
            pass  # fall through to index.html

    # SPA fallback
    index_file = _V2_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="React SPA not built yet")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


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


@app.get("/", response_class=HTMLResponse)
async def root():
    """Main page with file manager interface (auth handled by frontend)"""
    html_file = STATIC_DIR / "index.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Login page"""
    html_file = STATIC_DIR / "login.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is banned. Try again in {remaining} minutes.",
            )

        users = load_users()
        user = next((u for u in users.get("users", []) if u.get("username") == username), None)

        if user is None:
            record_login_attempt(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )

        # Verify password
        if not verify_password(password, user.get("password_hash", "")):
            record_login_attempt(username, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )

        # Successful login
        record_login_attempt(username, True)

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
    # allowed_roles, else null.
    explicit_default = current_user.get("default_role")
    if explicit_default and explicit_default in allowed_roles:
        default_role: Optional[str] = explicit_default
    elif allowed_roles:
        default_role = allowed_roles[0]
    else:
        default_role = None
    return {
        "username": current_user.get("username"),
        "is_admin": is_admin,
        "csrf_token": current_user.get("csrf_token"),  # Return CSRF token for client
        "theme": current_user.get("theme", "auto"),  # Return user's theme preference
        "allowed_roles": allowed_roles,
        "default_role": default_role,
        "disable_deletion": disable_deletion,
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


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Admin page (authentication checked on client side)"""
    html_file = STATIC_DIR / "admin.html"
    with open(html_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


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
        "created_at": datetime.now().isoformat(),
    }

    users.setdefault("users", []).append(new_user)
    save_users(users)

    return {"message": "User created successfully", "username": username}


@app.put("/api/admin/users/{username}/password")
async def update_user_password(
    request: Request,
    username: str,
    password: str = Body(..., embed=True, description="New password"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update user password (admin only)"""
    if not password or len(password.strip()) == 0:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    users = load_users()
    user = next((u for u in users.get("users", []) if u.get("username") == username), None)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    _enforce_password_policy(password)

    # Hash password using auth module
    hashed_password = hash_password(password)

    user["password_hash"] = hashed_password
    save_users(users)

    return {"message": f"Password updated successfully for user {username}"}


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

    users_update_user(username, password_hash=hash_password(payload.new_password))
    return {"ok": True}


class UpdateDefaultRolePayload(BaseModel):
    role: Optional[str] = None


@app.put("/api/me/default-role")
async def update_my_default_role(
    payload: UpdateDefaultRolePayload,
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Set the authenticated user's default role.

    Payload: {"role": "<role-name>" | null}. `null` clears the explicit choice
    so the computed fallback applies (first of allowed_roles, or null).
    Returns 400 if the role is not in the user's allowed set.
    """
    new_role = payload.role
    if new_role is not None:
        # Validate against the user's CURRENT allowed_roles (not the legacy
        # global config). Admin gets the full role list per /api/me logic.
        is_admin = current_user.get("is_admin", False)
        if is_admin:
            config = load_config()
            allowed = [r["name"] for r in config.get("roles", []) if r.get("name")]
        else:
            allowed = current_user.get("allowed_roles", [])
        if new_role not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Role '{new_role}' is not in your allowed roles",
            )
    from another_s3_manager.users import update_user as users_update_user_role

    try:
        users_update_user_role(current_user["username"], default_role=new_role)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"default_role": new_role}


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

    # Get items_per_page from config file, fallback to environment variable, then default
    items_per_page = config.get("items_per_page")
    if items_per_page is None:
        items_per_page = int(os.getenv("ITEMS_PER_PAGE", "200"))
    else:
        items_per_page = int(items_per_page)

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

        # Apply default_role if specified
        default_role = config.get("default_role", "")
        if default_role and any(r.get("name") == default_role for r in config.get("roles", [])):
            effective_role = default_role
        else:
            # Use first role if default_role is not set or invalid
            effective_role = config.get("roles", [{}])[0].get("name", "") if config.get("roles") else ""

        safe_config = {
            "roles": [sanitize_role(role) for role in config.get("roles", [])],
            "default_role": default_role,  # Return default_role so admin can see/edit it
            "current_role": effective_role,  # Computed value for frontend (not stored in config)
            "items_per_page": items_per_page,
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "auto_inline_extensions": config.get("auto_inline_extensions", []),
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
            "items_per_page": items_per_page,
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
        }

    # Filter roles and sanitize
    filtered_roles = [sanitize_role(role) for role in config.get("roles", []) if role.get("name") in allowed_roles]

    # Apply default_role if specified and available
    default_role = config.get("default_role", "")

    # If default_role is set and is in allowed_roles, use it
    if default_role and default_role in allowed_roles:
        effective_role = default_role
    # Otherwise, use first allowed role or empty
    else:
        effective_role = allowed_roles[0] if allowed_roles else ""

    return {
        "roles": filtered_roles,
        "current_role": effective_role,
        "items_per_page": items_per_page,
        "disable_deletion": disable_deletion,
        "enable_lazy_loading": enable_lazy_loading,
        "max_file_size": max_file_size,
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

        # Handle items_per_page - if provided, validate and use it; otherwise preserve existing
        if "items_per_page" in config:
            # Validate items_per_page
            try:
                items_per_page_val = int(config["items_per_page"])
                if items_per_page_val < 10 or items_per_page_val > 1000:
                    raise HTTPException(status_code=400, detail="items_per_page must be between 10 and 1000")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="items_per_page must be a valid integer")
        else:
            # Preserve items_per_page from current config if not provided
            current_config = load_config(force_reload=False)
            if "items_per_page" in current_config:
                config["items_per_page"] = current_config["items_per_page"]

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

        # Handle auto_inline_extensions - if provided, validate and use it; otherwise preserve existing
        if "auto_inline_extensions" in config:
            # Validate auto_inline_extensions (must be a list of strings)
            if not isinstance(config["auto_inline_extensions"], list):
                raise HTTPException(status_code=400, detail="auto_inline_extensions must be a list")
            # Validate that all items are strings
            for ext in config["auto_inline_extensions"]:
                if not isinstance(ext, str):
                    raise HTTPException(status_code=400, detail="auto_inline_extensions must contain only strings")
            # Normalize extensions: remove leading dots and convert to lowercase
            config["auto_inline_extensions"] = [
                ext.lstrip(".").lower() for ext in config["auto_inline_extensions"] if ext.strip()
            ]
        else:
            # Preserve auto_inline_extensions from current config if exists, otherwise use default
            current_config = load_config(force_reload=False)
            if "auto_inline_extensions" in current_config:
                config["auto_inline_extensions"] = current_config["auto_inline_extensions"]
            else:
                config["auto_inline_extensions"] = []

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
    """List available S3 buckets - either from allowed_buckets config or by listing all buckets"""
    try:
        # Validate role access
        validated_role = validate_role_access(role, current_user)

        # Load config to check for allowed_buckets
        from another_s3_manager.config import load_config as _load_config

        config = _load_config(force_reload=False)
        roles = config.get("roles", [])

        # Find the role configuration
        role_config = None
        if validated_role:
            role_config = next((r for r in roles if r.get("name") == validated_role), None)
        else:
            # Use first role
            role_config = roles[0] if roles else None

        # Check if role has allowed_buckets configured
        if role_config and "allowed_buckets" in role_config and role_config["allowed_buckets"]:
            # Return configured buckets without requiring list_buckets permission
            allowed_buckets = role_config["allowed_buckets"]
            if isinstance(allowed_buckets, list):
                # Verify buckets exist and user has access (optional - can be disabled for performance)
                # For now, just return the list as-is
                return allowed_buckets
            else:
                raise HTTPException(status_code=400, detail="allowed_buckets must be a list")

        # Fallback to listing all buckets (requires s3:ListAllMyBuckets permission)
        def fetch_buckets(s3_client):
            response = s3_client.list_buckets()
            return [bucket["Name"] for bucket in response["Buckets"]]

        return execute_with_s3_retry(validated_role, "list", fetch_buckets)
    except HTTPException:
        raise
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        error_msg = str(e)
        logger.error(f"Configuration error when listing buckets: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
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
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List files and directories in a bucket at the specified path"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        # Normalize path - remove leading/trailing slashes
        prefix = path + "/" if path else ""

        def fetch_files(s3_client):
            files = []
            directories = set()  # Track directories to avoid duplicates

            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix, Delimiter="/")

            for page in pages:
                if "CommonPrefixes" in page:
                    for prefix_obj in page["CommonPrefixes"]:
                        dir_name = prefix_obj["Prefix"][len(prefix) :].rstrip("/")
                        if dir_name and dir_name not in directories:
                            directories.add(dir_name)
                            files.append({"name": dir_name, "is_directory": True, "size": 0})

                if "Contents" in page:
                    for obj in page["Contents"]:
                        if obj["Key"].endswith("/") and obj["Size"] == 0:
                            continue

                        file_name = obj["Key"][len(prefix) :]
                        if file_name:
                            files.append(
                                {
                                    "name": file_name,
                                    "is_directory": False,
                                    "size": obj["Size"],
                                    "last_modified": obj["LastModified"].isoformat(),
                                }
                            )

            files.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))
            return {"files": files, "path": path, "total_count": len(files)}

        return execute_with_s3_retry(validated_role, "list", fetch_files)
    except HTTPException:
        raise
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
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
    """Upload a file to S3 bucket using streaming to minimize memory usage"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            key = sanitize_path(key)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)
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
                size_mb = max_file_size / (1024 * 1024)
                raise HTTPException(status_code=400, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

            # Write chunk to buffer
            content_buffer.write(chunk)

        # Get content from buffer
        content_buffer.seek(0)
        content = content_buffer.getvalue()
        content_buffer.close()

        # Check if file extension should have Content-Disposition: inline
        auto_inline_extensions = config.get("auto_inline_extensions", [])
        content_disposition = None
        if auto_inline_extensions:
            # Get file extension from key (path)
            file_ext = Path(key).suffix.lstrip(".").lower()
            if file_ext in auto_inline_extensions:
                content_disposition = "inline"

        def upload_object(s3_client):
            put_object_params = {
                "Bucket": bucket_name,
                "Key": key,
                "Body": content,
                "ContentType": file.content_type or "application/octet-stream",
            }
            if content_disposition:
                put_object_params["ContentDisposition"] = content_disposition
            s3_client.put_object(**put_object_params)
            return {"message": "File uploaded successfully", "key": key}

        result = execute_with_s3_retry(validated_role, "put", upload_object)
        # Record bytes uploaded after a successful put
        from another_s3_manager.metrics import s3_bytes_uploaded_total, safe_role_label

        s3_bytes_uploaded_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket_name).inc(
            len(content)
        )
        return result
    except HTTPException:
        raise
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
            "role": validated_role,
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
                "role": validated_role,
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
    """Download a file from S3 bucket directly"""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate role access
        validated_role = validate_role_access(role, current_user)

        def fetch_object(s3_client):
            return s3_client.get_object(Bucket=bucket_name, Key=path)

        response = execute_with_s3_retry(validated_role, "get", fetch_object)
        # Record bytes downloaded; ContentLength is available in get_object metadata
        content_length = response.get("ContentLength", 0)
        if content_length:
            from another_s3_manager.metrics import s3_bytes_downloaded_total, safe_role_label

            s3_bytes_downloaded_total.labels(role=safe_role_label(validated_role or "unknown"), bucket=bucket_name).inc(
                content_length
            )
        content_type = response.get("ContentType", "application/octet-stream")
        filename = path.split("/")[-1]  # Get filename from path

        # Create generator to stream file directly from S3 without loading into memory
        # FastAPI StreamingResponse can handle regular generators for streaming
        def generate():
            body = response["Body"]
            chunk_size = 8192  # 8KB chunks
            try:
                while True:
                    chunk = body.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                # Ensure body is closed properly
                if hasattr(body, "close"):
                    try:
                        body.close()
                    except Exception:
                        pass

        # Return file as streaming response - stream directly from S3
        from fastapi.responses import StreamingResponse

        return StreamingResponse(
            generate(), media_type=content_type, headers={"Content-Disposition": format_content_disposition(filename)}
        )
    except HTTPException:
        raise
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
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Return a short-lived presigned URL for sharing or browser-side display.

    The signed URL embeds the role's credentials and is valid for 1 hour.
    Use this for Copy URL flows and for `<img>/<video>` srcs that can't
    carry the auth cookie reliably. The helper auto-applies a UTF-8 charset
    override for known text extensions so Cyrillic / CJK / emoji content
    renders correctly when the link is opened in a new tab.

    `role` is required (the underlying `s3_client._for_role` helper signature
    is `role: str`, not Optional). The frontend always passes it explicitly.
    Direct API callers that omit it get 422 from FastAPI's query validation.
    """
    from datetime import datetime, timedelta, timezone

    if op != "get":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported op: {op!r} (only 'get' is supported)",
        )

    try:
        bucket_name = sanitize_bucket_name(bucket_name)
        path = sanitize_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Validate the role belongs to the user; on success, validated_role is the
    # canonical role string the helper expects.
    validated_role = validate_role_access(role, current_user) or role

    expires_in = 3600
    try:
        url = s3_generate_presigned_url_for_role(
            validated_role,
            bucket_name,
            path,
            current_user,
            expires_in=expires_in,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ClientError, BotoCoreError) as e:
        # STS assume_role failure / credential refresh failure / invalid bucket
        # config — produce a clean error rather than a bare 500 with botocore repr.
        raise HTTPException(status_code=500, detail=format_boto_error(e))
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in get_presigned_url")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Presigned URL generation failed — see server logs"},
        ) from e

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
    return {"url": url, "expires_at": expires_at}


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

        # Validate role access
        validated_role = validate_role_access(role, current_user)
        # Normalize path
        prefix = path
        if not prefix:
            raise HTTPException(status_code=400, detail="Cannot delete root path")

        # Check if it's a directory (ends with /) or a file
        is_directory = prefix.endswith("/")
        if is_directory:
            prefix = prefix.rstrip("/")

        def perform_delete(s3_client):
            deleted_count = 0
            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix + ("/" if is_directory else ""))

            objects_to_delete = []
            for page in pages:
                if "Contents" in page:
                    for obj in page["Contents"]:
                        objects_to_delete.append({"Key": obj["Key"]})

            if not is_directory and not objects_to_delete:
                try:
                    s3_client.delete_object(Bucket=bucket_name, Key=prefix)
                    deleted_count = 1
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
                    if error_code in ("404", "NoSuchKey"):
                        raise HTTPException(status_code=404, detail=f"File or directory '{path}' not found")
                    raise
            else:
                if objects_to_delete:
                    for i in range(0, len(objects_to_delete), 1000):
                        batch = objects_to_delete[i : i + 1000]
                        s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": batch, "Quiet": True})
                        deleted_count += len(batch)

            if deleted_count == 0:
                raise HTTPException(status_code=404, detail=f"File or directory '{path}' not found")

            return {"message": f"Successfully deleted {deleted_count} object(s)", "count": deleted_count}

        return execute_with_s3_retry(validated_role, "delete", perform_delete)
    except HTTPException:
        raise
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
# registrations and AFTER middleware is wired up, so Starlette's middleware
# stack is already complete when the mount is added.
from another_s3_manager.mcp_server import get_mcp_app

app.mount("/mcp", get_mcp_app())


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    log_level = str(os.getenv("LOG_LEVEL", "info")).lower()
    host = str(os.getenv("UVICORN_HOST", "0.0.0.0"))
    uvicorn.run(app, host=host, port=port, log_level=log_level)
