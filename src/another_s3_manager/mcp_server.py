"""MCP server for another-s3-manager.

Mounted as a FastAPI sub-app at /mcp via Streamable HTTP transport.
All permission decisions delegate to s3_client.py — single source of truth.
"""

import hashlib
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from starlette.requests import Request

import another_s3_manager.config as _config_module
from another_s3_manager import api_tokens as token_svc
from another_s3_manager import s3_client as _s3_client
from another_s3_manager.metrics import (
    mcp_auth_failures_total,
    mcp_tool_calls_total,
    mcp_tool_duration_seconds,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP request context propagation
# ---------------------------------------------------------------------------

# Starlette Request captured from the ASGI scope, used by tool bodies to read
# the Authorization header. Set per-request by _RequestCaptureMiddleware.
_current_request: ContextVar[Request | None] = ContextVar("mcp_request", default=None)


class _RequestCaptureMiddleware:
    """ASGI middleware that captures the Starlette Request into a ContextVar.

    This lets MCP tool bodies access HTTP headers (e.g. the Bearer token)
    even though FastMCP does not expose the HTTP request through its Context.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            request = Request(scope, receive)
            token = _current_request.set(request)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_request.reset(token)
        else:
            await self.app(scope, receive, send)


def _get_current_request() -> Request:
    """Return the current HTTP request from the contextvar.

    Raises McpError if called outside an HTTP request context.
    """
    req = _current_request.get()
    if req is None:
        raise McpError("INTERNAL_ERROR", "No HTTP request context available")
    return req


# ---------------------------------------------------------------------------
# McpError
# ---------------------------------------------------------------------------


@dataclass
class McpError(Exception):
    code: str
    message: str
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def to_payload(self) -> dict:
        return {"error": self.code, "message": self.message, "details": self.details}


# ---------------------------------------------------------------------------
# Write-gate
# ---------------------------------------------------------------------------

# Tools that perform write operations — used by assert_write_allowed.
WRITE_TOOLS = {"upload_file", "delete_file"}


def assert_write_allowed(token: Any, tool_name: str, config: dict) -> None:
    """Raise McpError if the given token/config combination disallows a write tool.

    Decision order (most authoritative first):
    1. Server-wide write disable (mcp_disable_writes in config).
    2. Per-token read-only flag.
    3. delete_file blocked when server-level deletion is disabled.
    """
    if config.get("mcp_disable_writes", False):
        raise McpError(
            "READ_ONLY_SERVER",
            "Server config disables MCP writes",
            {"tool": tool_name},
        )
    if token.is_read_only:
        raise McpError(
            "READ_ONLY_TOKEN",
            "This token is read-only",
            {"tool": tool_name},
        )
    if tool_name == "delete_file" and config.get("disable_deletion", False):
        raise McpError(
            "DELETION_DISABLED",
            "Deletion is disabled in server config",
            {"tool": tool_name},
        )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


async def authenticate_mcp_request(request: Any) -> tuple[Any, dict]:
    """Parse Bearer token, look up hash in DB, return (token_orm, user_dict).

    Raises McpError on any authentication failure, incrementing the
    mcp_auth_failures_total Prometheus counter with an appropriate reason label.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        mcp_auth_failures_total.labels(reason="malformed").inc()
        raise McpError("INVALID_TOKEN", "Missing or malformed Bearer token")

    plaintext = auth_header[len("Bearer ") :]
    if not plaintext.startswith("as3m_"):
        mcp_auth_failures_total.labels(reason="malformed").inc()
        raise McpError("INVALID_TOKEN", "Token does not start with as3m_")

    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    token = token_svc.find_active_token_by_hash(digest)
    if token is None:
        mcp_auth_failures_total.labels(reason="invalid_token").inc()
        raise McpError("INVALID_TOKEN", "Invalid or revoked token")

    # Resolve the owning user inside a single session scope.
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User as UserModel

    with session_scope() as session:
        u = session.execute(
            select(UserModel).where(UserModel.id == token.user_id).options(selectinload(UserModel.roles))
        ).scalar_one_or_none()
        if u is None:
            mcp_auth_failures_total.labels(reason="invalid_token").inc()
            raise McpError("INVALID_TOKEN", "Token's user no longer exists")
        user_dict = {
            "username": u.username,
            "is_admin": u.is_admin,
            "allowed_roles": [r.role_name for r in u.roles],
        }

    token_svc.touch_last_used(token.id)
    return token, user_dict


# ---------------------------------------------------------------------------
# MCP app factory
# ---------------------------------------------------------------------------


def get_mcp_app() -> Any:
    """Return the ASGI app for the MCP sub-app, mountable on FastAPI at /mcp.

    Uses FastMCP (MCP SDK 1.12.4) which handles Streamable HTTP transport,
    tool registration, and dispatch internally via @mcp.tool() decorators.

    The returned app is wrapped in _RequestCaptureMiddleware so that each
    tool body can retrieve the current HTTP request (and its Authorization
    header) via _get_current_request().
    """
    import base64

    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("another-s3-manager")

    # ------------------------------------------------------------------
    # list_roles — returns the intersection of user's allowed_roles and
    # role names defined in config (only what actually exists).
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_roles() -> dict:
        """List role names accessible to the authenticated user."""
        error_code = "none"
        start = time.perf_counter()
        try:
            token, user = await authenticate_mcp_request(_get_current_request())
            config = _config_module.load_config(force_reload=False)
            all_role_names = {r["name"] for r in config.get("roles", [])}
            visible = [r for r in user["allowed_roles"] if r in all_role_names]
            logger.info("mcp.list_roles", extra={"user": user["username"], "count": len(visible)})
            return {"roles": visible}
        except McpError:
            raise
        except Exception:
            error_code = "INTERNAL_ERROR"
            logger.exception("mcp.list_roles.error")
            raise McpError("INTERNAL_ERROR", "Internal server error")
        finally:
            mcp_tool_calls_total.labels(tool="list_roles", error_code=error_code).inc()
            mcp_tool_duration_seconds.labels(tool="list_roles").observe(time.perf_counter() - start)

    # ------------------------------------------------------------------
    # list_buckets — lists buckets accessible via the given role.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_buckets(role: str) -> dict:
        """List buckets accessible via the given role."""
        error_code = "none"
        start = time.perf_counter()
        try:
            token, user = await authenticate_mcp_request(_get_current_request())
            try:
                buckets = _s3_client.list_buckets_for_role(role, user)
            except PermissionError as e:
                raise McpError(
                    "ROLE_NOT_ALLOWED",
                    str(e),
                    {"role": role, "allowed_roles": user["allowed_roles"]},
                )
            logger.info("mcp.list_buckets", extra={"user": user["username"], "role": role, "count": len(buckets)})
            return {"buckets": buckets}
        except McpError as e:
            error_code = e.code
            raise
        except Exception:
            error_code = "INTERNAL_ERROR"
            logger.exception("mcp.list_buckets.error")
            raise McpError("INTERNAL_ERROR", "Internal server error")
        finally:
            mcp_tool_calls_total.labels(tool="list_buckets", error_code=error_code).inc()
            mcp_tool_duration_seconds.labels(tool="list_buckets").observe(time.perf_counter() - start)

    # ------------------------------------------------------------------
    # list_files — lists files at a path within a bucket.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_files(role: str, bucket: str, path: str = "") -> dict:
        """List files at a path within a bucket."""
        error_code = "none"
        start = time.perf_counter()
        try:
            token, user = await authenticate_mcp_request(_get_current_request())
            try:
                files = _s3_client.list_objects_for_role(role, bucket, path, user)
            except PermissionError as e:
                msg = str(e).lower()
                if "bucket" in msg:
                    raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
                raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
            logger.info(
                "mcp.list_files",
                extra={"user": user["username"], "role": role, "bucket": bucket, "path": path, "count": len(files)},
            )
            return {"files": files}
        except McpError as e:
            error_code = e.code
            raise
        except Exception:
            error_code = "INTERNAL_ERROR"
            logger.exception("mcp.list_files.error")
            raise McpError("INTERNAL_ERROR", "Internal server error")
        finally:
            mcp_tool_calls_total.labels(tool="list_files", error_code=error_code).inc()
            mcp_tool_duration_seconds.labels(tool="list_files").observe(time.perf_counter() - start)

    # ------------------------------------------------------------------
    # upload_file — upload a file to a bucket. Content as base64.
    # WRITE TOOL: gated by assert_write_allowed.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def upload_file(role: str, bucket: str, path: str, content_base64: str) -> dict:
        """Upload a file to a bucket. Content must be base64-encoded."""
        error_code = "none"
        start = time.perf_counter()
        try:
            token, user = await authenticate_mcp_request(_get_current_request())
            config = _config_module.load_config(force_reload=False)
            assert_write_allowed(token, "upload_file", config)
            content = base64.b64decode(content_base64)
            try:
                _s3_client.put_object_for_role(role, bucket, path, content, user)
            except PermissionError as e:
                msg = str(e).lower()
                if "bucket" in msg:
                    raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
                raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
            logger.info(
                "mcp.upload_file",
                extra={"user": user["username"], "role": role, "bucket": bucket, "path": path, "size": len(content)},
            )
            return {"ok": True, "bucket": bucket, "path": path, "size": len(content)}
        except McpError as e:
            error_code = e.code
            raise
        except Exception:
            error_code = "INTERNAL_ERROR"
            logger.exception("mcp.upload_file.error")
            raise McpError("INTERNAL_ERROR", "Internal server error")
        finally:
            mcp_tool_calls_total.labels(tool="upload_file", error_code=error_code).inc()
            mcp_tool_duration_seconds.labels(tool="upload_file").observe(time.perf_counter() - start)

    # ------------------------------------------------------------------
    # delete_file — delete a file from a bucket.
    # WRITE TOOL: gated by assert_write_allowed.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def delete_file(role: str, bucket: str, path: str) -> dict:
        """Delete a file from a bucket."""
        error_code = "none"
        start = time.perf_counter()
        try:
            token, user = await authenticate_mcp_request(_get_current_request())
            config = _config_module.load_config(force_reload=False)
            assert_write_allowed(token, "delete_file", config)
            try:
                _s3_client.delete_object_for_role(role, bucket, path, user)
            except PermissionError as e:
                msg = str(e).lower()
                if "bucket" in msg:
                    raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
                raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
            logger.info(
                "mcp.delete_file",
                extra={"user": user["username"], "role": role, "bucket": bucket, "path": path},
            )
            return {"ok": True, "bucket": bucket, "path": path}
        except McpError as e:
            error_code = e.code
            raise
        except Exception:
            error_code = "INTERNAL_ERROR"
            logger.exception("mcp.delete_file.error")
            raise McpError("INTERNAL_ERROR", "Internal server error")
        finally:
            mcp_tool_calls_total.labels(tool="delete_file", error_code=error_code).inc()
            mcp_tool_duration_seconds.labels(tool="delete_file").observe(time.perf_counter() - start)

    asgi_app = mcp.streamable_http_app()
    return _RequestCaptureMiddleware(asgi_app)
