"""MCP server for another-s3-manager.

Mounted as a FastAPI sub-app at /mcp via Streamable HTTP transport.
All permission decisions delegate to s3_client.py — single source of truth.
"""

import base64
import binascii
import hashlib
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request

import another_s3_manager.config as _config_module
from another_s3_manager import api_tokens as token_svc
from another_s3_manager import s3_client as _s3_client
from another_s3_manager.metrics import (
    mcp_auth_failures_total,
    mcp_bytes_read_total,
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
        # Admins implicitly have access to every role in config — same expansion
        # the web UI does in GET /api/me. Without this, an admin-issued MCP
        # token returns 0 roles via list_roles because the admin user's
        # allowed_roles column is empty (admins manage roles, they don't get
        # explicit assignments).
        if u.is_admin:
            cfg = _config_module.load_config(force_reload=False)
            allowed_roles = [r["name"] for r in cfg.get("roles", []) if r.get("name")]
        else:
            allowed_roles = [r.role_name for r in u.roles]
        user_dict = {
            "username": u.username,
            "is_admin": u.is_admin,
            "allowed_roles": allowed_roles,
        }

    token_svc.touch_last_used(token.id)
    return token, user_dict


# ---------------------------------------------------------------------------
# Text/binary classification constants and helpers for read_file
# ---------------------------------------------------------------------------

TEXT_EXTENSIONS_WHITELIST: frozenset[str] = frozenset(
    {
        "txt",
        "md",
        "rst",
        "json",
        "yaml",
        "yml",
        "toml",
        "xml",
        "html",
        "htm",
        "css",
        "scss",
        "less",
        "csv",
        "tsv",
        "ndjson",
        "jsonl",
        "log",
        "conf",
        "cfg",
        "ini",
        "env",
        "properties",
        "py",
        "js",
        "ts",
        "tsx",
        "jsx",
        "mjs",
        "cjs",
        "vue",
        "svelte",
        "sh",
        "bash",
        "zsh",
        "fish",
        "ps1",
        "sql",
        "go",
        "rs",
        "rb",
        "java",
        "kt",
        "swift",
        "c",
        "cpp",
        "h",
        "hpp",
        "lua",
        "pl",
        "pm",
        "ex",
        "exs",
        "erl",
        "hs",
        "clj",
        "scala",
        "graphql",
        "gql",
        "proto",
    }
)

EXTENSIONLESS_TEXT_BASENAMES: frozenset[str] = frozenset(
    {
        "readme",
        "license",
        "licence",
        "copying",
        "authors",
        "changelog",
        "news",
        "dockerfile",
        "makefile",
        "rakefile",
        "procfile",
        "vagrantfile",
        "gitignore",
        "dockerignore",
        "gitattributes",
    }
)

UNKNOWN_OK_TO_SNIFF: frozenset[str] = frozenset({"data", "out", "dump", "bak"})

KNOWN_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "bmp",
        "ico",
        "svg",
        "mp3",
        "mp4",
        "wav",
        "ogg",
        "flac",
        "avi",
        "mov",
        "mkv",
        "webm",
        "zip",
        "tar",
        "gz",
        "bz2",
        "xz",
        "7z",
        "rar",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "odp",
        "exe",
        "dll",
        "so",
        "dylib",
        "bin",
        "iso",
        "parquet",
        "orc",
        "avro",
        "feather",
        "pyc",
        "class",
        "o",
        "a",
    }
)


def _classify_text(path: str, config: dict) -> tuple[str, str | None]:
    """Classify a file path as text or binary using extension and basename rules.

    Returns (decision, ext) where decision is one of:
    'text:extension' | 'text:extensionless' | 'binary:known' | 'sniff'
    """
    basename = path.split("/")[-1].lower()
    ext = basename.rsplit(".", 1)[-1] if "." in basename else None
    if basename in EXTENSIONLESS_TEXT_BASENAMES:
        return "text:extensionless", None
    if ext is not None:
        custom = set(config.get("mcp_text_extensions", []))
        if ext in TEXT_EXTENSIONS_WHITELIST or ext in custom:
            return "text:extension", ext
        if ext in KNOWN_BINARY_EXTENSIONS:
            return "binary:known", ext
        if ext in UNKNOWN_OK_TO_SNIFF:
            return "sniff", ext
        # Other unknown extension — sniff
        return "sniff", ext
    return "sniff", None


def _is_likely_text_sample(sample: bytes) -> bool:
    """Return True if the sample bytes appear to be valid UTF-8 text.

    Rejects samples containing a NUL byte in the first 1KB (binary indicator).
    Handles partial multibyte sequences at the end of the sample.
    """
    if b"\x00" in sample[:1024]:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        # Sample may end in the middle of a multibyte sequence — try trimming.
        for cut in range(1, 4):
            try:
                sample[:-cut].decode("utf-8")
                return True
            except UnicodeDecodeError:
                continue
        return False


# ---------------------------------------------------------------------------
# FastMCP instance — must be created at module level (not inside a factory)
# so that lifespan handlers can reach mcp.session_manager. FastMCP's
# session_manager.run() context manager is the only way to initialize the
# task group it needs to handle requests; it must be entered during the
# Starlette/FastAPI lifespan event, not on demand at request time.
#
# See FastMCP.streamable_http_app docstring:
#     "Use this in the lifespan context manager of your Starlette app"
# ---------------------------------------------------------------------------

# streamable_http_path="/" so that mounting on FastAPI as app.mount("/mcp", …)
# produces the canonical /mcp endpoint instead of the awkward /mcp/mcp.
# (FastMCP's default streamable_http_path is "/mcp", which double-prefixes.)
mcp = FastMCP("another-s3-manager", streamable_http_path="/")


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
    except McpError as e:
        error_code = e.code
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
#
# Two modes:
#   recursive=False (default): one level deep, returns sub-directories as
#     {is_directory: true} entries. Use for browsing dir-by-dir.
#   recursive=True: flat list of all keys under `path`, paginated via
#     continuation_token. Use for counting/searching/processing whole subtrees
#     without N+1 calls. Returns up to max_keys (default 1000, max 10000) per
#     call; pass back next_continuation_token to get the next page.
# ------------------------------------------------------------------
@mcp.tool()
async def list_files(
    role: str,
    bucket: str,
    path: str = "",
    recursive: bool = False,
    max_keys: int = 1000,
    continuation_token: str | None = None,
) -> dict:
    """List files at a path within a bucket.

    Args:
        role: Role name (must be in user's allowed_roles).
        bucket: Bucket name (must be in role's allowed_buckets if configured).
        path: Prefix to scope the listing. "" = bucket root.
        recursive: If True, returns flat list of all keys under path with
            pagination. If False (default), one level deep with directory entries.
        max_keys: Max keys per call when recursive=True. Default 1000, max 10000.
        continuation_token: Pass back next_continuation_token from the previous
            recursive call to get the next page.

    Returns:
        Non-recursive: {"files": [{name, is_directory, size, last_modified?}, ...]}
        Recursive: {"files": [{key, size, last_modified}, ...],
                    "is_truncated": bool, "next_continuation_token": str|null,
                    "key_count": int}
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        try:
            if recursive:
                # Normalize path → S3 prefix (no leading slash; trailing slash
                # only if non-empty so we don't accidentally match other names).
                prefix = path.strip("/")
                if prefix:
                    prefix += "/"
                result = _s3_client.list_objects_recursive_for_role(
                    role, bucket, prefix, user, max_keys=max_keys, continuation_token=continuation_token
                )
            else:
                files = _s3_client.list_objects_for_role(role, bucket, path, user)
                result = {"files": files}
        except PermissionError as e:
            msg = str(e).lower()
            if "bucket" in msg:
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.list_files",
            extra={
                "user": user["username"],
                "role": role,
                "bucket": bucket,
                "path": path,
                "recursive": recursive,
                "count": len(result["files"]),
            },
        )
        return result
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
        try:
            content = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise McpError("INVALID_INPUT", f"content_base64 is not valid base64: {e}", {"tool": "upload_file"})
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


# ------------------------------------------------------------------
# read_file — download and return a text file from a bucket.
# Uses HEAD-first pipeline: size check → classification → download.
# AppFlow regression: S3 Content-Type metadata is IGNORED; classification
# is driven by extension whitelist and UTF-8 sniffing only.
# ------------------------------------------------------------------
@mcp.tool()
async def read_file(role: str, bucket: str, path: str, force_text: bool = False) -> dict:
    """Download and return a text file from a bucket.

    Performs HEAD first to avoid downloading large or binary files.
    Set force_text=True to skip detection and use errors='replace' decoding.
    """
    error_code = "none"
    start_t = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        effective_max = min(
            token.max_read_bytes,
            config.get("mcp_global_max_read_bytes", 10_485_760),
        )

        try:
            size = _s3_client.head_object_for_role(role, bucket, path, user)
        except FileNotFoundError:
            raise McpError("FILE_NOT_FOUND", "Object not found", {"bucket": bucket, "path": path})
        except PermissionError as e:
            if "bucket" in str(e).lower():
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})

        if size > effective_max:
            raise McpError(
                "FILE_TOO_LARGE",
                f"File size {size} exceeds limit {effective_max}",
                {"size": size, "max_read_bytes": effective_max},
            )

        ext: str | None = None
        if force_text:
            decision = "forced"
        else:
            kind, ext = _classify_text(path, config)
            if kind == "binary:known":
                raise McpError(
                    "BINARY_CONTENT",
                    f"File appears binary (size {size}, ext .{ext}). Use force_text=true if you know better.",
                    {"bucket": bucket, "path": path, "size": size, "ext": ext, "hint": "force_text=true"},
                )
            elif kind == "text:extension":
                decision = "extension"
            elif kind == "text:extensionless":
                decision = "extensionless"
            else:  # sniff
                sample = _s3_client.read_object_range_for_role(role, bucket, path, 0, 8191, user)
                if _is_likely_text_sample(sample):
                    decision = "sniffed"
                else:
                    raise McpError(
                        "BINARY_CONTENT",
                        f"File appears binary (size {size}). Use force_text=true if you know better.",
                        {"bucket": bucket, "path": path, "size": size, "ext": ext, "hint": "force_text=true"},
                    )

        raw = _s3_client.read_object_for_role(role, bucket, path, user)
        mcp_bytes_read_total.labels(bucket=bucket).inc(len(raw))

        # Strip UTF-8 BOM silently if present.
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]

        if force_text:
            content = raw.decode("utf-8", errors="replace")
        else:
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise McpError(
                    "BINARY_CONTENT",
                    f"File could not be decoded as UTF-8 (size {size}). Use force_text=true.",
                    {"bucket": bucket, "path": path, "size": size, "hint": "force_text=true"},
                )

        logger.info(
            "mcp.read_file",
            extra={
                "user": user["username"],
                "role": role,
                "bucket": bucket,
                "path": path,
                "size": size,
                "detection": decision,
            },
        )
        return {
            "content": content,
            "encoding": "utf-8",
            "size": size,
            "detection": decision,
            "bucket": bucket,
            "path": path,
        }
    except McpError as e:
        error_code = e.code
        raise
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.read_file.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="read_file", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="read_file").observe(time.perf_counter() - start_t)


# ---------------------------------------------------------------------------
# Module-level ASGI app — mounted on FastAPI at /mcp.
# Wrapping with _RequestCaptureMiddleware lets tool bodies pull the HTTP
# request out of contextvars to read the Authorization header.
# ---------------------------------------------------------------------------
mcp_asgi_app = _RequestCaptureMiddleware(mcp.streamable_http_app())


def get_mcp_app() -> Any:
    """Backwards-compatible accessor for the wrapped MCP ASGI app.

    Tests and main.py use this; tests can call it any number of times
    without creating a new FastMCP instance (which would re-register tools).
    """
    return mcp_asgi_app
