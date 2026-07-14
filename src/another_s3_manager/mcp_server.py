"""MCP server for another-s3-manager.

Mounted as a FastAPI sub-app at /mcp via Streamable HTTP transport.
All permission decisions delegate to s3_client.py — single source of truth.
"""

import base64
import binascii
import hashlib
import json
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.requests import Request

import another_s3_manager.config as _config_module
from another_s3_manager import api_tokens as token_svc
from another_s3_manager import s3_client as _s3_client
from another_s3_manager.errors import (
    CredentialsExpiredError,
    RoleNotFoundError,
    S3AccessDeniedError,
    S3ConfigError,
    S3NetworkError,
    S3NotFoundError,
    S3OperationError,
)
from another_s3_manager.metrics import (
    mcp_auth_failures_total,
    mcp_bytes_read_total,
    mcp_reads_refused_total,
    mcp_tool_calls_total,
    mcp_tool_duration_seconds,
    mcp_writes_denied_total,
    upload_rejected_total,
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
        """Render the error the way the agent actually receives it.

        FastMCP (mcp/server/fastmcp/tools/base.py, Tool.run) catches every
        exception raised from a tool body and wraps `str(e)` as an
        `isError: true` text result — `details` never reaches the client any
        other way. This used to mean useful, already-computed context (e.g.
        ROLE_NOT_ALLOWED's `allowed_roles`, or the `hint` pointing at
        presigned_url on BINARY_CONTENT/FILE_TOO_LARGE) was silently thrown
        away: the agent was told "no" and never told what "yes" looks like.

        Fold in only details that are both actionable (tell the agent what to
        do next) and safe (information the caller is already entitled to —
        `allowed_roles` is the caller's OWN role list, `hint` is static
        guidance text naming another tool). Everything else in `details`
        stays out of the message; it's either redundant with `message`
        already or not meant to leave the process. The "{code}: " prefix is
        always kept first so the machine-readable code stays trivially
        parseable out of the string.
        """
        suffix = []
        if "allowed_roles" in self.details:
            roles = self.details["allowed_roles"]
            roles_text = ", ".join(roles) if roles else "(none)"
            suffix.append(f"Roles you may use: {roles_text}.")
        hint = self.details.get("hint")
        if hint:
            suffix.append(str(hint))

        if not suffix:
            # Nothing to fold — leave the string byte-identical to the plain form.
            return f"{self.code}: {self.message}"

        # Terminate the message, or the sentences run together: "...not found in
        # configuration Roles you may use: ...". Only the message needs it; the
        # suffix parts already end in punctuation.
        message = self.message if self.message.rstrip().endswith((".", "!", "?", ":")) else f"{self.message}."
        return " ".join([f"{self.code}: {message}", *suffix])


# ---------------------------------------------------------------------------
# Write-gate
# ---------------------------------------------------------------------------

# Tools that perform write operations — used by assert_write_allowed.
WRITE_TOOLS = {"upload_file", "delete_file", "copy_object"}


def assert_write_allowed(token: Any, tool_name: str, config: dict) -> None:
    """Raise McpError if the given token/config combination disallows a write tool.

    Decision order (most authoritative first):
    1. Server-wide write disable (mcp_disable_writes in config).
    2. Per-token read-only flag.
    3. delete_file blocked when server-level deletion is disabled.
    """
    if config.get("mcp_disable_writes", False):
        mcp_writes_denied_total.labels(tool=tool_name, reason="writes_disabled").inc()
        raise McpError(
            "READ_ONLY_SERVER",
            "Server config disables MCP writes",
            {"tool": tool_name},
        )
    if token.is_read_only:
        mcp_writes_denied_total.labels(tool=tool_name, reason="read_only_token").inc()
        raise McpError(
            "READ_ONLY_TOKEN",
            "This token is read-only",
            {"tool": tool_name},
        )
    if tool_name == "delete_file" and config.get("disable_deletion", False):
        mcp_writes_denied_total.labels(tool=tool_name, reason="deletion_disabled").inc()
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

# Server-level orientation delivered once per connection via
# initialize.instructions. Single server-level string by design: a per-role
# variant was evaluated and rejected (MCP delivers instructions once per
# connection, so a multi-role user would only ever see one role's prompt).
MCP_SERVER_INSTRUCTIONS = """\
another-s3-manager: manage files in S3 and S3-compatible buckets.

Getting oriented: call list_roles first, then list_buckets(role), then
bucket_summary(role, bucket) to learn what a bucket contains — object counts,
sizes, per-prefix breakdown, extension histogram — in one compact call. Drill
into a subtree with bucket_summary(role, bucket, path="some/prefix/"). Only
then use list_files for actual keys and read_file for file contents.

list_files returns actual keys and both modes are bounded by max_keys: in
recursive mode, when is_truncated is true, pass next_continuation_token back
to fetch the next page; in non-recursive mode a truncated listing has no
continuation token — call bucket_summary or retry with recursive=True.

The application's REST API requires a browser session cookie for /api/... routes;
your MCP Bearer token (as3m_...) is not a JWT and will be rejected there. Use /mcp
tools instead. Do not attempt REST calls with the MCP token.
"""

# streamable_http_path="/" so that mounting on FastAPI as app.mount("/mcp", …)
# produces the canonical /mcp endpoint instead of the awkward /mcp/mcp.
# (FastMCP's default streamable_http_path is "/mcp", which double-prefixes.)
mcp = FastMCP("another-s3-manager", instructions=MCP_SERVER_INSTRUCTIONS, streamable_http_path="/")


def _observe_response_size(tool: str, token: Any, payload: dict) -> dict:
    """Record the JSON size of a tool's response payload as a Histogram sample.

    Pass-through helper: returns `payload` unchanged so callers can `return
    _observe_response_size(...)`. The serialization here is best-effort —
    if json.dumps raises, we skip the observation rather than failing the call.

    The bytes count is a proxy for the LLM-input-token cost the agent will pay
    when it reinjects this result into its next prompt (≈4 bytes / token for
    English text). Labeled by tool only — see metrics.mcp_tool_response_bytes
    for the cardinality reasoning. The `token` argument is kept in the
    signature for future log-emit use (token id is already logged via
    logger.info("mcp.<tool>", extra={"user": ...}) in each tool body).
    """
    del token  # unused — see docstring
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return payload
    from another_s3_manager.metrics import mcp_tool_response_bytes

    mcp_tool_response_bytes.labels(tool=tool).observe(size)
    return payload


# ------------------------------------------------------------------
# list_roles — returns the intersection of user's allowed_roles and
# role names defined in config (only what actually exists).
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def list_roles() -> dict:
    """List role names accessible to the authenticated user.

    Call this FIRST — every other tool needs a role name, and this is how you learn which ones you have.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        all_role_names = {r["name"] for r in config.get("roles", [])}
        visible = [r for r in user["allowed_roles"] if r in all_role_names]
        logger.info("mcp.list_roles", extra={"user": user["username"], "count": len(visible)})
        return _observe_response_size("list_roles", token, {"roles": visible})
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.list_roles.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.list_roles.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.list_roles.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.list_roles.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.list_roles.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.list_roles.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
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
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def list_buckets(role: str) -> dict:
    """List buckets accessible via the given role.

    Call this right after list_roles, before touching files — every other tool needs a bucket name too.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        try:
            buckets = _s3_client.list_buckets_for_role(role, user)
        except (PermissionError, RoleNotFoundError) as e:
            raise McpError(
                "ROLE_NOT_ALLOWED",
                str(e),
                {"role": role, "allowed_roles": user["allowed_roles"]},
            )
        logger.info("mcp.list_buckets", extra={"user": user["username"], "role": role, "count": len(buckets)})
        return _observe_response_size("list_buckets", token, {"buckets": buckets})
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.list_buckets.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.list_buckets.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.list_buckets.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.list_buckets.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.list_buckets.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.list_buckets.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
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
# Two modes, BOTH bounded by the same config-driven max_keys (2026-07-13:
# the non-recursive branch used to be unbounded — a flat bucket with
# thousands of loose keys at one level was the exact firehose this feature
# exists to prevent, reachable with zero optional arguments):
#   recursive=False (default): one level deep, returns sub-directories as
#     {is_directory: true} entries. Use for browsing dir-by-dir. A listing
#     longer than the effective cap is truncated with is_truncated/hint —
#     there is no continuation token for this mode (see the hint text).
#   recursive=True: flat list of all keys under `path`, paginated via
#     continuation_token. Use for counting/searching/processing whole subtrees
#     without N+1 calls. Returns up to max_keys (config-driven default
#     mcp_list_page_size, ceiling mcp_list_max_page_size) per call; pass back
#     next_continuation_token to get the next page.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def list_files(
    role: str,
    bucket: str,
    path: str = "",
    recursive: bool = False,
    max_keys: int | None = None,
    continuation_token: str | None = None,
) -> dict:
    """List files at a path within a bucket. Returns ACTUAL KEYS — to learn
    what a bucket contains (counts, sizes, prefix breakdown), call
    bucket_summary instead: one compact call, no paging.

    Args:
        role: Role name (must be in user's allowed_roles).
        bucket: Bucket name (must be in role's allowed_buckets if configured).
        path: Prefix to scope the listing. "" = bucket root.
        recursive: If True, returns a flat list of all keys under path with
            pagination. If False (default), one level deep with directory entries.
        max_keys: Max entries per call, in EITHER mode. Defaults to the
            server-configured page size (mcp_list_page_size, normally 1000);
            values above the server ceiling (mcp_list_max_page_size) are
            clamped, not rejected.
        continuation_token: Pass back next_continuation_token from the previous
            recursive call to get the next page. Not applicable when
            recursive=False — a truncated non-recursive listing has no
            continuation token (see is_truncated/hint below).

    Returns:
        Non-recursive: {"files": [{name, is_directory, size, last_modified?}, ...],
                         "is_truncated"?: true, "hint"?: str}
            is_truncated/hint are present ONLY when the listing was cut —
            absent, not null/false, on a short listing.
        Recursive: {"files": [{key, size, last_modified}, ...],
                    "is_truncated": bool, "next_continuation_token": str|null,
                    "key_count": int, "hint"?: str}
            is_truncated is always present here; "hint" is present only when
            is_truncated is true.
        A recursive page can be LARGE (~160 KB at 1000 keys). When
        is_truncated is true, pass next_continuation_token back to continue
        paging — or use bucket_summary for the shape of the bucket in one call.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        try:
            config = _config_module.load_config(force_reload=False)
            # Resolution rules (2026-07-12 design, extended 2026-07-13 to
            # bound the non-recursive branch too — see the module comment
            # above): floors of 1 on both keys; the ceiling wins over the
            # default page size; an agent-supplied max_keys is clamped to
            # the ceiling, never rejected. Per-S3-request MaxKeys stays
            # min(effective, 1000) inside the recursive helper — S3's own
            # limit, not configurable.
            page_size = max(1, int(config.get("mcp_list_page_size", 1000)))
            ceiling = max(1, int(config.get("mcp_list_max_page_size", 10_000)))
            # Floor of 1 on the RESULT too, not just the two config inputs: an
            # agent-supplied max_keys=0 (or negative) must not collapse the
            # non-recursive branch to an empty, "is_truncated" response — the
            # recursive helper already re-floors internally
            # (list_objects_recursive_for_role: max(1, min(...))), so this
            # keeps both modes consistent instead of only fixing one.
            effective_max_keys = max(1, min(max_keys if max_keys is not None else page_size, ceiling))
            if recursive:
                # Normalize path → S3 prefix (no leading slash; trailing slash
                # only if non-empty so we don't accidentally match other names).
                prefix = path.strip("/")
                if prefix:
                    prefix += "/"
                result = _s3_client.list_objects_recursive_for_role(
                    role,
                    bucket,
                    prefix,
                    user,
                    max_keys=effective_max_keys,
                    continuation_token=continuation_token,
                    max_page_size=ceiling,
                )
                if result.get("is_truncated"):
                    # Redirect at the exact moment the recorded incident went
                    # off the rails. Only on truncated recursive pages — the
                    # field is absent (not null) otherwise.
                    result["hint"] = (
                        "This is the first page of a larger listing. Pass "
                        "next_continuation_token to page through keys, or call "
                        "bucket_summary(role, bucket, path) to get counts, sizes "
                        "and the prefix breakdown in one compact call."
                    )
            else:
                # s3_client.list_objects_for_role still walks the WHOLE level
                # (unchanged — the web UI relies on that helper too); what we
                # bound here is the AGENT'S CONTEXT, i.e. what this tool
                # returns. No continuation token exists for a non-recursive
                # listing, so we do not invent one — the hint below points at
                # the two real alternatives instead.
                files = _s3_client.list_objects_for_role(role, bucket, path, user)
                result = {"files": files}
                if len(files) > effective_max_keys:
                    result["files"] = files[:effective_max_keys]
                    result["is_truncated"] = True
                    result["hint"] = (
                        f"This directory listing was cut at {effective_max_keys} entries. "
                        "There is no continuation token for a non-recursive listing — call "
                        "bucket_summary(role, bucket, path) for counts and the prefix "
                        "breakdown, or list_files(..., recursive=True) to page through "
                        "every key."
                    )
        except (PermissionError, RoleNotFoundError) as e:
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
        return _observe_response_size("list_files", token, result)
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.list_files.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.list_files.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.list_files.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.list_files.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.list_files.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.list_files.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.list_files.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="list_files", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="list_files").observe(time.perf_counter() - start)


# ------------------------------------------------------------------
# bucket_summary — one-call compact digest of a bucket / prefix.
# Read-only; the remedy for the "list_files firehose" failure mode.
# All S3 work and permission checks live in
# s3_client.summarize_bucket_for_role — this stays a thin wrapper.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def bucket_summary(role: str, bucket: str, path: str = "") -> dict:
    """Summarize what's in a bucket (or under a prefix) in ONE compact call:
    object count, total size, per-prefix breakdown, extension histogram,
    largest objects, modified range. Use this FIRST when asked what a bucket
    contains — do not page through list_files. Drill down by passing path.
    Reported "ext" values are capped at 16 characters.

    IMPORTANT — when the bucket exceeds the scan cap, `complete` is false and
    a `note` field explains that root_objects, extensions, largest_objects
    and the oldest/newest_modified range cover ONLY the scanned range (keys
    up to `scan_stopped_at`, in S3's lexicographic order) and can
    UNDER-REPORT: a prefix alone larger than the cap can hide a loose object
    at the bucket root, or the single largest object in the whole bucket, if
    either happens to sort later. Only total_objects/total_bytes (nulled)
    and each prefix's own `coverage` (complete/partial/not_scanned) are safe
    to treat as exact on a partial scan — everything else in the response is
    a lower bound, not a total. Narrow with `path` or raise
    mcp_summary_max_keys for a trustworthy full-bucket answer.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        max_keys = int(config.get("mcp_summary_max_keys", 50_000))
        prefix_scan_pages = int(config.get("mcp_summary_prefix_scan_pages", 20))
        # Normalize path → S3 prefix, exactly like list_files recursive mode.
        prefix = path.strip("/")
        if prefix:
            prefix += "/"
        try:
            result = _s3_client.summarize_bucket_for_role(
                role, bucket, prefix, user, max_keys=max_keys, prefix_scan_pages=prefix_scan_pages
            )
        except (PermissionError, RoleNotFoundError) as e:
            msg = str(e).lower()
            if "bucket" in msg:
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.bucket_summary",
            extra={
                "user": user["username"],
                "role": role,
                "bucket": bucket,
                "path": path,
                "scanned_objects": result["scanned_objects"],
                "complete": result["complete"],
            },
        )
        return _observe_response_size("bucket_summary", token, result)
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.bucket_summary.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.bucket_summary.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.bucket_summary.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.bucket_summary.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.bucket_summary.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.bucket_summary.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.bucket_summary.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="bucket_summary", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="bucket_summary").observe(time.perf_counter() - start)


def _estimate_base64_decoded_size(content_base64: str) -> int:
    """Estimate the decoded byte size of a base64 string WITHOUT decoding it.

    Base64 encodes 3 raw bytes as 4 characters, padded with '=' at the end so
    the encoded length is always a multiple of 4. This inverts that: strip up
    to two trailing '=' padding characters from the count, then convert the
    remaining character count back to bytes. Deliberately approximate (it
    does not validate the string is well-formed base64 — that check still
    happens in b64decode afterward) — its only job is to reject an oversized
    payload BEFORE paying for the full decode.

    Padding is capped at 2 characters by construction (only the last two
    characters of the string are ever inspected for '='): legitimate base64
    padding is never more than two '=' characters, so a malformed string with
    a longer run of '=' must not be allowed to inflate `padding` past 2 — that
    would make the estimate go negative and sail past the size check below
    without ever exercising it. A malformed tail instead makes the estimate
    LARGER than the true decoded size (safe: more likely to reject, never to
    under-count), and b64decode(validate=True) still rejects the malformed
    input afterward regardless. The estimate is also clamped at 0 as a second,
    independent guard against ever returning a negative value.
    """
    length = len(content_base64)
    tail = content_base64[-2:]
    padding = len(tail) - len(tail.rstrip("="))
    estimate = (length * 3 // 4) - padding
    return max(estimate, 0)


# ------------------------------------------------------------------
# upload_file — upload a file to a bucket. Content as base64.
# WRITE TOOL: gated by assert_write_allowed.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
async def upload_file(role: str, bucket: str, path: str, content_base64: str) -> dict:
    """Upload a file to a bucket (WRITE operation — creates or overwrites the
    object at `path`). Content must be base64-encoded. Blocked for read-only
    tokens and when the server disables MCP writes. Rejected with
    FILE_TOO_LARGE before decoding if the payload exceeds the server's
    max_file_size limit."""
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        assert_write_allowed(token, "upload_file", config)

        # Layer 2 (defense in depth): reject an oversized upload BEFORE
        # b64decode ever runs — the real transport-level bound lives in
        # main.py's _mcp_body_guard middleware (Layer 1), which rejects the
        # request before its body is even read off the socket. This check
        # exists for the cases the middleware ceiling deliberately allows
        # through (its ceiling has JSON-envelope headroom baked in) and,
        # more importantly, gives the AGENT an actionable error instead of a
        # transport-level rejection it cannot interpret.
        # Shared with main.py's web-upload guard/route (config.py's single
        # implementation, passed the already-loaded config to avoid a
        # redundant load_config call) — see config.resolve_max_file_size's
        # docstring for why this used to be a hand-copy and isn't anymore.
        max_file_size = _config_module.resolve_max_file_size(config)
        estimated_size = _estimate_base64_decoded_size(content_base64)
        if estimated_size > max_file_size:
            upload_rejected_total.labels(reason="size_limit").inc()
            raise McpError(
                "FILE_TOO_LARGE",
                f"Upload of ~{estimated_size} bytes exceeds the server's max_file_size limit of {max_file_size}",
                {
                    "estimated_size": estimated_size,
                    "max_file_size": max_file_size,
                    "hint": "Reduce the file size, or ask the operator to raise max_file_size.",
                },
            )

        try:
            content = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise McpError("INVALID_INPUT", f"content_base64 is not valid base64: {e}", {"tool": "upload_file"})
        try:
            _s3_client.put_object_for_role(role, bucket, path, content, user)
        except (PermissionError, RoleNotFoundError) as e:
            msg = str(e).lower()
            if "bucket" in msg:
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.upload_file",
            extra={"user": user["username"], "role": role, "bucket": bucket, "path": path, "size": len(content)},
        )
        return _observe_response_size(
            "upload_file", token, {"ok": True, "bucket": bucket, "path": path, "size": len(content)}
        )
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.upload_file.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.upload_file.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.upload_file.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.upload_file.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.upload_file.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.upload_file.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
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
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
async def delete_file(role: str, bucket: str, path: str) -> dict:
    """Delete a file from a bucket (WRITE / DESTRUCTIVE operation — the object is
    permanently removed; a `path` ending in "/" deletes the whole folder
    recursively). Blocked for read-only tokens, when the server disables MCP
    writes, and when deletion is disabled server-wide.

    Args:
        role: Role name (must be in user's allowed_roles).
        bucket: Bucket name (must be in role's allowed_buckets if configured).
        path: Full S3 key to delete — exactly that object, nothing else. A
            trailing "/" changes this into a RECURSIVE FOLDER DELETE: every
            object nested under that prefix is removed. Omit the trailing
            slash unless a whole folder is genuinely meant to be wiped.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        assert_write_allowed(token, "delete_file", config)
        try:
            _s3_client.delete_object_for_role(role, bucket, path, user)
        except FileNotFoundError:
            raise McpError("FILE_NOT_FOUND", "Object not found", {"bucket": bucket, "path": path})
        except (PermissionError, RoleNotFoundError) as e:
            msg = str(e).lower()
            if "bucket" in msg:
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.delete_file",
            extra={"user": user["username"], "role": role, "bucket": bucket, "path": path},
        )
        return _observe_response_size("delete_file", token, {"ok": True, "bucket": bucket, "path": path})
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.delete_file.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.delete_file.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.delete_file.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.delete_file.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.delete_file.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.delete_file.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
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
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def read_file(role: str, bucket: str, path: str, force_text: bool = False) -> dict:
    """Download a text file's FULL CONTENTS into your context. Call this only when you actually need to
    read/quote/analyze what's inside a specific, already-known-text file.

    Do NOT call this to check whether a file exists, how big it is, or what
    type it is — that's get_object_metadata (no download, cheap, use it
    first if you're unsure). Do NOT call this for binary files (images,
    archives, PDFs, executables, media) or for a file you intend to hand to
    a user rather than read yourself — that's presigned_url, a link instead
    of bytes through your context.

    Performs HEAD first so oversized or binary files are refused before
    download: FILE_TOO_LARGE and BINARY_CONTENT errors both name
    presigned_url as the alternative. Set force_text=True to skip binary
    detection and decode with errors='replace' (undecodable bytes become the
    UTF-8 replacement character).
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
        except (PermissionError, RoleNotFoundError) as e:
            if "bucket" in str(e).lower():
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})

        if size > effective_max:
            mcp_reads_refused_total.labels(tool="read_file", reason="file_too_large").inc()
            raise McpError(
                "FILE_TOO_LARGE",
                f"File size {size} exceeds limit {effective_max}",
                {
                    "size": size,
                    "max_read_bytes": effective_max,
                    "hint": (
                        "Use the presigned_url tool for a download link instead, "
                        "or request a token with a higher max_read_bytes."
                    ),
                },
            )

        ext: str | None = None
        if force_text:
            decision = "forced"
        else:
            kind, ext = _classify_text(path, config)
            if kind == "binary:known":
                mcp_reads_refused_total.labels(tool="read_file", reason="binary_content").inc()
                raise McpError(
                    "BINARY_CONTENT",
                    f"File appears binary (size {size}, ext .{ext}). Use force_text=true if you know better.",
                    {
                        "bucket": bucket,
                        "path": path,
                        "size": size,
                        "ext": ext,
                        "hint": "Use force_text=true to decode anyway, or the presigned_url tool for a download link",
                    },
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
                    mcp_reads_refused_total.labels(tool="read_file", reason="binary_content").inc()
                    raise McpError(
                        "BINARY_CONTENT",
                        f"File appears binary (size {size}). Use force_text=true if you know better.",
                        {
                            "bucket": bucket,
                            "path": path,
                            "size": size,
                            "ext": ext,
                            "hint": "Use force_text=true to decode anyway, or the presigned_url tool for a download link",
                        },
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
                mcp_reads_refused_total.labels(tool="read_file", reason="binary_content").inc()
                raise McpError(
                    "BINARY_CONTENT",
                    f"File could not be decoded as UTF-8 (size {size}). Use force_text=true.",
                    {
                        "bucket": bucket,
                        "path": path,
                        "size": size,
                        "hint": "Use force_text=true to decode anyway, or the presigned_url tool for a download link",
                    },
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
        return _observe_response_size(
            "read_file",
            token,
            {
                "content": content,
                "encoding": "utf-8",
                "size": size,
                "detection": decision,
                "bucket": bucket,
                "path": path,
            },
        )
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.read_file.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.read_file.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.read_file.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.read_file.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.read_file.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        # Unknown S3 subclass — still better than INTERNAL_ERROR.
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.read_file.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.read_file.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="read_file", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="read_file").observe(time.perf_counter() - start_t)


# ------------------------------------------------------------------
# copy_object — server-side copy (optionally move/rename) within a role.
# WRITE TOOL: gated by assert_write_allowed; delete_source also needs deletion.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
async def copy_object(
    role: str,
    source_bucket: str,
    source_path: str,
    dest_bucket: str,
    dest_path: str,
    delete_source: bool = False,
) -> dict:
    """Copy an object to a new location (WRITE operation — overwrites the
    object at `dest_path` if one already exists; there is no existence
    check first).

    Server-side copy within one role's credentials — source and destination
    buckets must both be accessible to `role`. Set delete_source=true to MOVE
    (or rename) instead of copy: the source is deleted after a successful copy,
    which additionally requires deletion to be enabled server-wide. Blocked for
    read-only tokens and when the server disables MCP writes.
    """
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        assert_write_allowed(token, "copy_object", config)
        if delete_source and config.get("disable_deletion", False):
            # This guard lives outside assert_write_allowed (it's conditional on
            # delete_source, not just the tool name), but it's still a write
            # denial for the same reason and must be counted identically.
            mcp_writes_denied_total.labels(tool="copy_object", reason="deletion_disabled").inc()
            raise McpError(
                "DELETION_DISABLED",
                "Deletion is disabled in server config (delete_source requires it)",
                {"tool": "copy_object"},
            )
        try:
            _s3_client.copy_object_for_role(role, source_bucket, source_path, dest_bucket, dest_path, user)
            if delete_source:
                _s3_client.delete_object_for_role(role, source_bucket, source_path, user)
        except FileNotFoundError as e:
            raise McpError("FILE_NOT_FOUND", str(e), {"bucket": source_bucket, "path": source_path})
        except (PermissionError, RoleNotFoundError) as e:
            if "bucket" in str(e).lower():
                raise McpError(
                    "BUCKET_NOT_ALLOWED",
                    str(e),
                    {"source_bucket": source_bucket, "dest_bucket": dest_bucket},
                )
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.copy_object",
            extra={
                "user": user["username"],
                "role": role,
                "source_bucket": source_bucket,
                "source_path": source_path,
                "dest_bucket": dest_bucket,
                "dest_path": dest_path,
                "moved": delete_source,
            },
        )
        return _observe_response_size(
            "copy_object",
            token,
            {
                "ok": True,
                "source_bucket": source_bucket,
                "source_path": source_path,
                "dest_bucket": dest_bucket,
                "dest_path": dest_path,
                "moved": delete_source,
            },
        )
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.copy_object.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.copy_object.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.copy_object.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.copy_object.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.copy_object.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.copy_object.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.copy_object.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="copy_object", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="copy_object").observe(time.perf_counter() - start)


# ------------------------------------------------------------------
# get_object_metadata — HEAD an object; no download. Read-only.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def get_object_metadata(role: str, bucket: str, path: str) -> dict:
    """Return object metadata (size, last_modified, content_type, etag) without
    downloading it. Read-only — useful to inspect a file before read_file or
    before handing out a presigned_url."""
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        try:
            meta = _s3_client.get_object_metadata_for_role(role, bucket, path, user)
        except FileNotFoundError:
            raise McpError("FILE_NOT_FOUND", "Object not found", {"bucket": bucket, "path": path})
        except (PermissionError, RoleNotFoundError) as e:
            if "bucket" in str(e).lower():
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        logger.info(
            "mcp.get_object_metadata",
            extra={"user": user["username"], "role": role, "bucket": bucket, "path": path},
        )
        return _observe_response_size("get_object_metadata", token, {"bucket": bucket, "path": path, **meta})
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.get_object_metadata.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.get_object_metadata.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.get_object_metadata.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.get_object_metadata.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.get_object_metadata.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.get_object_metadata.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.get_object_metadata.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="get_object_metadata", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="get_object_metadata").observe(time.perf_counter() - start)


# ------------------------------------------------------------------
# presigned_url — time-limited GET URL for an object. Read-only.
# ------------------------------------------------------------------
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def presigned_url(role: str, bucket: str, path: str, expires_in: int = 3600) -> dict:
    """Generate a time-limited download URL for an object (read-only).

    Anyone holding the URL can fetch the object until it expires — hand it to a
    user instead of returning raw file bytes (works for binary files too).
    `expires_in` (seconds) is clamped to [60, presigned_url_max_ttl] from server
    config (default max 7 days)."""
    error_code = "none"
    start = time.perf_counter()
    try:
        token, user = await authenticate_mcp_request(_get_current_request())
        config = _config_module.load_config(force_reload=False)
        max_ttl = int(config.get("presigned_url_max_ttl", 604800))
        clamped = max(60, min(int(expires_in), max_ttl))
        try:
            url = _s3_client.generate_presigned_url_for_role(role, bucket, path, user, expires_in=clamped)
        except (PermissionError, RoleNotFoundError) as e:
            if "bucket" in str(e).lower():
                raise McpError("BUCKET_NOT_ALLOWED", str(e), {"bucket": bucket})
            raise McpError("ROLE_NOT_ALLOWED", str(e), {"role": role, "allowed_roles": user["allowed_roles"]})
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=clamped)).isoformat()
        logger.info(
            "mcp.presigned_url",
            extra={"user": user["username"], "role": role, "bucket": bucket, "path": path, "expires_in": clamped},
        )
        return _observe_response_size(
            "presigned_url",
            token,
            {"url": url, "expires_in": clamped, "expires_at": expires_at, "bucket": bucket, "path": path},
        )
    except McpError as e:
        error_code = e.code
        raise
    except S3AccessDeniedError as e:
        error_code = "S3_ACCESS_DENIED"
        logger.warning("mcp.presigned_url.access_denied", extra={"boto_code": e.code})
        raise McpError("S3_ACCESS_DENIED", str(e), {"boto_code": e.code})
    except S3NotFoundError as e:
        error_code = "S3_NOT_FOUND"
        logger.warning("mcp.presigned_url.not_found", extra={"boto_code": e.code})
        raise McpError("S3_NOT_FOUND", str(e), {"boto_code": e.code})
    except S3ConfigError as e:
        error_code = "S3_CONFIG_ERROR"
        logger.warning("mcp.presigned_url.config_error", extra={"boto_code": e.code})
        raise McpError("S3_CONFIG_ERROR", str(e), {"boto_code": e.code})
    except S3NetworkError as e:
        error_code = "S3_NETWORK_ERROR"
        logger.warning("mcp.presigned_url.network_error", extra={"boto_code": e.code})
        raise McpError("S3_NETWORK_ERROR", str(e), {"boto_code": e.code})
    except CredentialsExpiredError as e:
        error_code = "CREDENTIALS_EXPIRED"
        logger.warning("mcp.presigned_url.credentials_expired", extra={"boto_code": e.code})
        raise McpError("CREDENTIALS_EXPIRED", str(e), {"boto_code": e.code})
    except S3OperationError as e:
        error_code = "S3_OPERATION_ERROR"
        logger.warning("mcp.presigned_url.s3_operation_error", extra={"boto_code": e.code})
        raise McpError("S3_OPERATION_ERROR", str(e), {"boto_code": e.code})
    except Exception:
        error_code = "INTERNAL_ERROR"
        logger.exception("mcp.presigned_url.error")
        raise McpError("INTERNAL_ERROR", "Internal server error")
    finally:
        mcp_tool_calls_total.labels(tool="presigned_url", error_code=error_code).inc()
        mcp_tool_duration_seconds.labels(tool="presigned_url").observe(time.perf_counter() - start)


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
