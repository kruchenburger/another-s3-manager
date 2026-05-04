"""MCP server for another-s3-manager.

Mounted as a FastAPI sub-app at /mcp via Streamable HTTP transport.
All permission decisions delegate to s3_client.py — single source of truth.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from another_s3_manager import api_tokens as token_svc
from another_s3_manager.metrics import (
    mcp_auth_failures_total,
    mcp_tool_calls_total,  # noqa: F401 — imported for tools in Task 12-13
    mcp_tool_duration_seconds,  # noqa: F401 — imported for tools in Task 12-13
)

logger = logging.getLogger(__name__)


@dataclass
class McpError(Exception):
    code: str
    message: str
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def to_payload(self) -> dict:
        return {"error": self.code, "message": self.message, "details": self.details}


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


def get_mcp_app():
    """Return the ASGI app for the MCP sub-app, mountable on FastAPI at /mcp.

    Uses FastMCP (MCP SDK 1.12.4) which handles Streamable HTTP transport,
    tool registration, and dispatch internally via @mcp.tool() decorators.
    Real tools (list_roles, list_buckets, …) are added in Tasks 12-13.
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("another-s3-manager")

    # Placeholder tool — verifies that MCP is mounted and reachable.
    # Replaced/supplemented by real tools in Task 12-13.
    @mcp.tool()
    async def ping() -> str:
        """Health check — verifies MCP is mounted and reachable."""
        return "pong"

    return mcp.streamable_http_app()
