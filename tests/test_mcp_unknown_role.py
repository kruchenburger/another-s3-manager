"""An unknown role must be actionable for the agent — even for an admin token.

Found by a live smoke, not by the suite. validate_role_access() short-circuits
for admins ("admins have access to all roles"), so an admin asking for a role
that does not exist in config is NOT rejected there. It used to surface later as
a bare ValueError out of get_s3_client(), which the tools' exception ladder
swallowed into "INTERNAL_ERROR: Internal server error" — the agent learned
nothing, and a routine "no such role" was counted as a server fault in
mcp_tool_calls_total. A non-admin asking the exact same thing got a proper
ROLE_NOT_ALLOWED naming the roles it may use. The answer depended on who asked.

RoleNotFoundError (a ValueError subclass, named explicitly by the MCP handlers)
makes both paths agree. It stays a ValueError so the web routes, which map
ValueError -> HTTP 400 for a dozen unrelated config faults, are untouched.
"""

from unittest.mock import patch

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.errors import RoleNotFoundError
from another_s3_manager.mcp_server import McpError, _current_request
from another_s3_manager.models import User, UserRole


class _FakeRequest:
    def __init__(self, headers: dict):
        self.headers = headers


def _fake_request(plaintext: str) -> _FakeRequest:
    return _FakeRequest({"authorization": f"Bearer {plaintext}"})


@pytest.fixture(scope="module")
def tool_registry():
    from another_s3_manager.mcp_server import mcp

    return {tool.name: tool.fn for tool in mcp._tool_manager._tools.values()}


async def _call(tool_registry, name, request, **kwargs):
    token = _current_request.set(request)
    try:
        return await tool_registry[name](**kwargs)
    finally:
        _current_request.reset(token)


@pytest.fixture
def admin_user():
    """An ADMIN token — the case the smoke exposed. Admins bypass the role check."""
    with session_scope() as session:
        user = User(username="root_unknown_role", password_hash="x", is_admin=True)
        session.add(user)
        session.flush()
        uid = user.id
    _, plaintext = svc.create_token(uid, "unknown-role-admin", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


@pytest.fixture
def plain_user():
    with session_scope() as session:
        user = User(username="alice_unknown_role", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_name="Default"))
        session.flush()
        uid = user.id
    _, plaintext = svc.create_token(uid, "unknown-role-plain", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


def test_role_not_found_is_still_a_value_error():
    """Load-bearing: the web routes catch ValueError -> HTTP 400 for config
    faults. Narrowing the bases would silently turn those 400s into something
    else (their `except PermissionError` clause is listed FIRST)."""
    assert issubclass(RoleNotFoundError, ValueError)
    assert not issubclass(RoleNotFoundError, PermissionError)


@pytest.mark.asyncio
async def test_admin_unknown_role_is_actionable_not_internal_error(admin_user, tool_registry):
    """THE regression this file exists for: an admin must be told which roles
    exist, not handed an opaque INTERNAL_ERROR."""
    uid, plaintext = admin_user
    with patch(
        "another_s3_manager.s3_client.list_buckets_for_role",
        side_effect=RoleNotFoundError("Role 'Backup' not found in configuration"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "list_buckets", _fake_request(plaintext), role="Backup")

    err = exc_info.value
    assert err.code == "ROLE_NOT_ALLOWED", f"admin got {err.code} — the agent is back to a dead end"
    assert err.code != "INTERNAL_ERROR"
    # The whole point: the text the agent receives must name the way forward.
    assert "Roles you may use:" in str(err)


@pytest.mark.asyncio
async def test_unknown_role_reaches_the_agent_on_bucket_summary(admin_user, tool_registry):
    """The ladder is copied across all 10 tools — pin a second one so a partial
    fix cannot pass."""
    uid, plaintext = admin_user
    with patch(
        "another_s3_manager.s3_client.summarize_bucket_for_role",
        side_effect=RoleNotFoundError("Role 'Backup' not found in configuration"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Backup", bucket="b")

    assert exc_info.value.code == "ROLE_NOT_ALLOWED"
    assert "Roles you may use:" in str(exc_info.value)


@pytest.mark.asyncio
async def test_non_admin_unknown_role_still_role_not_allowed(plain_user, tool_registry):
    """The pre-existing non-admin path (PermissionError from validate_role_access)
    must keep working — the fix widened the handler, it must not have replaced it."""
    uid, plaintext = plain_user
    with patch(
        "another_s3_manager.s3_client.list_buckets_for_role",
        side_effect=PermissionError("Access denied: You don't have permission to use role 'Backup'"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "list_buckets", _fake_request(plaintext), role="Backup")

    assert exc_info.value.code == "ROLE_NOT_ALLOWED"
    assert "Roles you may use:" in str(exc_info.value)
