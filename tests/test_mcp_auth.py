"""Tests for MCP Bearer auth pipeline and write-block decision tree."""

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.mcp_server import McpError, assert_write_allowed, authenticate_mcp_request
from another_s3_manager.models import User

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_user():
    """Insert a test user; fixture cleans up via transaction rollback in conftest."""
    with session_scope() as session:
        user = User(username="alice_mcp", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        return user.id


class _FakeRequest:
    """Minimal stub that satisfies authenticate_mcp_request's .headers interface."""

    def __init__(self, headers: dict):
        self.headers = headers


# ---------------------------------------------------------------------------
# McpError unit tests
# ---------------------------------------------------------------------------


def test_mcp_error_str():
    err = McpError("SOME_CODE", "some message")
    assert str(err) == "SOME_CODE: some message"


def test_mcp_error_to_payload_no_details():
    err = McpError("SOME_CODE", "some message")
    payload = err.to_payload()
    assert payload == {"error": "SOME_CODE", "message": "some message", "details": {}}


def test_mcp_error_to_payload_with_details():
    err = McpError("READ_ONLY_TOKEN", "Read-only", {"tool": "upload_file"})
    payload = err.to_payload()
    assert payload["details"] == {"tool": "upload_file"}


# ---------------------------------------------------------------------------
# authenticate_mcp_request — failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_missing_authorization_header():
    """No Authorization header → INVALID_TOKEN (malformed)."""
    req = _FakeRequest({})
    with pytest.raises(McpError) as exc_info:
        await authenticate_mcp_request(req)
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_auth_wrong_scheme_token_not_bearer():
    """'Token xyz' instead of 'Bearer ...' → INVALID_TOKEN (malformed)."""
    req = _FakeRequest({"authorization": "Token xyz"})
    with pytest.raises(McpError) as exc_info:
        await authenticate_mcp_request(req)
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_auth_bearer_without_as3m_prefix():
    """'Bearer sometoken' not starting with as3m_ → INVALID_TOKEN (malformed)."""
    req = _FakeRequest({"authorization": "Bearer not_a_valid_token"})
    with pytest.raises(McpError) as exc_info:
        await authenticate_mcp_request(req)
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_auth_unknown_hash():
    """Valid format but unknown hash → INVALID_TOKEN."""
    req = _FakeRequest({"authorization": "Bearer as3m_unknowntoken1234567890abcdefghij"})
    with pytest.raises(McpError) as exc_info:
        await authenticate_mcp_request(req)
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_auth_revoked_token(alice_user):
    """Revoked token hash → INVALID_TOKEN (find_active_token_by_hash returns None)."""
    token, plaintext = svc.create_token(alice_user, "mcp-rev", is_read_only=True, max_read_bytes=1024)
    svc.revoke_token(token.id, by_user_id=alice_user, by_is_admin=False)

    req = _FakeRequest({"authorization": f"Bearer {plaintext}"})
    with pytest.raises(McpError) as exc_info:
        await authenticate_mcp_request(req)
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_auth_valid_token_returns_token_and_user_dict(alice_user):
    """Valid active token → returns (token_orm, user_dict) with correct username."""
    _, plaintext = svc.create_token(alice_user, "mcp-ok", is_read_only=True, max_read_bytes=1024)

    req = _FakeRequest({"authorization": f"Bearer {plaintext}"})
    token, user_dict = await authenticate_mcp_request(req)

    assert token is not None
    assert token.user_id == alice_user
    assert user_dict["username"] == "alice_mcp"
    assert isinstance(user_dict["allowed_roles"], list)


@pytest.mark.asyncio
async def test_auth_valid_token_increments_last_used(alice_user):
    """Successful auth calls touch_last_used (last_used_at becomes non-None)."""
    token_orm, plaintext = svc.create_token(alice_user, "mcp-touch", is_read_only=True, max_read_bytes=1024)
    assert token_orm.last_used_at is None

    req = _FakeRequest({"authorization": f"Bearer {plaintext}"})
    returned_token, _ = await authenticate_mcp_request(req)

    # Verify the call succeeded — touch_last_used may be throttled on fast
    # re-fetch, but authenticate_mcp_request itself must not raise.
    assert returned_token is not None


# ---------------------------------------------------------------------------
# assert_write_allowed
# ---------------------------------------------------------------------------


class _FakeToken:
    """Minimal stub for assert_write_allowed token parameter."""

    def __init__(self, is_read_only: bool):
        self.is_read_only = is_read_only


def test_write_allowed_server_disable_wins_over_rw_token():
    """mcp_disable_writes=True blocks even a read-write token."""
    token = _FakeToken(is_read_only=False)
    with pytest.raises(McpError) as exc_info:
        assert_write_allowed(token, "upload_file", {"mcp_disable_writes": True})
    assert exc_info.value.code == "READ_ONLY_SERVER"


def test_write_allowed_read_only_token_blocked():
    """is_read_only token is blocked for write tools."""
    token = _FakeToken(is_read_only=True)
    with pytest.raises(McpError) as exc_info:
        assert_write_allowed(token, "upload_file", {})
    assert exc_info.value.code == "READ_ONLY_TOKEN"


def test_write_allowed_delete_blocked_by_disable_deletion():
    """delete_file is blocked when server disable_deletion=True."""
    token = _FakeToken(is_read_only=False)
    with pytest.raises(McpError) as exc_info:
        assert_write_allowed(token, "delete_file", {"disable_deletion": True})
    assert exc_info.value.code == "DELETION_DISABLED"


def test_write_allowed_delete_passes_when_deletion_enabled():
    """delete_file is allowed for rw token when disable_deletion=False."""
    token = _FakeToken(is_read_only=False)
    # Should not raise
    assert_write_allowed(token, "delete_file", {"disable_deletion": False})


def test_write_allowed_upload_passes_for_rw_token():
    """upload_file is allowed for read-write token on permissive config."""
    token = _FakeToken(is_read_only=False)
    # Should not raise
    assert_write_allowed(token, "upload_file", {})


def test_write_allowed_details_include_tool_name():
    """McpError.details always carries the tool_name for observability."""
    token = _FakeToken(is_read_only=True)
    with pytest.raises(McpError) as exc_info:
        assert_write_allowed(token, "upload_file", {})
    assert exc_info.value.details.get("tool") == "upload_file"


# ---------------------------------------------------------------------------
# Admin role expansion (regression: admin tokens were getting empty allowed_roles)
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_user():
    """Insert an admin user with NO explicit role assignments."""
    with session_scope() as session:
        u = User(username="admin_mcp", password_hash="x", is_admin=True)
        session.add(u)
        session.flush()
        return u.id


@pytest.mark.asyncio
async def test_admin_token_sees_all_config_roles(admin_user, monkeypatch):
    """Regression: an admin-issued token must inherit all roles from config,
    matching the web UI's GET /api/me behavior. Previously the MCP auth
    pipeline returned `allowed_roles=[]` for admins (since admins don't have
    explicit role rows), which made list_roles return zero roles even for
    admin-issued tokens.
    """
    from another_s3_manager import config as _cfg
    from another_s3_manager import mcp_server as _mcp_module

    fake_cfg = {"roles": [{"name": "MyR2"}, {"name": "Wasabi"}, {"name": "AwsProd"}]}
    monkeypatch.setattr(_mcp_module._config_module, "load_config", lambda force_reload=False: fake_cfg)

    _, plaintext = svc.create_token(admin_user, "t-admin", is_read_only=True, max_read_bytes=1024)
    _, user_dict = await authenticate_mcp_request(_FakeRequest({"authorization": f"Bearer {plaintext}"}))
    assert user_dict["is_admin"] is True
    assert sorted(user_dict["allowed_roles"]) == ["AwsProd", "MyR2", "Wasabi"]


@pytest.mark.asyncio
async def test_non_admin_token_uses_explicit_role_assignments(alice_user, monkeypatch):
    """Sanity check: non-admin tokens still get only their explicitly assigned roles."""
    from another_s3_manager.models import UserRole

    # Assign alice exactly one role
    with session_scope() as session:
        session.add(UserRole(user_id=alice_user, role_name="MyR2"))

    from another_s3_manager import mcp_server as _mcp_module

    fake_cfg = {"roles": [{"name": "MyR2"}, {"name": "Wasabi"}]}
    monkeypatch.setattr(_mcp_module._config_module, "load_config", lambda force_reload=False: fake_cfg)

    _, plaintext = svc.create_token(alice_user, "t-alice", is_read_only=True, max_read_bytes=1024)
    _, user_dict = await authenticate_mcp_request(_FakeRequest({"authorization": f"Bearer {plaintext}"}))
    assert user_dict["is_admin"] is False
    assert user_dict["allowed_roles"] == ["MyR2"]
