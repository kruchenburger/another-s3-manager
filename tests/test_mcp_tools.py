"""Unit tests for MCP tool implementations.

Tests call tool bodies directly by patching _get_current_request so they
receive a fake HTTP request with the desired Authorization header, without
going through the MCP transport layer.  E2E HTTP tests live in test_mcp_protocol.py
(Task 14).
"""

import base64
from unittest.mock import patch

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.mcp_server import (
    McpError,
    _current_request,
    _RequestCaptureMiddleware,
)
from another_s3_manager.models import User, UserRole

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_user():
    """Insert alice with the 'Default' role; return (user_id, plaintext_token)."""
    with session_scope() as session:
        user = User(username="alice_tools", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        role = UserRole(user_id=user.id, role_name="Default")
        session.add(role)
        session.flush()
        uid = user.id

    _, plaintext = svc.create_token(uid, "tools-test", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


@pytest.fixture
def alice_readonly(alice_user):
    """Return (user_id, plaintext) for a read-only token owned by alice."""
    uid, _ = alice_user
    _, plaintext = svc.create_token(uid, "ro-test", is_read_only=True, max_read_bytes=10_485_760)
    return uid, plaintext


class _FakeRequest:
    """Minimal stub satisfying authenticate_mcp_request's .headers interface."""

    def __init__(self, headers: dict):
        self.headers = headers


def _fake_request(plaintext: str) -> _FakeRequest:
    return _FakeRequest({"authorization": f"Bearer {plaintext}"})


def _no_auth_request() -> _FakeRequest:
    return _FakeRequest({})


# ---------------------------------------------------------------------------
# Tool registry: build get_mcp_app() once, extract callables by name
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tool_registry():
    """Extract MCP tool callables from the module-level FastMCP instance.

    Returns a dict {tool_name: async_fn}.

    Phase 5 lifespan refactor moved FastMCP from inside get_mcp_app() to
    module level so the FastAPI lifespan handler can reach session_manager.
    Tools are now registered at import time, so we just read them off
    mcp_server.mcp directly.

    Note: scope="module" is safe because tool functions are pure closures;
    test isolation comes from _current_request (contextvar, per-coroutine).
    """
    from another_s3_manager.mcp_server import mcp

    return {tool.name: tool.fn for tool in mcp._tool_manager._tools.values()}


async def _call(tool_registry, name: str, request: _FakeRequest, **kwargs):
    """Set the contextvar to `request` and invoke the named tool."""
    token = _current_request.set(request)
    try:
        fn = tool_registry[name]
        return await fn(**kwargs)
    finally:
        _current_request.reset(token)


# ---------------------------------------------------------------------------
# list_roles
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_roles_returns_user_allowed_roles(alice_user, tool_registry):
    """Authenticated user with 'Default' role should get ['Default'] back."""
    uid, plaintext = alice_user
    result = await _call(tool_registry, "list_roles", _fake_request(plaintext))
    assert "Default" in result["roles"]


@pytest.mark.asyncio
async def test_list_roles_no_auth_raises(tool_registry):
    """Missing Bearer token → McpError(INVALID_TOKEN)."""
    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "list_roles", _no_auth_request())
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_list_roles_filters_roles_not_in_config(alice_user, tool_registry, monkeypatch):
    """If a user has a role that no longer exists in config, it's excluded."""
    uid, plaintext = alice_user
    # Config has no roles defined → intersection should be empty.
    # Patch the module-level reference used by tool closures.
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _empty_roles_config(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        return {**cfg, "roles": []}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _empty_roles_config)
    result = await _call(tool_registry, "list_roles", _fake_request(plaintext))
    assert result["roles"] == []


# ---------------------------------------------------------------------------
# list_buckets
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_buckets_role_not_allowed(alice_user, tool_registry):
    """Requesting a role the user doesn't have → McpError(ROLE_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "list_buckets", _fake_request(plaintext), role="AdminRole")
    assert exc_info.value.code == "ROLE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_list_buckets_no_auth_raises(tool_registry):
    """No bearer token → INVALID_TOKEN."""
    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "list_buckets", _no_auth_request(), role="Default")
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_list_buckets_happy_path(alice_user, tool_registry):
    """Allowed role with mocked s3_client → returns {'buckets': [...]}."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_buckets_for_role", return_value=["bucket-a", "bucket-b"]):
        result = await _call(tool_registry, "list_buckets", _fake_request(plaintext), role="Default")
    assert result["buckets"] == ["bucket-a", "bucket-b"]


# ---------------------------------------------------------------------------
# list_files
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_files_happy_path(alice_user, tool_registry):
    """Allowed role+bucket+path → returns {'files': [...]}."""
    uid, plaintext = alice_user
    fake_files = [{"key": "a/b.txt", "size": 10}]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files):
        result = await _call(
            tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="my-bucket", path="a/"
        )
    assert result["files"] == fake_files


@pytest.mark.asyncio
async def test_list_files_role_not_allowed(alice_user, tool_registry):
    """PermissionError mentioning 'role' → McpError(ROLE_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.list_objects_for_role",
        side_effect=PermissionError("role 'AdminRole' not in allowed_roles"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "list_files", _fake_request(plaintext), role="AdminRole", bucket="b", path="")
    assert exc_info.value.code == "ROLE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_list_files_bucket_not_allowed(alice_user, tool_registry):
    """PermissionError mentioning 'bucket' → McpError(BUCKET_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.list_objects_for_role",
        side_effect=PermissionError("bucket 'secret-bucket' not in allowed_buckets"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="secret-bucket", path=""
            )
    assert exc_info.value.code == "BUCKET_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_list_files_no_auth_raises(tool_registry):
    """No bearer → INVALID_TOKEN."""
    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "list_files", _no_auth_request(), role="Default", bucket="b", path="")
    assert exc_info.value.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_list_files_default_path(alice_user, tool_registry):
    """list_files without path argument defaults to '' and works."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=[]):
        result = await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b")
    assert result == {"files": []}


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_file_happy_path(alice_user, tool_registry):
    """RW token + allowed role → returns {ok, bucket, path, size}."""
    uid, plaintext = alice_user
    content = b"hello world"
    encoded = base64.b64encode(content).decode()
    with patch("another_s3_manager.s3_client.put_object_for_role", return_value=None):
        result = await _call(
            tool_registry,
            "upload_file",
            _fake_request(plaintext),
            role="Default",
            bucket="my-bucket",
            path="test.txt",
            content_base64=encoded,
        )
    assert result == {"ok": True, "bucket": "my-bucket", "path": "test.txt", "size": len(content)}


@pytest.mark.asyncio
async def test_upload_file_read_only_token(alice_readonly, tool_registry):
    """Read-only token → McpError(READ_ONLY_TOKEN)."""
    uid, plaintext = alice_readonly
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "upload_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
            content_base64=base64.b64encode(b"data").decode(),
        )
    assert exc_info.value.code == "READ_ONLY_TOKEN"


@pytest.mark.asyncio
async def test_upload_file_read_only_server(alice_user, tool_registry, monkeypatch):
    """Server-level mcp_disable_writes=True → McpError(READ_ONLY_SERVER)."""
    uid, plaintext = alice_user
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _disabled_writes(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        return {**cfg, "mcp_disable_writes": True}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _disabled_writes)
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "upload_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
            content_base64=base64.b64encode(b"data").decode(),
        )
    assert exc_info.value.code == "READ_ONLY_SERVER"


@pytest.mark.asyncio
async def test_upload_file_role_not_allowed(alice_user, tool_registry):
    """PermissionError from s3_client (role) → McpError(ROLE_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.put_object_for_role",
        side_effect=PermissionError("role 'RestrictedRole' not in allowed_roles"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "upload_file",
                _fake_request(plaintext),
                role="RestrictedRole",
                bucket="b",
                path="f.txt",
                content_base64=base64.b64encode(b"data").decode(),
            )
    assert exc_info.value.code == "ROLE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_upload_file_bucket_not_allowed(alice_user, tool_registry):
    """PermissionError from s3_client mentioning 'bucket' → BUCKET_NOT_ALLOWED."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.put_object_for_role",
        side_effect=PermissionError("bucket 'secret' not in allowed_buckets"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "upload_file",
                _fake_request(plaintext),
                role="Default",
                bucket="secret",
                path="f.txt",
                content_base64=base64.b64encode(b"data").decode(),
            )
    assert exc_info.value.code == "BUCKET_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_upload_file_no_auth(tool_registry):
    """No bearer token → INVALID_TOKEN."""
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "upload_file",
            _no_auth_request(),
            role="Default",
            bucket="b",
            path="f.txt",
            content_base64="",
        )
    assert exc_info.value.code == "INVALID_TOKEN"


# ---------------------------------------------------------------------------
# delete_file
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_file_happy_path(alice_user, tool_registry):
    """RW token + deletion enabled → returns {ok, bucket, path}."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.delete_object_for_role",
        return_value={"message": "Deleted 1 object(s).", "count": 1},
    ):
        result = await _call(
            tool_registry,
            "delete_file",
            _fake_request(plaintext),
            role="Default",
            bucket="my-bucket",
            path="test.txt",
        )
    assert result == {"ok": True, "bucket": "my-bucket", "path": "test.txt"}


@pytest.mark.asyncio
async def test_delete_file_read_only_token(alice_readonly, tool_registry):
    """Read-only token → McpError(READ_ONLY_TOKEN)."""
    uid, plaintext = alice_readonly
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "delete_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
        )
    assert exc_info.value.code == "READ_ONLY_TOKEN"


@pytest.mark.asyncio
async def test_delete_file_deletion_disabled(alice_user, tool_registry, monkeypatch):
    """Server-level disable_deletion=True → McpError(DELETION_DISABLED)."""
    uid, plaintext = alice_user
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _deletion_disabled(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        return {**cfg, "disable_deletion": True}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _deletion_disabled)
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "delete_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
        )
    assert exc_info.value.code == "DELETION_DISABLED"


@pytest.mark.asyncio
async def test_delete_file_read_only_server(alice_user, tool_registry, monkeypatch):
    """mcp_disable_writes=True blocks delete too."""
    uid, plaintext = alice_user
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _disabled_writes(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        return {**cfg, "mcp_disable_writes": True}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _disabled_writes)
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "delete_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
        )
    assert exc_info.value.code == "READ_ONLY_SERVER"


@pytest.mark.asyncio
async def test_delete_file_role_not_allowed(alice_user, tool_registry):
    """PermissionError from s3_client → McpError(ROLE_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.delete_object_for_role",
        side_effect=PermissionError("role not in allowed_roles"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "delete_file",
                _fake_request(plaintext),
                role="Default",
                bucket="b",
                path="f.txt",
            )
    assert exc_info.value.code == "ROLE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_delete_file_bucket_not_allowed(alice_user, tool_registry):
    """PermissionError mentioning 'bucket' → McpError(BUCKET_NOT_ALLOWED)."""
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.delete_object_for_role",
        side_effect=PermissionError("bucket 'secret' not in allowed_buckets for role"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "delete_file",
                _fake_request(plaintext),
                role="Default",
                bucket="secret",
                path="f.txt",
            )
    assert exc_info.value.code == "BUCKET_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_delete_file_no_auth(tool_registry):
    """No bearer token → INVALID_TOKEN."""
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "delete_file",
            _no_auth_request(),
            role="Default",
            bucket="b",
            path="f.txt",
        )
    assert exc_info.value.code == "INVALID_TOKEN"


# ---------------------------------------------------------------------------
# _RequestCaptureMiddleware unit test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_capture_middleware_sets_contextvar():
    """Middleware must populate _current_request so _get_current_request works."""
    captured = {}

    async def _dummy_app(scope, receive, send):
        # Read the contextvar from inside the downstream app
        captured["req"] = _current_request.get()

    middleware = _RequestCaptureMiddleware(_dummy_app)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp/mcp",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer as3m_test")],
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(msg):
        pass

    await middleware(scope, _receive, _send)
    assert captured["req"] is not None


@pytest.mark.asyncio
async def test_request_capture_middleware_non_http_passthrough():
    """Non-HTTP (websocket/lifespan) scopes skip the contextvar logic."""
    called = {}

    async def _dummy_app(scope, receive, send):
        called["type"] = scope["type"]

    middleware = _RequestCaptureMiddleware(_dummy_app)
    scope = {"type": "lifespan"}

    await middleware(scope, None, None)
    assert called["type"] == "lifespan"


# ---------------------------------------------------------------------------
# list_roles — error_code metric label on auth failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_roles_records_error_code_on_auth_failure(tool_registry):
    """When list_roles auth fails, mcp_tool_calls_total must label error_code=INVALID_TOKEN."""
    from another_s3_manager import metrics

    def _count(tool: str, code: str) -> float:
        for sample in metrics.mcp_tool_calls_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("tool") == tool
                and sample.labels.get("error_code") == code
            ):
                return sample.value
        return 0.0

    before_invalid = _count("list_roles", "INVALID_TOKEN")
    before_none = _count("list_roles", "none")

    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "list_roles", _no_auth_request())

    assert exc_info.value.code == "INVALID_TOKEN"
    # The counter for INVALID_TOKEN must have incremented, not 'none'.
    assert _count("list_roles", "INVALID_TOKEN") >= before_invalid + 1
    # 'none' counter must NOT have incremented (was the pre-fix bug).
    assert _count("list_roles", "none") == before_none


# ---------------------------------------------------------------------------
# upload_file — INVALID_INPUT on malformed base64
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_file_returns_invalid_input_on_malformed_base64(alice_user, tool_registry):
    """Malformed base64 content_base64 should raise McpError(INVALID_INPUT), not INTERNAL_ERROR."""
    uid, plaintext = alice_user
    with pytest.raises(McpError) as exc_info:
        await _call(
            tool_registry,
            "upload_file",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="f.txt",
            content_base64="not-base64!!!@@@",
        )
    assert exc_info.value.code == "INVALID_INPUT"


# ---------------------------------------------------------------------------
# Response-bytes histogram (LLM-context proxy)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_roles_records_response_bytes(alice_user, tool_registry):
    """mcp_tool_response_bytes{tool} must observe the JSON size after a successful tool call.

    NOTE: previously labeled by (tool, token_id) but token_id violated the
    "Never label by user_id" cardinality rule (revoked tokens never leave
    the Prometheus label set). Label set is now {tool} only.
    """
    from another_s3_manager import metrics

    _, plaintext = alice_user

    def count(tool: str) -> float:
        for sample in metrics.mcp_tool_response_bytes.collect()[0].samples:
            if sample.name.endswith("_count") and sample.labels.get("tool") == tool:
                return sample.value
        return 0.0

    before = count("list_roles")
    await _call(tool_registry, "list_roles", _fake_request(plaintext))
    after = count("list_roles")
    assert after >= before + 1
