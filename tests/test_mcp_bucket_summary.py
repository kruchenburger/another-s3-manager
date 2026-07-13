"""Unit tests for the bucket_summary MCP tool.

Same direct-invocation pattern as tests/test_mcp_tools.py: patch the request
contextvar with a fake carrying the Authorization header and call the tool
body straight off the FastMCP tool registry.
"""

from unittest.mock import patch

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.errors import (
    CredentialsExpiredError,
    S3AccessDeniedError,
    S3ConfigError,
    S3NetworkError,
    S3NotFoundError,
    S3OperationError,
)
from another_s3_manager.mcp_server import McpError, _current_request
from another_s3_manager.models import User, UserRole

# ---------------------------------------------------------------------------
# Fixtures (mirrors test_mcp_tools.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_user():
    """Insert alice with the 'Default' role; return (user_id, plaintext_token)."""
    with session_scope() as session:
        user = User(username="alice_summary", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        role = UserRole(user_id=user.id, role_name="Default")
        session.add(role)
        session.flush()
        uid = user.id

    _, plaintext = svc.create_token(uid, "summary-test", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


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


_FAKE_SUMMARY = {
    "bucket": "b",
    "path": "",
    "complete": True,
    "scanned_objects": 3,
    "scanned_bytes": 30,
    "scanned_bytes_human": "30 B",
    "total_objects": 3,
    "total_bytes": 30,
    "total_bytes_human": "30 B",
    "scan_stopped_at": None,
    "root_objects": 3,
    "prefixes": [],
    "prefix_count": 0,
    "prefix_list_complete": True,
    "prefixes_truncated": False,
    "extensions": [{"ext": "txt", "objects": 3, "bytes": 30}],
    "extension_count": 1,
    "extensions_truncated": False,
    "largest_objects": [],
    "oldest_modified": None,
    "newest_modified": None,
}


# ---------------------------------------------------------------------------
# Registration + happy path
# ---------------------------------------------------------------------------


def test_bucket_summary_is_registered(tool_registry):
    """Discovery is the fix: the tool must exist under exactly this name."""
    assert "bucket_summary" in tool_registry


@pytest.mark.asyncio
async def test_bucket_summary_happy_path_passes_config_defaults(alice_user, tool_registry):
    """Result is returned verbatim; helper receives config defaults 50000/20 and prefix ''."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.summarize_bucket_for_role", return_value=dict(_FAKE_SUMMARY)) as helper:
        result = await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b")
    assert result["scanned_objects"] == 3
    assert result["complete"] is True
    args, kwargs = helper.call_args
    assert args[0] == "Default"
    assert args[1] == "b"
    assert args[2] == ""  # normalized prefix
    assert kwargs["max_keys"] == 50_000
    assert kwargs["prefix_scan_pages"] == 20


@pytest.mark.asyncio
async def test_bucket_summary_normalizes_path_like_list_files(alice_user, tool_registry):
    """path '/logs/' → prefix 'logs/' (strip slashes, re-append one trailing)."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.summarize_bucket_for_role", return_value=dict(_FAKE_SUMMARY)) as helper:
        await _call(
            tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b", path="/logs/"
        )
    assert helper.call_args.args[2] == "logs/"


@pytest.mark.asyncio
async def test_bucket_summary_reads_config_overrides(alice_user, tool_registry, monkeypatch):
    """Operator-tuned mcp_summary_* keys reach the helper."""
    uid, plaintext = alice_user
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _tuned(force_reload=False):
        return {
            **original_load(force_reload=force_reload),
            "mcp_summary_max_keys": 60_000,
            "mcp_summary_prefix_scan_pages": 5,
        }

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _tuned)
    with patch("another_s3_manager.s3_client.summarize_bucket_for_role", return_value=dict(_FAKE_SUMMARY)) as helper:
        await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b")
    assert helper.call_args.kwargs["max_keys"] == 60_000
    assert helper.call_args.kwargs["prefix_scan_pages"] == 5


@pytest.mark.asyncio
async def test_bucket_summary_propagates_incomplete_fields(alice_user, tool_registry):
    """Cap-hit shape passes through untouched: complete=False, coverage, total_*=None."""
    uid, plaintext = alice_user
    incomplete = {
        **_FAKE_SUMMARY,
        "complete": False,
        "scanned_objects": 1000,
        "total_objects": None,
        "total_bytes": None,
        "total_bytes_human": None,
        "scan_stopped_at": "logs/f0700.log",
        "prefixes": [
            {"prefix": "archive/", "objects": 300, "bytes": 300, "coverage": "complete"},
            {"prefix": "logs/", "objects": 700, "bytes": 700, "coverage": "partial"},
            {"prefix": "uploads/", "objects": None, "bytes": None, "coverage": "not_scanned"},
        ],
    }
    with patch("another_s3_manager.s3_client.summarize_bucket_for_role", return_value=incomplete):
        result = await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b")
    assert result["complete"] is False
    assert result["total_objects"] is None
    assert [p["coverage"] for p in result["prefixes"]] == ["complete", "partial", "not_scanned"]


# ---------------------------------------------------------------------------
# Permission mapping + auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bucket_summary_role_not_allowed(alice_user, tool_registry):
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.summarize_bucket_for_role",
        side_effect=PermissionError("role 'AdminRole' not in allowed_roles"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="AdminRole", bucket="b")
    assert exc_info.value.code == "ROLE_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_bucket_summary_bucket_not_allowed(alice_user, tool_registry):
    uid, plaintext = alice_user
    with patch(
        "another_s3_manager.s3_client.summarize_bucket_for_role",
        side_effect=PermissionError("bucket 'secret' not in allowed_buckets for role 'Default'"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="secret")
    assert exc_info.value.code == "BUCKET_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_bucket_summary_no_auth_raises(tool_registry):
    with pytest.raises(McpError) as exc_info:
        await _call(tool_registry, "bucket_summary", _FakeRequest({}), role="Default", bucket="b")
    assert exc_info.value.code == "INVALID_TOKEN"


# ---------------------------------------------------------------------------
# Typed S3 exception ladder (final review, 2026-07-13 — carried-over minor
# from Task 4: correctness was previously verified only by source comparison
# against list_files/list_buckets, not by a test that would fail on
# regression). Same pattern as test_mcp_list_buckets_typed_access_denied_...
# / test_mcp_list_files_typed_config_error_... in test_mcp_tools.py, but
# swept over all six typed exceptions in one parametrize since bucket_summary
# had none at all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls,expected_code",
    [
        (S3AccessDeniedError, "S3_ACCESS_DENIED"),
        (S3NotFoundError, "S3_NOT_FOUND"),
        (S3ConfigError, "S3_CONFIG_ERROR"),
        (S3NetworkError, "S3_NETWORK_ERROR"),
        (CredentialsExpiredError, "CREDENTIALS_EXPIRED"),
        (S3OperationError, "S3_OPERATION_ERROR"),
    ],
)
@pytest.mark.asyncio
async def test_bucket_summary_typed_s3_exception_ladder(alice_user, tool_registry, exc_cls, expected_code):
    """Each typed S3 exception from summarize_bucket_for_role must surface its
    own McpError code (never fall through to INTERNAL_ERROR) and increment
    mcp_tool_calls_total{tool="bucket_summary", error_code=<expected_code>}."""
    from another_s3_manager import metrics

    uid, plaintext = alice_user

    def _count() -> float:
        for sample in metrics.mcp_tool_calls_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("tool") == "bucket_summary"
                and sample.labels.get("error_code") == expected_code
            ):
                return sample.value
        return 0.0

    before = _count()
    with patch(
        "another_s3_manager.s3_client.summarize_bucket_for_role",
        side_effect=exc_cls("SomeBotoCode", "boom"),
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="b")

    assert exc_info.value.code == expected_code
    assert exc_info.value.details.get("boto_code") == "SomeBotoCode"
    assert _count() == before + 1


# ---------------------------------------------------------------------------
# End-to-end through moto (real helper, real aggregation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bucket_summary_end_to_end_via_moto(alice_user, tool_registry, moto_s3):
    """The incident scenario in miniature: one call, complete honest answer."""
    uid, plaintext = alice_user
    moto_s3.create_bucket(Bucket="e2e-mini")
    for i in range(7):
        moto_s3.put_object(Bucket="e2e-mini", Key=f"logs/f{i}.log", Body=b"xx")
    moto_s3.put_object(Bucket="e2e-mini", Key="root.txt", Body=b"y")

    result = await _call(tool_registry, "bucket_summary", _fake_request(plaintext), role="Default", bucket="e2e-mini")

    assert result["complete"] is True
    assert result["total_objects"] == 8
    assert result["root_objects"] == 1
    assert result["prefix_count"] == 1
    assert result["prefixes"][0]["prefix"] == "logs/"
    assert result["prefixes"][0]["objects"] == 7
    assert result["prefixes"][0]["coverage"] == "complete"
