"""Tests for list_files config-driven page sizing (mcp_list_page_size /
mcp_list_max_page_size) and the truncation hint that redirects agents to
bucket_summary. Direct-invocation pattern from tests/test_mcp_tools.py."""

from unittest.mock import patch

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.mcp_server import _current_request
from another_s3_manager.models import User, UserRole


@pytest.fixture
def alice_user():
    with session_scope() as session:
        user = User(username="alice_paging", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_name="Default"))
        session.flush()
        uid = user.id
    _, plaintext = svc.create_token(uid, "paging-test", is_read_only=False, max_read_bytes=10_485_760)
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


def _patch_paging_config(monkeypatch, **overrides):
    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _patched(force_reload=False):
        return {**original_load(force_reload=force_reload), **overrides}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _patched)


_NOT_TRUNCATED = {"files": [], "is_truncated": False, "next_continuation_token": None, "key_count": 0}
_TRUNCATED = {
    "files": [{"key": "a.txt", "size": 1, "last_modified": "2026-01-01T00:00:00+00:00"}],
    "is_truncated": True,
    "next_continuation_token": "TOKEN-A",
    "key_count": 1,
}


# ---------------------------------------------------------------------------
# Resolution rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_omitted_max_keys_uses_config_page_size(alice_user, tool_registry, monkeypatch):
    """mcp_list_page_size=200 → recursive call without max_keys asks for 200."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=200, mcp_list_max_page_size=10_000)
    with patch(
        "another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)
    ) as helper:
        await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", recursive=True)
    assert helper.call_args.kwargs["max_keys"] == 200
    assert helper.call_args.kwargs["max_page_size"] == 10_000


@pytest.mark.asyncio
async def test_agent_max_keys_above_ceiling_is_clamped_not_rejected(alice_user, tool_registry, monkeypatch):
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=1000, mcp_list_max_page_size=10_000)
    with patch(
        "another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)
    ) as helper:
        await _call(
            tool_registry,
            "list_files",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            recursive=True,
            max_keys=50_000,
        )
    assert helper.call_args.kwargs["max_keys"] == 10_000


@pytest.mark.asyncio
async def test_agent_max_keys_below_ceiling_is_honoured(alice_user, tool_registry, monkeypatch):
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=1000, mcp_list_max_page_size=10_000)
    with patch(
        "another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)
    ) as helper:
        await _call(
            tool_registry,
            "list_files",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            recursive=True,
            max_keys=500,
        )
    assert helper.call_args.kwargs["max_keys"] == 500


@pytest.mark.asyncio
async def test_inconsistent_config_ceiling_wins(alice_user, tool_registry, monkeypatch):
    """mcp_list_page_size=5000 with mcp_list_max_page_size=1000 → effective 1000, no error."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=5000, mcp_list_max_page_size=1000)
    with patch(
        "another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)
    ) as helper:
        await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", recursive=True)
    assert helper.call_args.kwargs["max_keys"] == 1000
    assert helper.call_args.kwargs["max_page_size"] == 1000


@pytest.mark.asyncio
async def test_zero_or_negative_config_clamped_to_one(alice_user, tool_registry, monkeypatch):
    """Server-side floor: page size 0 and ceiling -5 in a hand-edited config resolve to 1."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=0, mcp_list_max_page_size=-5)
    with patch(
        "another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)
    ) as helper:
        await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", recursive=True)
    assert helper.call_args.kwargs["max_keys"] == 1
    assert helper.call_args.kwargs["max_page_size"] == 1


# ---------------------------------------------------------------------------
# The hint — present exactly when the agent needs it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hint_present_when_truncated(alice_user, tool_registry):
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_TRUNCATED)):
        result = await _call(
            tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", recursive=True
        )
    assert result["is_truncated"] is True
    assert "bucket_summary" in result["hint"]
    assert "next_continuation_token" in result["hint"]


@pytest.mark.asyncio
async def test_hint_absent_when_not_truncated(alice_user, tool_registry):
    """Small responses are not polluted: the field is ABSENT, not null."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_objects_recursive_for_role", return_value=dict(_NOT_TRUNCATED)):
        result = await _call(
            tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", recursive=True
        )
    assert "hint" not in result


@pytest.mark.asyncio
async def test_hint_absent_in_short_non_recursive_listing(alice_user, tool_registry):
    """A non-recursive listing well under the effective cap gets neither
    field — is_truncated/hint are additive, not always-present."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=[]):
        result = await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b")
    assert "hint" not in result
    assert "is_truncated" not in result


# ---------------------------------------------------------------------------
# Non-recursive mode is bounded too (2026-07-13 final review, BLOCKING 1):
# recursive=False is the DEFAULT — reachable with zero optional arguments —
# and previously called list_objects_for_role with no cap at all. A flat
# bucket (backup dumps, exports, loose media) hit the exact firehose this
# feature exists to prevent.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_recursive_listing_truncated_at_config_page_size(alice_user, tool_registry, monkeypatch):
    """mcp_list_page_size=3 with 5 fake entries -> truncated to 3, is_truncated
    True, and a hint that does NOT promise a continuation token."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=3, mcp_list_max_page_size=1000)
    fake_files = [{"name": f"f{i}.txt", "is_directory": False, "size": i} for i in range(5)]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files):
        result = await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b")
    assert result["files"] == fake_files[:3]
    assert result["is_truncated"] is True
    assert "bucket_summary" in result["hint"]
    assert "continuation token" in result["hint"]
    assert "next_continuation_token" not in result["hint"]


@pytest.mark.asyncio
async def test_non_recursive_listing_under_cap_is_not_truncated(alice_user, tool_registry, monkeypatch):
    """4 entries under a page size of 5 -> untouched, no truncation fields."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=5, mcp_list_max_page_size=1000)
    fake_files = [{"name": f"f{i}.txt", "is_directory": False, "size": i} for i in range(4)]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files):
        result = await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b")
    assert result["files"] == fake_files
    assert "is_truncated" not in result
    assert "hint" not in result


@pytest.mark.asyncio
async def test_non_recursive_agent_max_keys_applies_too(alice_user, tool_registry, monkeypatch):
    """An agent-supplied max_keys bounds the non-recursive listing exactly
    like the recursive one — same resolution formula, both branches."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=1000, mcp_list_max_page_size=1000)
    fake_files = [{"name": f"f{i}.txt", "is_directory": False, "size": i} for i in range(10)]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files):
        result = await _call(
            tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", max_keys=2
        )
    assert result["files"] == fake_files[:2]
    assert result["is_truncated"] is True


@pytest.mark.asyncio
async def test_non_recursive_agent_max_keys_zero_floors_to_one(alice_user, tool_registry, monkeypatch):
    """An agent-supplied max_keys=0 must not collapse the response to an
    empty files list — the recursive branch already floors this internally
    (list_objects_recursive_for_role: max(1, min(...))); the non-recursive
    branch computes its own bound in mcp_server.py and needs the same floor."""
    uid, plaintext = alice_user
    _patch_paging_config(monkeypatch, mcp_list_page_size=1000, mcp_list_max_page_size=1000)
    fake_files = [{"name": f"f{i}.txt", "is_directory": False, "size": i} for i in range(3)]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files):
        result = await _call(
            tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", max_keys=0
        )
    assert result["files"] == fake_files[:1]
    assert result["is_truncated"] is True


# ---------------------------------------------------------------------------
# Trailing-slash normalization (2026-07-14 review, Important-3(b)):
# list_objects_for_role appends "/" onto path itself
# (`prefix = path + "/" if path else ""`), so a caller-supplied trailing
# slash used to double up into "//" and S3 silently returned an empty
# listing — no error, just nothing. bucket_summary's own path description
# demonstrates the trailing-slash form, so this tool actively steered agents
# into the broken call shape. mcp_server.py must strip a trailing slash
# before calling list_objects_for_role, the same way the recursive branch
# already normalizes via path.strip("/").
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_recursive_trailing_slash_normalized_same_as_without(alice_user, tool_registry):
    """A trailing-slash path must produce the SAME listing as the same path
    without one — both by result and by what's actually sent to S3."""
    uid, plaintext = alice_user
    fake_files = [{"name": "f0.txt", "is_directory": False, "size": 0}]
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=fake_files) as helper:
        result_with_slash = await _call(
            tool_registry,
            "list_files",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="some/subdir/",
        )
        result_without_slash = await _call(
            tool_registry,
            "list_files",
            _fake_request(plaintext),
            role="Default",
            bucket="b",
            path="some/subdir",
        )

    assert result_with_slash == result_without_slash == {"files": fake_files}
    # Both calls must reach the S3 helper with the identical, slash-stripped
    # path — not "some/subdir/" for one call and "some/subdir" for the other.
    assert helper.call_args_list[0].args[2] == "some/subdir"
    assert helper.call_args_list[1].args[2] == "some/subdir"


@pytest.mark.asyncio
async def test_non_recursive_root_path_still_lists_bucket_root(alice_user, tool_registry):
    """Regression guard: normalizing path must not turn "" into something
    else — the bucket root listing (path="") must keep calling
    list_objects_for_role with path="", exactly as before."""
    uid, plaintext = alice_user
    with patch("another_s3_manager.s3_client.list_objects_for_role", return_value=[]) as helper:
        await _call(tool_registry, "list_files", _fake_request(plaintext), role="Default", bucket="b", path="")
    assert helper.call_args.args[2] == ""
