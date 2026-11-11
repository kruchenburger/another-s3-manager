"""ASM-64: one deletion gate (env DISABLE_DELETION OR config disable_deletion) on every delete path."""

from unittest.mock import patch

import pytest

from another_s3_manager import config as config_mod
from another_s3_manager import move_jobs
from another_s3_manager.errors import MoveError
from another_s3_manager.mcp_server import McpError
from tests.test_main import login
from tests.test_mcp_tools import _call, _fake_request, alice_user, tool_registry  # noqa: F401

# (env value or None, config flag, deletion disabled?)
GATE_CASES = [
    pytest.param(None, False, False, id="neither"),
    pytest.param("true", False, True, id="env-only"),
    pytest.param(None, True, True, id="config-only"),
    pytest.param("true", True, True, id="both"),
]
BLOCKED_CASES = [case for case in GATE_CASES if case.values[2]]


def _apply(monkeypatch, env, cfg_flag):
    if env is None:
        monkeypatch.delenv("DISABLE_DELETION", raising=False)
    else:
        monkeypatch.setenv("DISABLE_DELETION", env)
    cfg = config_mod.load_config(force_reload=True)
    config_mod.save_config({**cfg, "disable_deletion": cfg_flag})


@pytest.mark.parametrize("env,cfg_flag,expected", GATE_CASES)
def test_gate_helper(monkeypatch, env, cfg_flag, expected):
    if env is None:
        monkeypatch.delenv("DISABLE_DELETION", raising=False)
    else:
        monkeypatch.setenv("DISABLE_DELETION", env)
    assert config_mod.is_deletion_disabled({"disable_deletion": cfg_flag}) is expected


def test_gate_helper_env_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("DISABLE_DELETION", "TRUE")
    assert config_mod.is_deletion_disabled({"disable_deletion": False}) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("env,cfg_flag,expected", BLOCKED_CASES)
async def test_mcp_delete_file_blocked(alice_user, tool_registry, monkeypatch, env, cfg_flag, expected):  # noqa: F811
    _apply(monkeypatch, env, cfg_flag)
    _, plaintext = alice_user
    with patch("another_s3_manager.s3_client.delete_object_for_role") as del_mock:
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "delete_file",
                _fake_request(plaintext),
                role="Default",
                bucket="b",
                path="a.txt",
            )
    assert exc_info.value.code == "DELETION_DISABLED"
    del_mock.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("env,cfg_flag,expected", BLOCKED_CASES)
async def test_mcp_copy_with_delete_source_blocked(alice_user, tool_registry, monkeypatch, env, cfg_flag, expected):  # noqa: F811
    _apply(monkeypatch, env, cfg_flag)
    _, plaintext = alice_user
    with (
        patch("another_s3_manager.s3_client.copy_object_for_role") as copy_mock,
        patch("another_s3_manager.s3_client.delete_object_for_role") as del_mock,
    ):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "copy_object",
                _fake_request(plaintext),
                role="Default",
                source_bucket="b",
                source_path="a.txt",
                dest_bucket="b",
                dest_path="b.txt",
                delete_source=True,
            )
    assert exc_info.value.code == "DELETION_DISABLED"
    copy_mock.assert_not_called()
    del_mock.assert_not_called()


@pytest.mark.asyncio
async def test_mcp_copy_without_delete_source_ignores_gate(alice_user, tool_registry, monkeypatch):  # noqa: F811
    _apply(monkeypatch, "true", True)
    _, plaintext = alice_user
    with patch("another_s3_manager.s3_client.copy_object_for_role", return_value=None) as copy_mock:
        result = await _call(
            tool_registry,
            "copy_object",
            _fake_request(plaintext),
            role="Default",
            source_bucket="b",
            source_path="a.txt",
            dest_bucket="b",
            dest_path="c.txt",
        )
    assert result["moved"] is False
    copy_mock.assert_called_once()


@pytest.mark.parametrize("env,cfg_flag,expected", BLOCKED_CASES)
def test_web_delete_blocked(app_client, monkeypatch, env, cfg_flag, expected):
    _apply(monkeypatch, env, cfg_flag)
    _, headers = login(app_client)
    # main.py imports delete_object_for_role by name, so patch it there.
    with patch("another_s3_manager.main.delete_object_for_role") as del_mock:
        response = app_client.delete("/api/buckets/b/files?path=a.txt&role=Default", headers=headers)
    assert response.status_code == 403
    del_mock.assert_not_called()


@pytest.mark.parametrize("env,cfg_flag,expected", GATE_CASES)
def test_web_reports_same_gate(app_client, monkeypatch, env, cfg_flag, expected):
    _apply(monkeypatch, env, cfg_flag)
    login(app_client)
    assert app_client.get("/api/me").json()["disable_deletion"] is expected
    assert app_client.get("/api/config").json()["disable_deletion"] is expected


@pytest.mark.parametrize("env,cfg_flag,expected", BLOCKED_CASES)
def test_move_blocked(app_client, monkeypatch, env, cfg_flag, expected):
    _apply(monkeypatch, env, cfg_flag)
    with pytest.raises(MoveError) as exc_info:
        move_jobs.require_access({"username": "admin", "is_admin": True}, "Default", "b", deleting=True)
    assert exc_info.value.code == "DELETION_DISABLED"
