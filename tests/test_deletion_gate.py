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
    from another_s3_manager import users

    user = users.load_users()["users"][0]
    with pytest.raises(MoveError) as exc_info:
        move_jobs.require_access(user, "Default", "b", deleting=True)
    assert exc_info.value.code == "DELETION_DISABLED"


def test_web_partial_delete_mapping(app_client, monkeypatch):
    from another_s3_manager.errors import PartialDeleteError

    _, headers = login(app_client)

    def partial(*args):
        raise PartialDeleteError(2, {"dir/denied": "AccessDenied"})

    monkeypatch.setattr("another_s3_manager.main.delete_object_for_role", partial)
    response = app_client.delete("/api/buckets/bucket/files?path=dir/&role=Default", headers=headers)
    assert response.status_code == 502
    assert response.json()["detail"] == {
        "code": "PARTIAL_DELETE",
        "message": "Deleted 2 of 3 objects; 1 could not be deleted (first: dir/denied: AccessDenied)",
        "deleted": 2,
        "failed_count": 1,
    }


@pytest.mark.asyncio
async def test_mcp_partial_delete_mapping(alice_user, tool_registry, monkeypatch):  # noqa: F811
    from another_s3_manager.errors import PartialDeleteError

    def partial(*args):
        raise PartialDeleteError(2, {"dir/denied": "AccessDenied"})

    monkeypatch.setattr("another_s3_manager.s3_client.delete_object_for_role", partial)
    with pytest.raises(McpError) as caught:
        await _call(
            tool_registry, "delete_file", _fake_request(alice_user[1]), role="Default", bucket="bucket", path="dir/"
        )
    assert caught.value.code == "PARTIAL_DELETE"
    assert caught.value.details["deleted"] == 2
    assert caught.value.details["failed_count"] == 1
    assert caught.value.message == "Deleted 2 of 3 objects; 1 could not be deleted (first: dir/denied: AccessDenied)"


def test_web_delete_calls_current_destructive_helper(app_client, moto_s3, monkeypatch):
    from unittest.mock import Mock

    from another_s3_manager import s3_client

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="web-helper")
    moto_s3.put_object(Bucket="web-helper", Key="file", Body=b"x")
    helper = Mock(wraps=s3_client.require_current_destructive)
    monkeypatch.setattr(s3_client, "require_current_destructive", helper)
    response = app_client.delete("/api/buckets/web-helper/files?path=file&role=Default", headers=headers)
    assert response.status_code == 200
    assert helper.call_args.args[1:] == ("Default", "web-helper")
    assert helper.call_args.args[0]["id"] is not None
    assert not moto_s3.list_objects_v2(Bucket="web-helper").get("Contents")


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["delete_file", "copy_object"])
async def test_mcp_destructive_paths_use_current_helper(alice_user, tool_registry, moto_s3, monkeypatch, tool):  # noqa: F811
    from unittest.mock import Mock

    from another_s3_manager import s3_client

    moto_s3.create_bucket(Bucket="mcp-helper")
    moto_s3.put_object(Bucket="mcp-helper", Key="file", Body=b"x")
    helper = Mock(wraps=s3_client.require_current_destructive)
    monkeypatch.setattr(s3_client, "require_current_destructive", helper)
    kwargs = (
        {"path": "file"}
        if tool == "delete_file"
        else {
            "source_bucket": "mcp-helper",
            "source_path": "file",
            "dest_bucket": "mcp-helper",
            "dest_path": "copy",
            "delete_source": True,
        }
    )
    if tool == "delete_file":
        kwargs["bucket"] = "mcp-helper"
    await _call(tool_registry, tool, _fake_request(alice_user[1]), role="Default", **kwargs)
    assert helper.call_args.args[0]["id"] == alice_user[0]
    assert helper.call_args.args[1:] == ("Default", "mcp-helper")
    assert "file" not in {item["Key"] for item in moto_s3.list_objects_v2(Bucket="mcp-helper").get("Contents", [])}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,code,details",
    [
        ("MoveError", "ROLE_CHANGED", {"http_status": 409}),
        ("S3AccessDeniedError", "S3_ACCESS_DENIED", {"boto_code": "AccessDenied"}),
        ("CredentialsExpiredError", "CREDENTIALS_EXPIRED", {"boto_code": "ExpiredToken"}),
        ("S3ConfigError", "S3_CONFIG_ERROR", {"boto_code": "InvalidRegion"}),
        ("S3NotFoundError", "S3_NOT_FOUND", {"boto_code": "NoSuchKey"}),
        ("S3NetworkError", "S3_NETWORK_ERROR", {"boto_code": "EndpointConnectionError"}),
        ("S3OperationError", "S3_OPERATION_ERROR", {"boto_code": "Unknown"}),
    ],
)
async def test_delete_storage_mapping_contract(alice_user, tool_registry, monkeypatch, kind, code, details):  # noqa: F811
    from another_s3_manager import errors, mcp_server

    error = (
        errors.MoveError("ROLE_CHANGED", 409)
        if kind == "MoveError"
        else getattr(errors, kind)(details["boto_code"], "storage message")
    )

    def fail(*args):
        raise error

    monkeypatch.setattr("another_s3_manager.s3_client.delete_object_for_role", fail)
    with pytest.raises(mcp_server.McpError) as caught:
        await _call(
            tool_registry, "delete_file", _fake_request(alice_user[1]), role="Default", bucket="bucket", path="file"
        )
    assert caught.value.code == code
    assert caught.value.message == str(error)
    assert caught.value.details == details


@pytest.mark.asyncio
async def test_mcp_user_snapshot_contains_account_generation(alice_user):  # noqa: F811
    from another_s3_manager import mcp_server, users

    _, user = await mcp_server.authenticate_mcp_request(_fake_request(alice_user[1]))
    current = users.get_user_by_id(alice_user[0])
    assert user["created_at"] == current["created_at"]
