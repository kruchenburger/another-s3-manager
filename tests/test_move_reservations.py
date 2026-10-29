import pytest

from another_s3_manager import move_reservations as reservations
from another_s3_manager.errors import MoveError

pytest_plugins = ["tests.test_mcp_tools"]


def test_overlap_and_release():
    with reservations.reserve("one", [("Default", "bucket", "a/b/")]):
        with pytest.raises(MoveError) as error:
            with reservations.reserve("two", [("Default", "bucket", "a/b/x")]):
                pytest.fail("overlap allowed")
        assert error.value.code == "BUSY"
        with reservations.reserve("three", [("Default", "bucket", "a/bc")]):
            pass
    with reservations.reserve("two", [("Default", "bucket", "a/b/x")]):
        pass


def test_file_and_folder_name_collide():
    with reservations.reserve("one", [("Default", "bucket", "x")]):
        with pytest.raises(MoveError):
            with reservations.reserve("two", [("Default", "bucket", "x/y")]):
                pass


def test_different_role_cannot_bypass_reservation():
    with reservations.reserve("one", [("role-one", "bucket", "source/")]):
        with pytest.raises(MoveError) as error:
            with reservations.reserve("two", [("role-two", "bucket", "source/key")]):
                pass
        assert error.value.code == "BUSY"


@pytest.mark.parametrize("role", [None, "Default"])
def test_web_write_busy(app_client, role):
    from tests.test_main import login

    _, headers = login(app_client)
    with reservations.reserve("move", [("Default", "bucket", "source/")]):
        data = {"key": "source/a"}
        if role:
            data["role"] = role
        response = app_client.post(
            "/api/buckets/bucket/upload", data=data, files={"file": ("a", b"body")}, headers=headers
        )
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "BUSY"
        response = app_client.delete(
            "/api/buckets/bucket/files",
            params={"path": "source/a", **({"role": role} if role else {})},
            headers=headers,
        )
        assert response.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,kwargs",
    [
        ("upload_file", {"bucket": "bucket", "path": "source/a", "content_base64": "YQ=="}),
        ("delete_file", {"bucket": "bucket", "path": "source/a"}),
        (
            "copy_object",
            {"source_bucket": "bucket", "source_path": "source/a", "dest_bucket": "bucket", "dest_path": "target/a"},
        ),
        (
            "copy_object",
            {"source_bucket": "bucket", "source_path": "other/a", "dest_bucket": "bucket", "dest_path": "source/a"},
        ),
    ],
)
async def test_mcp_busy(alice_user, tool_registry, tool, kwargs):
    from another_s3_manager.mcp_server import McpError
    from tests.test_mcp_tools import _call, _fake_request

    with reservations.reserve("move", [("Default", "bucket", "source/")]):
        with pytest.raises(McpError) as error:
            await _call(tool_registry, tool, _fake_request(alice_user[1]), role="Default", **kwargs)
        assert error.value.code == "BUSY"
