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


def test_web_write_without_role_is_rejected_before_reservation(app_client):
    """A missing role is refused with ROLE_REQUIRED, never BUSY, even on a reserved path."""
    from tests.test_main import login

    _, headers = login(app_client)
    with reservations.reserve("move", [("Default", "bucket", "source/")]):
        response = app_client.post(
            "/api/buckets/bucket/upload", data={"key": "source/a"}, files={"file": ("a", b"body")}, headers=headers
        )
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "ROLE_REQUIRED"
        response = app_client.delete("/api/buckets/bucket/files", params={"path": "source/a"}, headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "ROLE_REQUIRED"


def test_removed_role_gets_same_refusal_on_reserved_and_free_paths(app_client):
    """A role deleted from config but still in allowed_roles must not reveal reservations."""
    from tests.test_main import create_user, login

    create_user("ghost", password="password123", allowed_roles=["Removed"])
    _, headers = login(app_client, username="ghost", password="password123")
    params = {"role": "Removed", "path": "source/a"}
    with reservations.reserve("move", [("Removed", "bucket", "source/")]):
        reserved = app_client.delete("/api/buckets/bucket/files", params=params, headers=headers)
    free = app_client.delete("/api/buckets/bucket/files", params=params, headers=headers)
    assert reserved.status_code == free.status_code
    assert reserved.status_code != 409
    assert reserved.json() == free.json()


def test_web_write_busy(app_client):
    from tests.test_main import login

    _, headers = login(app_client)
    role = "Default"
    with reservations.reserve("move", [("Default", "bucket", "source/")]):
        data = {"key": "source/a", "role": role}
        response = app_client.post(
            "/api/buckets/bucket/upload", data=data, files={"file": ("a", b"body")}, headers=headers
        )
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "BUSY"
        response = app_client.delete(
            "/api/buckets/bucket/files",
            params={"path": "source/a", "role": role},
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


@pytest.mark.parametrize("operation", ["put", "upload", "delete", "copy_source", "copy_dest", "folder"])
@pytest.mark.parametrize("denial", ["role", "bucket"])
def test_write_authorization_precedes_busy(operation, denial, monkeypatch):
    import io

    from another_s3_manager import config, s3_client

    cfg = config.load_config()
    cfg["roles"][0]["allowed_buckets"] = ["allowed"]
    config.save_config(cfg)
    user = {"is_admin": False, "allowed_roles": [] if denial == "role" else ["Default"]}
    bucket = "allowed" if denial == "role" else "forbidden"
    monkeypatch.setattr(s3_client, "get_s3_client", lambda *args: pytest.fail("unauthorized S3 access"))
    with reservations.reserve("move", [("Default", bucket, "source/")]):
        with pytest.raises(PermissionError):
            if operation == "put":
                s3_client.put_object_for_role("Default", bucket, "source/a", b"x", user)
            elif operation == "upload":
                s3_client.upload_fileobj_for_role("Default", bucket, "source/a", io.BytesIO(b"x"), user)
            elif operation == "delete":
                s3_client.delete_object_for_role("Default", bucket, "source/a", user)
            elif operation == "folder":
                s3_client.create_folder_for_role("Default", bucket, "source/a", user)
            elif operation == "copy_source":
                s3_client.copy_object_for_role("Default", bucket, "source/a", "allowed", "target/a", user)
            else:
                s3_client.copy_object_for_role("Default", "allowed", "target/a", bucket, "source/a", user)


@pytest.mark.parametrize("method", ["upload", "delete"])
def test_web_unauthorized_reserved_path_is_403(app_client, method):
    from another_s3_manager import auth, users
    from tests.test_main import login

    users.create_user("restricted", auth.hash_password("password123"), allowed_roles=[], must_change_password=False)
    _, headers = login(app_client, "restricted", "password123")
    with reservations.reserve("move", [("Default", "bucket", "source/")]):
        if method == "upload":
            response = app_client.post(
                "/api/buckets/bucket/upload",
                data={"key": "source/a", "role": "Default"},
                files={"file": ("a", b"body")},
                headers=headers,
            )
        else:
            response = app_client.delete(
                "/api/buckets/bucket/files",
                params={"path": "source/a", "role": "Default"},
                headers=headers,
            )
    assert response.status_code == 403
    assert "BUSY" not in response.text
