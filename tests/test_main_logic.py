import copy
import importlib
import sys
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException


@pytest.fixture
def reload_main():
    import another_s3_manager.main as main

    # Ensure sys.modules has the same object we're about to reload.
    # This avoids ImportError when a prior test patched sys.modules.
    sys.modules.setdefault("another_s3_manager.main", main)
    if sys.modules["another_s3_manager.main"] is not main:
        sys.modules["another_s3_manager.main"] = main
    return importlib.reload(main)


class SimpleUploadFile:
    def __init__(self, data: bytes, filename: str = "test.txt", content_type: str = "text/plain"):
        self._buffer = BytesIO(data)
        self.filename = filename
        self.content_type = content_type
        self.size = None

    async def read(self, n: int = -1) -> bytes:
        if n == -1:
            return self._buffer.read()
        return self._buffer.read(n)

    async def seek(self, offset: int) -> None:
        self._buffer.seek(offset)

    async def close(self) -> None:  # pragma: no cover - compatibility
        pass


def patch_load_config(monkeypatch, main_module, config_value):
    def fake_load_config(force_reload: bool = False):
        return copy.deepcopy(config_value)

    monkeypatch.setattr(main_module, "load_config", fake_load_config)
    monkeypatch.setattr("another_s3_manager.config.load_config", fake_load_config)


@pytest.mark.asyncio
async def test_get_config_admin_env_fallbacks(monkeypatch, reload_main):
    main = reload_main

    base_config = {
        "roles": [
            {
                "name": "Default",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCD12",
                "secret_access_key": "SECRET",
            }
        ],
    }

    patch_load_config(monkeypatch, main, base_config)
    monkeypatch.setattr("another_s3_manager.config.is_config_writable", lambda: True)

    monkeypatch.setenv("ITEMS_PER_PAGE", "250")
    monkeypatch.setenv("DISABLE_DELETION", "true")
    monkeypatch.setenv("ENABLE_LAZY_LOADING", "false")
    monkeypatch.setenv("MAX_FILE_SIZE", str(50 * 1024 * 1024))

    result = await main.get_config(False, {"is_admin": True})

    assert result["items_per_page"] == 250
    assert result["disable_deletion"] is True
    assert result["enable_lazy_loading"] is False
    assert result["max_file_size"] == 50 * 1024 * 1024
    assert "secret_access_key" not in result["roles"][0]
    assert result["is_read_only"] is False


@pytest.mark.asyncio
async def test_get_config_non_admin_filters_roles(monkeypatch, reload_main):
    main = reload_main

    base_config = {
        "roles": [
            {"name": "RoleA", "type": "default"},
            {
                "name": "RoleB",
                "type": "credentials",
                "access_key_id": "AKIA1098765432ZYXW10",
                "secret_access_key": "KEEPME",
            },
        ],
        "items_per_page": 100,
        "disable_deletion": False,
        "enable_lazy_loading": True,
        "max_file_size": 1234,
    }

    patch_load_config(monkeypatch, main, base_config)

    users_data = {
        "users": [
            {
                "username": "demo",
                "allowed_roles": ["RoleB"],
            }
        ]
    }

    monkeypatch.setattr(main, "load_users", lambda: copy.deepcopy(users_data))

    result = await main.get_config(False, {"username": "demo", "is_admin": False})

    assert result["roles"] == [{"name": "RoleB", "type": "credentials", "access_key_id": "AKIA1098765432ZYXW10"}]
    assert result["current_role"] == "RoleB"
    assert result["items_per_page"] == 100
    assert result["max_file_size"] == 1234


@pytest.mark.asyncio
async def test_get_config_user_missing(monkeypatch, reload_main):
    main = reload_main

    base_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, base_config)
    monkeypatch.setattr(main, "load_users", lambda: {"users": []})

    with pytest.raises(HTTPException) as exc:
        await main.get_config(False, {"username": "ghost", "is_admin": False})
    assert exc.value.status_code == 404


def test_validate_role_access_denied(monkeypatch, reload_main):
    main = reload_main

    users_data = {
        "users": [
            {
                "username": "demo",
                "allowed_roles": ["RoleA"],
            }
        ]
    }

    monkeypatch.setattr(main, "load_users", lambda: copy.deepcopy(users_data))

    with pytest.raises(HTTPException) as exc:
        main.validate_role_access("RoleB", {"username": "demo", "is_admin": False})
    assert exc.value.status_code == 403


def test_validate_role_access_user_missing(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(main, "load_users", lambda: {"users": []})

    with pytest.raises(HTTPException) as exc:
        main.validate_role_access("RoleA", {"username": "demo", "is_admin": False})
    assert exc.value.status_code == 404


def test_validate_role_access_admin_allows_any(monkeypatch, reload_main):
    main = reload_main

    assert main.validate_role_access("AnyRole", {"username": "admin", "is_admin": True}) == "AnyRole"


def test_validate_role_access_none(monkeypatch, reload_main):
    main = reload_main

    assert main.validate_role_access(None, {"username": "user", "is_admin": False}) is None


def test_validate_role_access_allowed(monkeypatch, reload_main):
    main = reload_main

    users_data = {
        "users": [
            {
                "username": "demo",
                "allowed_roles": ["RoleA"],
            }
        ]
    }

    monkeypatch.setattr(main, "load_users", lambda: copy.deepcopy(users_data))

    assert main.validate_role_access("RoleA", {"username": "demo", "is_admin": False}) == "RoleA"


@pytest.mark.asyncio
async def test_update_config_preserves_existing_fields(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [{"name": "RoleA", "type": "default"}],
        "items_per_page": 111,
    }

    patch_load_config(monkeypatch, main, current_config)
    monkeypatch.setenv("ENABLE_LAZY_LOADING", "false")
    monkeypatch.setenv("MAX_FILE_SIZE", str(5 * 1024 * 1024))

    saved = {}

    def fake_save_config(data):
        saved["data"] = copy.deepcopy(data)

    monkeypatch.setattr(main, "save_config", fake_save_config)

    new_config = {
        "roles": [{"name": "RoleA", "type": "default"}],
    }

    response = await main.update_config(None, new_config, {"is_admin": True}, True)
    assert response["message"] == "Configuration updated successfully"

    saved_config = saved["data"]
    assert saved_config["items_per_page"] == 111
    assert saved_config["enable_lazy_loading"] is False
    assert saved_config["max_file_size"] == 5 * 1024 * 1024


@pytest.mark.asyncio
async def test_update_config_rejects_small_max_file_size(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [{"name": "RoleA", "type": "default"}],
    }

    patch_load_config(monkeypatch, main, current_config)

    new_config = {
        "roles": [{"name": "RoleA", "type": "default"}],
        "max_file_size": 512,
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 400
    assert "at least 1024" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_requires_access_key(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    new_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "secret_access_key": "SECRET",
            }
        ],
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 400
    assert "access_key_id" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_rejects_empty_access_key(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    new_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "   ",
                "secret_access_key": "SECRET",
            }
        ],
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 400
    assert "cannot be empty" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_requires_role_fields(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    new_config = {
        "roles": [
            {
                "name": "NoType",
            }
        ],
        "current_role": "",
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 400
    assert "Role must have" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_preserves_existing_secret(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCDE1",
                "secret_access_key": "EXISTINGSECRET",
            }
        ],
    }

    patch_load_config(monkeypatch, main, current_config)

    saved = {}
    monkeypatch.setattr(main, "save_config", lambda data: saved.setdefault("data", copy.deepcopy(data)))

    new_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCDE1",
                "secret_access_key": "***REDACTED***",
            }
        ],
    }

    response = await main.update_config(None, new_config, {"is_admin": True}, True)
    assert response["message"] == "Configuration updated successfully"
    assert saved["data"]["roles"][0]["secret_access_key"] == "EXISTINGSECRET"


@pytest.mark.asyncio
async def test_update_config_rejects_missing_secret_on_existing(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCDE1",
                # secret missing
            }
        ],
    }

    patch_load_config(monkeypatch, main, current_config)

    new_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCDE1",
                "secret_access_key": "***REDACTED***",
            }
        ],
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 400
    assert "secret_access_key is required" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_accepts_new_secret(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    saved = {}
    monkeypatch.setattr(main, "save_config", lambda data: saved.setdefault("data", copy.deepcopy(data)))

    new_config = {
        "roles": [
            {
                "name": "Cred",
                "type": "credentials",
                "access_key_id": "AKIA1234567890ABCDE1",
                "secret_access_key": "  NEWSECRET  ",
            }
        ],
        "max_file_size": 2048,
    }

    response = await main.update_config(None, new_config, {"is_admin": True}, True)
    assert response["message"] == "Configuration updated successfully"
    saved_role = saved["data"]["roles"][0]
    assert saved_role["access_key_id"] == "AKIA1234567890ABCDE1"
    assert saved_role["secret_access_key"] == "NEWSECRET"


@pytest.mark.asyncio
async def test_update_config_permission_error(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    def fake_save_config(_):
        raise PermissionError("denied")

    monkeypatch.setattr(main, "save_config", fake_save_config)

    new_config = {
        "roles": [],
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 403
    assert "denied" in exc.value.detail


@pytest.mark.asyncio
async def test_update_config_unexpected_error(monkeypatch, reload_main):
    main = reload_main

    current_config = {
        "roles": [],
    }

    patch_load_config(monkeypatch, main, current_config)

    def fake_save_config(_):
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "save_config", fake_save_config)

    new_config = {
        "roles": [],
    }

    with pytest.raises(HTTPException) as exc:
        await main.update_config(None, new_config, {"is_admin": True}, True)
    assert exc.value.status_code == 500
    # Detail is now structured: {"code": "INTERNAL", "message": "Failed to update config — see server logs"}
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail["code"] == "INTERNAL"
    assert "Failed to update config" in exc.value.detail["message"]


# Note: test_list_buckets_allowed_buckets and test_list_buckets_invalid_allowed_type
# moved to tests/test_s3_client.py — the allowed_buckets short-circuit + isinstance
# validation now live inside list_buckets_for_role (s3_client.py), not in the route.


@pytest.mark.asyncio
async def test_list_buckets_with_explicit_role(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(
        main,
        "list_buckets_for_role",
        lambda role, user: ["bucket-x"],
    )

    buckets = await main.list_buckets("RoleB", {"is_admin": True})
    assert buckets == ["bucket-x"]


@pytest.mark.asyncio
async def test_list_buckets_defaults_to_first_role(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(
        main,
        "list_buckets_for_role",
        lambda role, user: ["bucket-a"],
    )

    buckets = await main.list_buckets(None, {"is_admin": True})
    assert buckets == ["bucket-a"]


@pytest.mark.asyncio
async def test_list_buckets_value_error(monkeypatch, reload_main):
    main = reload_main

    def _raise_value_error(role, user):
        raise ValueError("bad")

    monkeypatch.setattr(main, "list_buckets_for_role", _raise_value_error)

    with pytest.raises(HTTPException) as exc:
        await main.list_buckets(None, {"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_list_buckets_generic_exception(monkeypatch, reload_main):
    main = reload_main

    def _raise_runtime(role, user):
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "list_buckets_for_role", _raise_runtime)

    with pytest.raises(HTTPException) as exc:
        await main.list_buckets(None, {"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_list_files_success(monkeypatch, reload_main):
    """list_files route wraps the helper's list result in the legacy
    {files, path, total_count} envelope the frontend expects."""
    main = reload_main

    def _fake_helper(role, bucket, path, user):
        # Helper returns a flat list of {name, is_directory, size, ...} dicts.
        return [
            {"name": "sub", "is_directory": True, "size": 0},
            {
                "name": "file.txt",
                "is_directory": False,
                "size": 123,
                "last_modified": datetime.now(UTC).isoformat(),
            },
        ]

    monkeypatch.setattr(main, "list_objects_for_role", _fake_helper)

    result = await main.list_files("bucket", path="folder1", role=None, current_user={"is_admin": True})
    assert result["total_count"] == 2
    assert result["path"] == "folder1"
    names = {entry["name"] for entry in result["files"]}
    assert names == {"sub", "file.txt"}


@pytest.mark.asyncio
async def test_list_files_invalid_path(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: (_ for _ in ()).throw(ValueError("bad path")))

    with pytest.raises(HTTPException) as exc:
        await main.list_files("bucket", path="../etc", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400
    assert exc.value.detail == "bad path"


@pytest.mark.asyncio
async def test_upload_file_rejects_by_header(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class DummyClient:
        def __init__(self):
            self.called = False

        def put_object(self, *args, **kwargs):
            self.called = True

    client = DummyClient()

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(client)

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)
    patch_load_config(monkeypatch, main, {"max_file_size": 10})

    request = SimpleNamespace(headers={"content-length": "20"})
    upload = SimpleUploadFile(b"0123456789")

    with pytest.raises(HTTPException) as exc:
        await main.upload_file(request, "bucket", upload, key="test.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400
    assert "maximum allowed size" in exc.value.detail
    assert client.called is False


@pytest.mark.asyncio
async def test_upload_file_streaming_limit(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class DummyClient:
        def __init__(self):
            self.called = False

        def put_object(self, *args, **kwargs):
            self.called = True

    client = DummyClient()

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(client)

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)
    patch_load_config(monkeypatch, main, {"max_file_size": 5})

    request = SimpleNamespace(headers={})
    upload = SimpleUploadFile(b"0123456789")

    with pytest.raises(HTTPException) as exc:
        await main.upload_file(request, "bucket", upload, key="test.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400
    assert "maximum allowed size" in exc.value.detail
    assert client.called is False


@pytest.mark.asyncio
async def test_upload_file_success(monkeypatch, reload_main):
    """B1-style logic test: helper accepts the upload and returns successfully."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)

    calls = []

    def fake_put(role, bucket, path, content, user_dict, content_type=None, content_disposition=None):
        calls.append(
            {
                "role": role,
                "bucket": bucket,
                "path": path,
                "content": content,
                "content_type": content_type,
                "content_disposition": content_disposition,
            }
        )

    monkeypatch.setattr(main, "put_object_for_role", fake_put)
    patch_load_config(monkeypatch, main, {"max_file_size": 50})

    request = SimpleNamespace(headers={})
    upload = SimpleUploadFile(b"12345", filename="ok.txt")

    response = await main.upload_file(
        request, "bucket", upload, key="folder/ok.txt", role=None, current_user={"is_admin": True}
    )
    assert response["message"] == "File uploaded successfully"
    assert calls[0]["path"] == "folder/ok.txt"
    assert calls[0]["content"] == b"12345"


@pytest.mark.asyncio
async def test_list_files_s3_error(monkeypatch, reload_main):
    """Helper raises ClientError(NoSuchBucket) -> route maps to 404."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user):
        raise ClientError({"Error": {"Code": "NoSuchBucket"}}, "ListObjectsV2")

    monkeypatch.setattr(main, "list_objects_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.list_files("bucket", path="", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_list_buckets_boto_error(monkeypatch, reload_main):
    """AccessDenied on ListBuckets returns a friendly 403 pointing the user to the
    role's "Allowed Buckets" field (R2 / scoped IAM tokens). Generic boto errors
    still map to 500 — see test_list_buckets_generic_boto_error_returns_500 below."""
    main = reload_main

    def _raise_access_denied(role, user):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListBuckets")

    monkeypatch.setattr(main, "list_buckets_for_role", _raise_access_denied)

    with pytest.raises(HTTPException) as exc:
        await main.list_buckets(None, {"is_admin": True})
    assert exc.value.status_code == 403
    assert "permission to list all buckets" in exc.value.detail


@pytest.mark.asyncio
async def test_list_files_generic_exception(monkeypatch, reload_main):
    """Helper raises generic RuntimeError -> route maps to 500."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user):
        raise RuntimeError("fail")

    monkeypatch.setattr(main, "list_objects_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.list_files("bucket", path="", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_list_files_client_error_other(monkeypatch, reload_main):
    """Helper raises ClientError(AccessDenied) — not the friendly NoSuchBucket
    branch — so the route falls through to 500 via format_boto_error."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListObjectsV2")

    monkeypatch.setattr(main, "list_objects_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.list_files("bucket", path="", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_upload_file_invalid_key(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"max_file_size": 1024})
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: (_ for _ in ()).throw(ValueError("invalid")))

    request = SimpleNamespace(headers={})
    upload = SimpleUploadFile(b"data")

    with pytest.raises(HTTPException) as exc:
        await main.upload_file(request, "bucket", upload, key="../bad", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_upload_file_env_max_file_size(monkeypatch, reload_main):
    """Verifies MAX_FILE_SIZE env var is honored end-to-end when config omits
    max_file_size and the body fits under the env-configured cap."""
    main = reload_main

    patch_load_config(monkeypatch, main, {"roles": []})
    monkeypatch.setenv("MAX_FILE_SIZE", "4096")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)

    called = []

    def fake_put(role, bucket, path, content, user_dict, content_type=None, content_disposition=None):
        called.append(True)

    monkeypatch.setattr(main, "put_object_for_role", fake_put)

    request = SimpleNamespace(headers={})
    upload = SimpleUploadFile(b"abcd")

    response = await main.upload_file(
        request, "bucket", upload, key="file.txt", role=None, current_user={"is_admin": True}
    )
    assert response["message"] == "File uploaded successfully"
    assert called == [True]


@pytest.mark.asyncio
async def test_upload_file_invalid_content_length(monkeypatch, reload_main):
    """Pre-S3 path: malformed Content-Length header is silently ignored, body
    streamed instead. Helper still called once with the actual body."""
    main = reload_main

    patch_load_config(monkeypatch, main, {"max_file_size": 1024})
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)

    called = []

    def fake_put(role, bucket, path, content, user_dict, content_type=None, content_disposition=None):
        called.append(content)

    monkeypatch.setattr(main, "put_object_for_role", fake_put)

    request = SimpleNamespace(headers={"content-length": "abc"})
    upload = SimpleUploadFile(b"abcd")

    response = await main.upload_file(
        request, "bucket", upload, key="file.txt", role=None, current_user={"is_admin": True}
    )
    assert response["message"] == "File uploaded successfully"
    assert called == [b"abcd"]


@pytest.mark.asyncio
async def test_upload_file_client_error(monkeypatch, reload_main):
    """B2: helper raises ClientError(AccessDenied) -> route maps to 403."""
    main = reload_main

    patch_load_config(monkeypatch, main, {"max_file_size": 1024})
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda key: key)

    def _raise(role, bucket, path, content, user_dict, content_type=None, content_disposition=None):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject")

    monkeypatch.setattr(main, "put_object_for_role", _raise)

    request = SimpleNamespace(headers={})
    upload = SimpleUploadFile(b"abcd")

    with pytest.raises(HTTPException) as exc:
        await main.upload_file(request, "bucket", upload, key="file.txt", role=None, current_user={"is_admin": True})
    # AccessDenied errors now return 403 (Forbidden) instead of 500 (Internal Server Error)
    assert exc.value.status_code == 403
    assert "Failed to upload file" in exc.value.detail


@pytest.mark.asyncio
async def test_download_file_invalid_path(monkeypatch, reload_main):
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: (_ for _ in ()).throw(ValueError("bad path")))

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="../secret", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_download_file_s3_not_found(monkeypatch, reload_main):
    """B2: helper raises FileNotFoundError -> route returns 404."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user_dict, chunk_size=8192):
        raise FileNotFoundError(f"Object '{path}' not found in bucket '{bucket}'")

    monkeypatch.setattr(main, "iter_object_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="missing.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_download_file_generic_exception(monkeypatch, reload_main):
    """B2: helper raises a generic non-S3 exception -> route returns 500 with structured detail."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user_dict, chunk_size=8192):
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "iter_object_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500
    # Structured INTERNAL fallback per error-handling rules
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail.get("code") == "INTERNAL"


@pytest.mark.asyncio
async def test_download_file_client_error_other(monkeypatch, reload_main):
    """B2: helper raises a non-404 ClientError -> route returns 500."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user_dict, chunk_size=8192):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetObject")

    monkeypatch.setattr(main, "iter_object_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_download_file_outer_value_error(monkeypatch, reload_main):
    """Pre-S3 validation: sanitize_bucket_name raising ValueError -> 400."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: (_ for _ in ()).throw(ValueError("bad bucket")))

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_download_file_validate_role_value_error(monkeypatch, reload_main):
    """B2: helper raises ValueError (role/credentials config issue) -> 400."""
    main = reload_main

    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)

    def _raise(role, bucket, path, user_dict, chunk_size=8192):
        raise ValueError("bad role")

    monkeypatch.setattr(main, "iter_object_for_role", _raise)

    with pytest.raises(HTTPException) as exc:
        await main.download_file("bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_delete_file_invalid_path(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: (_ for _ in ()).throw(ValueError("bad path")))

    request = SimpleNamespace()

    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="../secret", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_delete_file_cannot_delete_root(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: "")

    request = SimpleNamespace()

    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400
    assert "Cannot delete root" in exc.value.detail


@pytest.mark.asyncio
async def test_delete_file_single_object_not_found(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def __init__(self):
            self.calls = []

        def get_paginator(self, name):
            class EmptyPaginator:
                def paginate(self, **kwargs):
                    return []

            return EmptyPaginator()

        def delete_object(self, Bucket, Key):
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "DeleteObject")

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(FakeClient())

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()

    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_delete_file_directory(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def __init__(self):
            self.deleted_batches = []

        def get_paginator(self, name):
            class Paginator:
                def paginate(self, **kwargs):
                    yield {
                        "Contents": [
                            {"Key": "dir/file1"},
                            {"Key": "dir/file2"},
                        ]
                    }

            return Paginator()

        def delete_objects(self, Bucket, Delete):
            self.deleted_batches.append(Delete["Objects"])

    client = FakeClient()

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(client)

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()
    response = await main.delete_file(request, "bucket", path="dir/", role=None, current_user={"is_admin": True})
    assert response["count"] == 2
    assert len(client.deleted_batches) == 1


@pytest.mark.asyncio
async def test_delete_file_no_objects_deleted(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def get_paginator(self, name):
            class Paginator:
                def paginate(self, **kwargs):
                    return []

            return Paginator()

        def delete_object(self, Bucket, Key):
            return {}

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(FakeClient())

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()
    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="empty_dir/", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_delete_file_client_error(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def get_paginator(self, name):
            class Paginator:
                def paginate(self, **kwargs):
                    return []

            return Paginator()

        def delete_object(self, Bucket, Key):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DeleteObject")

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(FakeClient())

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()

    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_delete_file_generic_exception(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def get_paginator(self, name):
            class Paginator:
                def paginate(self, **kwargs):
                    return []

            return Paginator()

        def delete_object(self, Bucket, Key):
            raise RuntimeError("boom")

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(FakeClient())

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()

    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500
    # Detail is now structured: {"code": "INTERNAL", "message": "Delete failed — see server logs"}
    assert isinstance(exc.value.detail, dict)
    assert exc.value.detail["code"] == "INTERNAL"
    assert "Delete failed" in exc.value.detail["message"]


@pytest.mark.asyncio
async def test_delete_file_single_success(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    class FakeClient:
        def get_paginator(self, name):
            class Paginator:
                def paginate(self, **kwargs):
                    return []

            return Paginator()

        def delete_object(self, Bucket, Key):
            return {}

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(FakeClient())

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()
    response = await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert response["count"] == 1


@pytest.mark.asyncio
async def test_delete_file_get_client_exception(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise RuntimeError("boom")

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()
    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 500


@pytest.mark.asyncio
async def test_delete_file_value_error(monkeypatch, reload_main):
    main = reload_main

    patch_load_config(monkeypatch, main, {"disable_deletion": False, "roles": []})
    monkeypatch.setenv("DISABLE_DELETION", "false")
    monkeypatch.setattr(main, "sanitize_bucket_name", lambda name: name)
    monkeypatch.setattr(main, "sanitize_path", lambda path: path)
    monkeypatch.setattr(main, "validate_role_access", lambda role, current_user: role)

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise ValueError("bad role")

    import another_s3_manager.main as main

    monkeypatch.setattr(main, "execute_with_s3_retry", mock_execute_with_s3_retry)

    request = SimpleNamespace()
    with pytest.raises(HTTPException) as exc:
        await main.delete_file(request, "bucket", path="file.txt", role=None, current_user={"is_admin": True})
    assert exc.value.status_code == 400
