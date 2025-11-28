import builtins
import importlib
import io
import json
import time
import copy
from datetime import datetime, timedelta, UTC

import os

os.environ.setdefault("APP_VERSION", "0.1.0")

from constants import APP_VERSION

import pytest
from botocore.exceptions import ClientError
from fastapi import status, HTTPException


def reload_main():
    import main

    importlib.reload(main)
    return main


def reload_auth_module():
    import auth

    importlib.reload(auth)
    return auth


def reload_users_module():
    import users

    importlib.reload(users)
    return users


def ensure_admin_exists(auth_module, users_module):
    data = users_module.load_users()
    if not any(user.get("username") == "admin" for user in data.get("users", [])):
        data.setdefault("users", []).append(
            {
                "username": "admin",
                "password_hash": auth_module.hash_password("admin123"),
                "is_admin": True,
                "allowed_roles": [],
                "theme": "auto",
                "created_at": datetime.now().isoformat(),
            }
        )
        users_module.save_users(data)


def test_reload_helpers():
    assert hasattr(reload_main(), "app")
    assert reload_auth_module()
    assert reload_users_module()


def test_reset_auth_state_adds_admin():
    users_module = reload_users_module()
    users_module.save_users({"users": []})
    auth_module = reload_auth_module()
    auth_module._login_attempts = {}
    users_module.save_bans({})
    ensure_admin_exists(auth_module, users_module)
    data = users_module.load_users()
    assert any(user.get("username") == "admin" for user in data["users"])


def test_main_import_without_dotenv(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("main"))
    try:
        assert hasattr(module, "app")
    finally:
        importlib.reload(module)


def test_main_exits_when_secret_missing(monkeypatch):
    module = importlib.import_module("main")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.setenv("JWT_SECRET_KEY", "")

    def fake_exit(code):
        raise SystemExit(code)

    monkeypatch.setattr("sys.exit", fake_exit)
    with pytest.raises(SystemExit) as exc:
        importlib.reload(module)
    assert exc.value.code == 1
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    importlib.reload(module)


@pytest.fixture(autouse=True)
def reset_auth_state():
    auth_module = reload_auth_module()
    auth_module._login_attempts = {}
    users_module = reload_users_module()
    users_module.save_bans({})
    ensure_admin_exists(auth_module, users_module)


def login(client, username="admin", password="admin123"):
    auth_module = reload_auth_module()
    auth_module._login_attempts = {}
    users_module = reload_users_module()
    users_module.save_bans({})
    response = client.post(
        "/api/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    token = data["access_token"]
    csrf = data["csrf_token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf,
    }
    return data, headers


def create_user(username, password="password", is_admin=False, allowed_roles=None):
    users_module = reload_users_module()
    auth_module = reload_auth_module()

    data = users_module.load_users()
    data["users"].append(
        {
            "username": username,
            "password_hash": auth_module.hash_password(password),
            "is_admin": is_admin,
            "allowed_roles": allowed_roles or [],
            "theme": "auto",
            "created_at": datetime.now().isoformat(),
        }
    )
    users_module.save_users(data)


def test_root_returns_html(app_client):
    response = app_client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "<!DOCTYPE html>" in response.text


def test_login_page_returns_html(app_client):
    response = app_client.get("/login")
    assert response.status_code == status.HTTP_200_OK
    assert "<!DOCTYPE html>" in response.text


def test_login_success(app_client):
    data, _ = login(app_client)
    assert "access_token" in data
    assert "csrf_token" in data


def test_login_failure(app_client):
    response = app_client.post(
        "/api/login", data={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_login_banned_user(app_client):
    auth_module = reload_auth_module()
    for _ in range(auth_module.MAX_LOGIN_ATTEMPTS):
        auth_module.record_login_attempt("admin", success=False)
    assert auth_module.check_ban("admin") is True
    response = app_client.post(
        "/api/login", data={"username": "admin", "password": "admin123"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_current_user_info(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "admin"
    assert data["is_admin"] is True
    assert data["app_version"] == APP_VERSION


def test_get_current_user_info_requires_auth(app_client):
    response = app_client.get("/api/me")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_app_info(app_client):
    response = app_client.get("/api/app-info")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "app_name" in data
    assert data["app_version"] == APP_VERSION


def test_admin_page(app_client):
    response = app_client.get("/admin")
    assert response.status_code == status.HTTP_200_OK
    assert "<!DOCTYPE html>" in response.text


def test_list_users_requires_admin(app_client):
    create_user("user", is_admin=False)
    data, headers = login(app_client)
    headers_non_admin = headers.copy()
    # create non-admin token
    create_user("regular", is_admin=False)
    response = app_client.post(
        "/api/login", data={"username": "regular", "password": "password"}
    )
    assert response.status_code == status.HTTP_200_OK
    regular_data = response.json()
    regular_headers = {
        "Authorization": f"Bearer {regular_data['access_token']}",
    }
    resp = app_client.get("/api/admin/users", headers=regular_headers)
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_list_users_as_admin(app_client):
    create_user("user", is_admin=False)
    _, headers = login(app_client)
    response = app_client.get("/api/admin/users", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "users" in data
    assert any(u["username"] == "user" for u in data["users"])


def test_create_user(app_client):
    _, headers = login(app_client)
    response = app_client.post(
        "/api/admin/users",
        data={
            "username": "newuser",
            "password": "newpassword",
            "is_admin": "true",
            "allowed_roles": "Default",
        },
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "newuser"


def test_create_user_duplicate(app_client):
    create_user("duplicate", is_admin=False)
    _, headers = login(app_client)
    response = app_client.post(
        "/api/admin/users",
        data={
            "username": "duplicate",
            "password": "password",
            "is_admin": "false",
        },
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_user_password(app_client):
    create_user("changeme", is_admin=False)
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/changeme/password",
        json={"password": "newpass"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK


def test_update_user(app_client):
    create_user("updateme", is_admin=False)
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/updateme",
        data={"is_admin": "true", "allowed_roles": "Default"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK


def test_update_user_theme(app_client):
    create_user("themer", is_admin=False)
    app_client.post("/api/login", data={"username": "themer", "password": "password"})
    login_response = app_client.post(
        "/api/login", data={"username": "themer", "password": "password"}
    )
    data = login_response.json()
    headers = {
        "Authorization": f"Bearer {data['access_token']}",
        "X-CSRF-Token": data["csrf_token"],
    }
    response = app_client.put(
        "/api/user/theme",
        json={"theme": "light"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["theme"] == "light"


def test_delete_user(app_client):
    create_user("deleteme", is_admin=False)
    _, headers = login(app_client)
    response = app_client.delete("/api/admin/users/deleteme", headers=headers)
    assert response.status_code == status.HTTP_200_OK


def test_list_bans(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/admin/bans", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "bans" in response.json()


def test_unban_user(app_client):
    users_module = reload_users_module()
    _, headers = login(app_client)

    auth_module = reload_auth_module()
    for _ in range(auth_module.MAX_LOGIN_ATTEMPTS):
        auth_module.record_login_attempt("troublesome", success=False)
    assert "troublesome" in users_module.load_bans()
    response = app_client.delete("/api/admin/bans/troublesome", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "troublesome" not in users_module.load_bans()


def test_get_config_admin(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "roles" in data
    assert "is_read_only" in data


def test_get_config_regular_user(app_client):
    create_user("viewer", is_admin=False)
    login_response = app_client.post(
        "/api/login", data={"username": "viewer", "password": "password"}
    )
    data = login_response.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "roles" in response.json()


def test_export_config_admin(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/config/export", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "roles" in data


def test_export_config_requires_admin(app_client):
    create_user("viewer", is_admin=False)
    login_response = app_client.post(
        "/api/login", data={"username": "viewer", "password": "password"}
    )
    data = login_response.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    response = app_client.get("/api/config/export", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_update_config(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Default",
                "type": "default",
                "description": "Use default credentials",
            }
        ],
        "items_per_page": 50,
        "enable_lazy_loading": False,
        "max_file_size": 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK, response.json()


def test_list_buckets_with_allowed_list(app_client, monkeypatch):
    import config as config_module
    import main

    config_data = config_module.load_config(force_reload=True)
    config_data["roles"][0]["allowed_buckets"] = ["bucket-a", "bucket-b"]
    config_module.save_config(config_data)

    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == ["bucket-a", "bucket-b"]


def test_list_buckets_uses_s3(app_client, mocker):
    _, headers = login(app_client)
    s3_mock = mocker.MagicMock()
    s3_mock.list_buckets.return_value = {"Buckets": [{"Name": "bucket"}]}

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(s3_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == ["bucket"]


def test_list_files(app_client, mocker):
    _, headers = login(app_client)
    paginator_mock = mocker.MagicMock()
    paginator_mock.paginate.return_value = [
        {
            "CommonPrefixes": [{"Prefix": "folder/"}],
            "Contents": [
                {
                    "Key": "folder/file.txt",
                    "Size": 10,
                    "LastModified": datetime.now(UTC),
                }
            ],
        }
    ]
    s3_mock = mocker.MagicMock()
    s3_mock.get_paginator.return_value = paginator_mock

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(s3_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/files", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total_count"] == 2


def test_upload_file(app_client, mocker):
    _, headers = login(app_client)
    s3_mock = mocker.MagicMock()

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(s3_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    file_content = io.BytesIO(b"content")
    response = app_client.post(
        "/api/buckets/test-bucket/upload",
        data={"key": "file.txt"},
        files={"file": ("file.txt", file_content, "text/plain")},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    s3_mock.put_object.assert_called_once()


def test_upload_file_too_large(app_client, mocker):
    import config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["max_file_size"] = 1
    config_module.save_config(config_data)
    _, headers = login(app_client)
    response = app_client.post(
        "/api/buckets/test-bucket/upload",
        data={"key": "file.txt"},
        files={"file": ("file.txt", io.BytesIO(b"toolarge"), "text/plain")},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_download_file(app_client, mocker):
    _, headers = login(app_client)
    body_mock = mocker.MagicMock()
    # Make read() return data on first call, then empty bytes to signal end
    body_mock.read.side_effect = [b"data", b""]
    s3_mock = mocker.MagicMock()
    s3_mock.get_object.return_value = {
        "Body": body_mock,
        "ContentType": "text/plain",
    }

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(s3_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/download", params={"path": "file.txt"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.content == b"data"


def test_delete_file(app_client, mocker):
    _, headers = login(app_client)
    paginator_mock = mocker.MagicMock()
    paginator_mock.paginate.return_value = [
        {
            "Contents": [
                {"Key": "path/file.txt", "Size": 1, "LastModified": datetime.now(UTC)}
            ]
        }
    ]
    s3_mock = mocker.MagicMock()
    s3_mock.get_paginator.return_value = paginator_mock

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(s3_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.delete(
        "/api/buckets/test-bucket/files", params={"path": "path"}, headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    s3_mock.delete_objects.assert_called_once()


def test_login_user_not_found(app_client):
    response = app_client.post(
        "/api/login",
        data={"username": "ghost", "password": "doesntmatter"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_login_handles_unexpected_error(app_client, mocker):
    mocker.patch("main.load_users", side_effect=RuntimeError("boom"))
    response = app_client.post(
        "/api/login",
        data={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_create_user_truncates_long_password(app_client):
    _, headers = login(app_client)
    long_password = "x" * 100
    response = app_client.post(
        "/api/admin/users",
        data={"username": "truncate", "password": long_password},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK


def test_update_user_password_empty(app_client):
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/someone/password",
        json={"password": ""},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_user_password_missing_user(app_client):
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/missing/password",
        json={"password": "newpass"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_update_user_not_found(app_client):
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/missing",
        data={"is_admin": "true"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_update_user_theme_invalid_value(app_client):
    create_user("themer", is_admin=False)
    login_response = app_client.post(
        "/api/login", data={"username": "themer", "password": "password"}
    )
    data = login_response.json()
    headers = {
        "Authorization": f"Bearer {data['access_token']}",
        "X-CSRF-Token": data["csrf_token"],
    }
    response = app_client.put(
        "/api/user/theme",
        json={"theme": "blue"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_user_theme_user_missing(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("main.load_users", return_value={"users": []})
    response = app_client.put(
        "/api/user/theme",
        json={"theme": "light"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_user_cannot_delete_self(app_client):
    _, headers = login(app_client)
    response = app_client.delete("/api/admin/users/admin", headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_unban_user_not_banned(app_client):
    _, headers = login(app_client)
    response = app_client.delete("/api/admin/bans/unknown", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_config_admin_read_only(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("config.is_config_writable", return_value=False)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["is_read_only"] is True


def test_get_config_regular_user_no_roles(app_client):
    create_user("limited", is_admin=False, allowed_roles=[])
    login_response = app_client.post(
        "/api/login", data={"username": "limited", "password": "password"}
    )
    data = login_response.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["roles"] == []


def test_list_buckets_handles_error(app_client, mocker):
    _, headers = login(app_client)

    def mock_execute_with_s3_retry(role_name, callback):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListBuckets")

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_list_files_handles_error(app_client, mocker):
    _, headers = login(app_client)

    def mock_execute_with_s3_retry(role_name, callback):
        raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "Missing"}}, "ListObjectsV2")

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/files", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_upload_file_handles_exception(app_client, mocker):
    _, headers = login(app_client)

    def mock_execute_with_s3_retry(role_name, callback):
        raise ValueError("boom")

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.post(
        "/api/buckets/test-bucket/upload",
        data={"key": "file.txt"},
        files={"file": ("file.txt", io.BytesIO(b"data"), "text/plain")},
        headers=headers,
    )
    # ValueError from s3_client now returns 400 (configuration error) instead of 500
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_download_file_not_found(app_client, mocker):
    _, headers = login(app_client)
    client_mock = mocker.MagicMock()
    client_mock.get_object.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Missing"}},
        "GetObject",
    )

    def mock_execute_with_s3_retry(role_name, callback):
        return callback(client_mock)

    mocker.patch("main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get(
        "/api/buckets/test-bucket/download", params={"path": "ghost.txt"}, headers=headers
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_file_handles_error(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch(
        "main.get_s3_client",
        side_effect=ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListObjectsV2"),
    )
    response = app_client.delete(
        "/api/buckets/test-bucket/files", params={"path": "path"}, headers=headers
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_list_bans_includes_remaining_minutes(app_client, mocker):
    _, headers = login(app_client)
    now = time.time()
    mocker.patch(
        "main.load_bans",
        return_value={
            "trouble": {
                "banned_until": now + 120,
                "banned_at": now,
                "reason": "testing",
            }
        },
    )
    response = app_client.get("/api/admin/bans", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()["bans"][0]
    assert data["remaining_minutes"] >= 1


def test_update_config_requires_admin(app_client):
    create_user("viewer", is_admin=False)
    login_response = app_client.post(
        "/api/login", data={"username": "viewer", "password": "password"}
    )
    info = login_response.json()
    headers = {
        "Authorization": f"Bearer {info['access_token']}",
        "X-CSRF-Token": info["csrf_token"],
    }
    response = app_client.post(
        "/api/config",
        json={"roles": []},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_update_config_read_only(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("config.is_config_writable", return_value=False)
    response = app_client.post(
        "/api/config",
        json={"roles": []},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_update_config_invalid_structure(app_client):
    _, headers = login(app_client)
    response = app_client.post("/api/config", json={}, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_invalid_items_per_page_type(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "items_per_page": "many",
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_items_per_page_out_of_range(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "items_per_page": 5,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_enable_lazy_loading_not_bool(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "enable_lazy_loading": "yes",
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_max_file_size_invalid(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "max_file_size": "big",
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_credentials_invalid_access_key(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Creds",
                "type": "credentials",
                "access_key_id": "BAD",
                "secret_access_key": "secret",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_credentials_missing_secret(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Creds",
                "type": "credentials",
                "access_key_id": "AKIA1234567890123456",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_profile_requires_name(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Profile",
                "type": "profile",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_assume_role_requires_arn(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Assume",
                "type": "assume_role",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_s3_compatible_success(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
                "use_ssl": False,
                "verify_ssl": False,
                "addressing_style": "path",
            }
        ],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    if response.status_code != status.HTTP_200_OK:
        print(f"Response: {response.status_code}")
        print(f"Detail: {response.json()}")
    assert response.status_code == status.HTTP_200_OK


def test_update_config_s3_compatible_missing_endpoint_url(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "endpoint_url" in response.json()["detail"].lower()


def test_update_config_s3_compatible_missing_access_key_id(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "access_key_id" in response.json()["detail"].lower()


def test_update_config_s3_compatible_missing_secret(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "secret_access_key" in response.json()["detail"].lower()


def test_update_config_s3_compatible_empty_endpoint_url(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "   ",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "endpoint_url" in response.json()["detail"].lower()


def test_update_config_s3_compatible_empty_access_key_id(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "   ",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "access_key_id" in response.json()["detail"].lower()


def test_update_config_s3_compatible_preserves_secret_on_edit(app_client):
    _, headers = login(app_client)
    # First, create a role with secret
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK

    # Now edit without providing secret (should preserve existing)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "newkey",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_list_buckets_invalid_allowed_buckets(mocker):
    module = reload_main()
    import config as config_module

    config_data = copy.deepcopy(config_module.load_config(force_reload=True))
    config_data["roles"][0]["allowed_buckets"] = "not-a-list"
    mocker.patch("config.load_config", return_value=config_data)

    with pytest.raises(HTTPException) as exc:
        await module.list_buckets(None, {"username": "admin", "is_admin": True})
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_list_files_invalid_path():
    module = reload_main()
    with pytest.raises(HTTPException) as exc:
        await module.list_files(
            "test-bucket",
            "../etc",
            None,
            {"username": "admin", "is_admin": True},
        )
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST


def test_validate_role_access_denied():
    create_user("limited", is_admin=False, allowed_roles=["Other"])
    module = reload_main()
    with pytest.raises(HTTPException) as exc:
        module.validate_role_access("Default", {"username": "limited", "is_admin": False})
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_delete_file_root_path_forbidden(app_client):
    _, headers = login(app_client)
    response = app_client.delete(
        "/api/buckets/test-bucket/files",
        params={"path": ""},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_delete_file_disabled(app_client, mocker):
    _, headers = login(app_client)
    import config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["disable_deletion"] = True
    config_module.save_config(config_data)
    response = app_client.delete(
        "/api/buckets/test-bucket/files",
        params={"path": "path/file.txt"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

