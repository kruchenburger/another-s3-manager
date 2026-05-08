import builtins
import copy
import importlib
import io
import os
import time
from datetime import UTC, datetime

os.environ.setdefault("APP_VERSION", "0.1.0")

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException, status

import another_s3_manager.constants as _constants_module


def reload_main():
    import another_s3_manager.main as main

    importlib.reload(main)
    return main


def reload_auth_module():
    import another_s3_manager.auth as auth

    importlib.reload(auth)
    return auth


def reload_users_module():
    import another_s3_manager.users as users

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
    module = importlib.reload(importlib.import_module("another_s3_manager.main"))
    try:
        assert hasattr(module, "app")
    finally:
        importlib.reload(module)


def test_main_exits_when_secret_missing(monkeypatch):
    module = importlib.import_module("another_s3_manager.main")
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
    # Cookie-based auth: TestClient's cookie jar auto-captures the Set-Cookie
    # response header, so subsequent calls on the same client send the
    # access_token cookie. CSRF token now lives only in the JWT (not in the
    # login body) and is exposed via /api/me for the client to echo back in
    # the X-CSRF-Token header on mutating requests.
    me_response = client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK, me_response.text
    csrf = me_response.json()["csrf_token"]
    headers = {
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


def test_v2_spa_fallback_serves_index_for_unknown_paths(app_client, tmp_path, monkeypatch):
    """REGRESSION: deep-linking into the React SPA (e.g. /v2/login, /v2/r/aws-prod/b/images)
    must serve index.html so React Router can take over. Without the SPA fallback route,
    StaticFiles returns 404 because no such file exists on disk."""
    # Seed a fake index.html so the fallback has something to return
    from another_s3_manager.constants import STATIC_DIR

    v2_dir = STATIC_DIR / "v2"
    v2_dir.mkdir(parents=True, exist_ok=True)
    index_file = v2_dir / "index.html"
    created = not index_file.exists()
    if created:
        index_file.write_text("<!DOCTYPE html><html><head></head><body><div id='root'></div></body></html>")

    try:
        # Direct deep-link should serve index.html (not 404)
        response = app_client.get("/v2/login")
        assert response.status_code == 200, f"deep-link /v2/login returned {response.status_code}"
        assert "<div id='root'>" in response.text or '<div id="root">' in response.text

        # Bare /v2 (no trailing slash) should also work
        response = app_client.get("/v2")
        assert response.status_code == 200

        # Nested deep-link
        response = app_client.get("/v2/r/aws-prod/b/images/p/2026/photos")
        assert response.status_code == 200
    finally:
        if created:
            index_file.unlink()


def test_login_success(app_client):
    data, _ = login(app_client)
    # After cookie-based auth migration: body returns only the user object,
    # the JWT itself rides in an httpOnly cookie set via Set-Cookie header.
    assert data["user"]["username"] == "admin"
    assert data["user"]["is_admin"] is True
    assert "access_token" not in data
    assert "csrf_token" not in data


def test_login_failure(app_client):
    response = app_client.post("/api/login", data={"username": "admin", "password": "wrong"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_login_sets_httponly_cookie_and_returns_user_only(app_client, monkeypatch):
    """Successful login: Set-Cookie header has access_token; body has only user object (no token)."""
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pw-12345")
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import save_users

    save_users(
        {
            "users": [
                {
                    "username": "admin",
                    "password_hash": hash_password("test-pw-12345"),
                    "is_admin": True,
                    "allowed_roles": [],
                    "theme": "auto",
                }
            ]
        }
    )

    response = app_client.post(
        "/api/login",
        data={"username": "admin", "password": "test-pw-12345"},
    )
    assert response.status_code == 200

    # Cookie set with httpOnly + SameSite=Strict
    set_cookie = response.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie or "samesite=strict" in set_cookie.lower()

    # Body shape: only `user`, no `access_token` / `token_type` / `csrf_token`
    body = response.json()
    assert "access_token" not in body
    assert "csrf_token" not in body  # CSRF now comes via /api/me, not login body
    assert body["user"] == {"username": "admin", "is_admin": True}


def test_login_wrong_password_no_cookie(app_client, monkeypatch):
    """Wrong password: 401, no Set-Cookie."""
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pw-12345")
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import save_users

    save_users(
        {
            "users": [
                {
                    "username": "admin",
                    "password_hash": hash_password("test-pw-12345"),
                    "is_admin": True,
                    "allowed_roles": [],
                    "theme": "auto",
                }
            ]
        }
    )

    response = app_client.post(
        "/api/login",
        data={"username": "admin", "password": "WRONG"},
    )
    assert response.status_code == 401
    assert "access_token=" not in response.headers.get("set-cookie", "")


def test_logout_clears_cookie(app_client, monkeypatch):
    """POST /api/logout returns ok and Set-Cookie that clears access_token."""
    # Seed admin
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pw-12345")
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import save_users

    save_users(
        {
            "users": [
                {
                    "username": "admin",
                    "password_hash": hash_password("test-pw-12345"),
                    "is_admin": True,
                    "allowed_roles": [],
                    "theme": "auto",
                }
            ]
        }
    )

    # Log in to get the cookie
    login = app_client.post(
        "/api/login",
        data={"username": "admin", "password": "test-pw-12345"},
    )
    assert login.status_code == 200

    # Logout
    response = app_client.post("/api/logout")
    assert response.status_code == 200
    assert response.json() == {"ok": True}

    set_cookie = response.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie
    # Cookie cleared via Max-Age=0 or expires in past
    assert "Max-Age=0" in set_cookie or "max-age=0" in set_cookie.lower() or "expires=" in set_cookie.lower()


def test_login_banned_user(app_client):
    """Non-admins get auto-banned after MAX_LOGIN_ATTEMPTS failures and the
    /api/login endpoint then refuses with 403. (Admins are exempt — see
    test_auth.test_record_login_attempt_admin_is_never_banned.)"""
    auth_module = reload_auth_module()
    create_user("alice", password="alice-pw", is_admin=False)
    for _ in range(auth_module.MAX_LOGIN_ATTEMPTS):
        auth_module.record_login_attempt("alice", success=False)
    assert auth_module.check_ban("alice") is True
    response = app_client.post("/api/login", data={"username": "alice", "password": "alice-pw"})
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_current_user_info(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "admin"
    assert data["is_admin"] is True
    assert data["app_version"] == _constants_module.APP_VERSION


def test_get_current_user_info_requires_auth(app_client):
    response = app_client.get("/api/me")
    # Cookie-based auth: missing access_token cookie -> 401 Not authenticated
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_app_info(app_client):
    response = app_client.get("/api/app-info")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "app_name" in data
    assert data["app_version"] == _constants_module.APP_VERSION


def test_admin_page(app_client):
    response = app_client.get("/admin")
    assert response.status_code == status.HTTP_200_OK
    assert "<!DOCTYPE html>" in response.text


def test_list_users_requires_admin(app_client):
    create_user("user", is_admin=False)
    data, headers = login(app_client)
    # Switch the active cookie to the regular user — TestClient's cookie jar
    # auto-replaces the access_token cookie from the new login's Set-Cookie.
    create_user("regular", is_admin=False)
    response = app_client.post("/api/login", data={"username": "regular", "password": "password"})
    assert response.status_code == status.HTTP_200_OK
    resp = app_client.get("/api/admin/users")
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
            "password": "NewPassword1",
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
        json={"password": "NewPass123"},
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
    login_response = app_client.post("/api/login", data={"username": "themer", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    # Cookie set automatically by TestClient cookie jar; pull CSRF from /api/me.
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}
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

    # User must exist for the ban FK to be honored
    users_module.create_user(username="troublesome", password_hash="h")

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
    login_response = app_client.post("/api/login", data={"username": "viewer", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    response = app_client.get("/api/config")
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
    login_response = app_client.post("/api/login", data={"username": "viewer", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    response = app_client.get("/api/config/export")
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
    import another_s3_manager.config as config_module

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

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
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

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/files", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total_count"] == 2


def test_upload_file(app_client, mocker):
    _, headers = login(app_client)
    s3_mock = mocker.MagicMock()

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
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
    import another_s3_manager.config as config_module

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

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/download", params={"path": "file.txt"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.content == b"data"


def test_delete_file(app_client, mocker):
    _, headers = login(app_client)
    paginator_mock = mocker.MagicMock()
    paginator_mock.paginate.return_value = [
        {"Contents": [{"Key": "path/file.txt", "Size": 1, "LastModified": datetime.now(UTC)}]}
    ]
    s3_mock = mocker.MagicMock()
    s3_mock.get_paginator.return_value = paginator_mock

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.delete("/api/buckets/test-bucket/files", params={"path": "path"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    s3_mock.delete_objects.assert_called_once()


def test_login_user_not_found(app_client):
    response = app_client.post(
        "/api/login",
        data={"username": "ghost", "password": "doesntmatter"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_login_handles_unexpected_error(app_client, mocker):
    mocker.patch("another_s3_manager.main.load_users", side_effect=RuntimeError("boom"))
    response = app_client.post(
        "/api/login",
        data={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_create_user_truncates_long_password(app_client):
    _, headers = login(app_client)
    # Strong prefix (upper, lower, digit, 8+ chars) + filler to exceed 72 bytes
    long_password = "Strong1A" + "x" * 92
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
    login_response = app_client.post("/api/login", data={"username": "themer", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}
    response = app_client.put(
        "/api/user/theme",
        json={"theme": "blue"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_user_theme_user_missing(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("another_s3_manager.main.load_users", return_value={"users": []})
    response = app_client.put(
        "/api/user/theme",
        json={"theme": "light"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_me_returns_allowed_roles(app_client, monkeypatch):
    """/api/me must include allowed_roles for the React sidebar."""
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pw")
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import save_users

    save_users(
        {
            "users": [
                {
                    "username": "alice",
                    "password_hash": hash_password("test-pw"),
                    "is_admin": False,
                    "allowed_roles": ["aws-prod", "r2-cdn"],
                    "theme": "auto",
                }
            ]
        }
    )

    login_response = app_client.post("/api/login", data={"username": "alice", "password": "test-pw"})
    assert login_response.status_code == 200, login_response.text

    me_response = app_client.get("/api/me")
    assert me_response.status_code == 200
    body = me_response.json()
    assert body["allowed_roles"] == ["aws-prod", "r2-cdn"]


def test_me_admin_returns_all_config_roles(app_client, mocker):
    """Admins should see every role defined in config.json, regardless of
    the per-user `allowed_roles` field. The React sidebar relies on this
    to show admins the full role tree without an extra /api/config call."""
    config_data = {
        "roles": [
            {"name": "aws-prod", "type": "default"},
            {"name": "r2-cdn", "type": "credentials"},
            {"name": "wasabi-archive", "type": "profile"},
        ],
    }
    mocker.patch("another_s3_manager.main.load_config", return_value=config_data)

    _, _ = login(app_client)  # admin login (admin user has allowed_roles=[])

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    body = me_response.json()
    assert body["is_admin"] is True
    assert body["allowed_roles"] == ["aws-prod", "r2-cdn", "wasabi-archive"]


def test_me_admin_with_empty_config_returns_empty_roles(app_client, mocker):
    """Admin with no roles in config gets an empty list — must not crash."""
    mocker.patch("another_s3_manager.main.load_config", return_value={"roles": []})

    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    body = me_response.json()
    assert body["is_admin"] is True
    assert body["allowed_roles"] == []


def test_me_includes_disable_deletion_from_config(app_client, mocker):
    """/api/me must surface disable_deletion so the React UI can disable Delete controls."""
    mocker.patch(
        "another_s3_manager.main.load_config",
        return_value={"roles": [], "disable_deletion": True},
    )
    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    assert me_response.json()["disable_deletion"] is True


def test_me_includes_disable_deletion_from_env(app_client, mocker, monkeypatch):
    """DISABLE_DELETION env var should win over config (matches /api/config behaviour)."""
    mocker.patch(
        "another_s3_manager.main.load_config",
        return_value={"roles": [], "disable_deletion": False},
    )
    monkeypatch.setenv("DISABLE_DELETION", "true")
    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    assert me_response.json()["disable_deletion"] is True


def test_me_disable_deletion_defaults_false(app_client, mocker, monkeypatch):
    """Neither env nor config set → disable_deletion is False."""
    mocker.patch("another_s3_manager.main.load_config", return_value={"roles": []})
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    _, _ = login(app_client)

    assert app_client.get("/api/me").json()["disable_deletion"] is False


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
    mocker.patch("another_s3_manager.config.is_config_writable", return_value=False)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["is_read_only"] is True


def test_get_config_regular_user_no_roles(app_client):
    create_user("limited", is_admin=False, allowed_roles=[])
    login_response = app_client.post("/api/login", data={"username": "limited", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    response = app_client.get("/api/config")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["roles"] == []


def test_list_buckets_access_denied_returns_friendly_403(app_client, mocker):
    """When ListBuckets fails with AccessDenied (e.g. R2 bucket-scoped tokens, AWS IAM
    bucket-scoped policies), the API must return 403 with a generic explanation —
    not a raw 500 boto error. The frontend layers role-appropriate CTAs on top."""

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListBuckets")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    detail = response.json()["detail"]
    assert "permission to list all buckets" in detail
    assert "scoped" in detail.lower()


def test_list_buckets_other_client_error_still_returns_500(app_client, mocker):
    """Non-403 boto errors should still surface as 500 — the friendly-error path
    is specifically for 'cannot list buckets' permission failures, not generic ones."""

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "ListBuckets")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_list_files_handles_error(app_client, mocker):
    _, headers = login(app_client)

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": "Missing"}}, "ListObjectsV2")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/files", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_upload_file_handles_exception(app_client, mocker):
    _, headers = login(app_client)

    def mock_execute_with_s3_retry(role_name, operation, callback):
        raise ValueError("boom")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
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

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(client_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)
    response = app_client.get("/api/buckets/test-bucket/download", params={"path": "ghost.txt"}, headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_file_handles_error(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch(
        "another_s3_manager.s3_client.get_s3_client",
        side_effect=ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListObjectsV2"),
    )
    response = app_client.delete("/api/buckets/test-bucket/files", params={"path": "path"}, headers=headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_list_bans_includes_remaining_minutes(app_client, mocker):
    _, headers = login(app_client)
    now = time.time()
    mocker.patch(
        "another_s3_manager.main.load_bans",
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
    login_response = app_client.post("/api/login", data={"username": "viewer", "password": "password"})
    assert login_response.status_code == status.HTTP_200_OK
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}
    response = app_client.post(
        "/api/config",
        json={"roles": []},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_update_config_read_only(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("another_s3_manager.config.is_config_writable", return_value=False)
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
    import another_s3_manager.config as config_module

    config_data = copy.deepcopy(config_module.load_config(force_reload=True))
    config_data["roles"][0]["allowed_buckets"] = "not-a-list"
    mocker.patch("another_s3_manager.config.load_config", return_value=config_data)

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
    import another_s3_manager.config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["disable_deletion"] = True
    config_module.save_config(config_data)
    response = app_client.delete(
        "/api/buckets/test-bucket/files",
        params={"path": "path/file.txt"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_startup_runs_migrations_and_json_import(monkeypatch, tmp_path):
    """At startup, app runs alembic upgrade head and migrates JSON if needed."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")

    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)
    database.reset_engine_for_tests()

    # Seed a JSON file
    import json

    (tmp_path / "users.json").write_text(
        json.dumps(
            {
                "users": [
                    {
                        "username": "imported",
                        "password_hash": "h",
                        "is_admin": False,
                        "allowed_roles": [],
                        "theme": "auto",
                    }
                ]
            }
        )
    )

    # Phase 5 lifespan refactor: startup is now part of the FastAPI lifespan
    # context manager rather than a standalone async function. Drive the same
    # behavior by entering the lifespan via TestClient — TestClient runs the
    # lifespan handler on enter (and exits it on close).
    from fastapi.testclient import TestClient

    from another_s3_manager.main import app

    with TestClient(app) as _client:
        # Lifespan startup runs synchronously before this block executes;
        # by the time we're here, alembic + JSON migration have completed.
        pass

    # DB exists, has the imported user, JSON renamed
    assert (tmp_path / "another_s3_manager.db").exists()
    assert (tmp_path / "users.json.migrated.bak").exists()

    from another_s3_manager.users import get_user_by_username

    assert get_user_by_username("imported") is not None


def test_download_file_with_colon_in_key(app_client, mocker):
    """REGRESSION: files with `:` in S3 key (e.g. ISO timestamps) must be downloadable.
    Previously sanitize_path rejected `:` outright, breaking download/delete for these keys."""
    key_with_colon = "logs/2026-04-30T15:00:00.log"
    file_content = b"hello from a colon-named file"

    # Build a mock S3 response whose Body.read() supports the chunk_size argument
    # used by the streaming generator in download_file().
    body_mock = mocker.MagicMock()
    # First call returns the full content; second signals EOF.
    body_mock.read.side_effect = [file_content, b""]
    s3_mock = mocker.MagicMock()
    s3_mock.get_object.return_value = {
        "Body": body_mock,
        "ContentType": "text/plain",
    }

    def mock_execute_with_s3_retry(role_name, operation, callback):
        return callback(s3_mock)

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=mock_execute_with_s3_retry)

    # Login to obtain session cookie + CSRF token
    _, headers = login(app_client)

    # Download via API — query param carries the literal key (TestClient handles URL encoding).
    # The key point of this test is that sanitize_path no longer rejects the `:` character.
    response = app_client.get(
        "/api/buckets/test-bucket/download",
        params={"path": key_with_colon},
        headers=headers,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text[:200]}"
    assert response.content == file_content


def test_admin_cannot_demote_self(app_client):
    """An admin trying to set their own is_admin=False must be rejected."""
    _, headers = login(app_client)  # logged in as admin (default seeded admin)
    response = app_client.put(
        "/api/admin/users/admin",
        data={"is_admin": "false", "allowed_roles": ""},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "own admin rights" in response.json()["detail"].lower()


def test_admin_can_demote_other_admin(app_client):
    """Defensive: the self-demote guard must NOT block demoting OTHER admins."""
    create_user("co_admin", is_admin=True, allowed_roles=[])
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/co_admin",
        data={"is_admin": "false", "allowed_roles": ""},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    # Verify the other admin really lost the flag
    users_module = reload_users_module()
    co = next(u for u in users_module.load_users()["users"] if u["username"] == "co_admin")
    assert co["is_admin"] is False


# ---------------------------------------------------------------------------
# PUT /api/me/password — self-service password change
# ---------------------------------------------------------------------------


def test_change_my_password_success(app_client):
    """Happy path: user changes own password, old fails, new works."""
    create_user("alice", password="OldPass123")
    # Login as alice and grab CSRF
    login_resp = app_client.post("/api/login", data={"username": "alice", "password": "OldPass123"})
    assert login_resp.status_code == status.HTTP_200_OK
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    # Change password
    response = app_client.put(
        "/api/me/password",
        json={"current_password": "OldPass123", "new_password": "NewPass456"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK, response.text
    assert response.json() == {"ok": True}

    # Logout (clear cookie jar)
    app_client.post("/api/logout")
    app_client.cookies.clear()

    # Old password no longer works
    bad = app_client.post("/api/login", data={"username": "alice", "password": "OldPass123"})
    assert bad.status_code == status.HTTP_401_UNAUTHORIZED

    # New password works
    good = app_client.post("/api/login", data={"username": "alice", "password": "NewPass456"})
    assert good.status_code == status.HTTP_200_OK


def test_change_my_password_wrong_current(app_client):
    """Wrong current_password → 401 with detail mentioning 'current password'."""
    create_user("bob", password="bobpass")
    login_resp = app_client.post("/api/login", data={"username": "bob", "password": "bobpass"})
    assert login_resp.status_code == status.HTTP_200_OK
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    response = app_client.put(
        "/api/me/password",
        json={"current_password": "wrong", "new_password": "newpass"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "current password" in response.json()["detail"].lower()


def test_change_my_password_same_password(app_client):
    """new_password equal to current_password → 400 with detail mentioning 'differ'."""
    create_user("carol", password="samepass")
    login_resp = app_client.post("/api/login", data={"username": "carol", "password": "samepass"})
    assert login_resp.status_code == status.HTTP_200_OK
    csrf = app_client.get("/api/me").json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    response = app_client.put(
        "/api/me/password",
        json={"current_password": "samepass", "new_password": "samepass"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "differ" in response.json()["detail"].lower()


def test_change_my_password_unauthenticated(app_client):
    """No auth cookie → 401 (get_current_user runs before CSRF check)."""
    response = app_client.put(
        "/api/me/password",
        json={"current_password": "x", "new_password": "y"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_change_my_password_no_csrf(app_client):
    """Logged in but no X-CSRF-Token header → 403."""
    create_user("dave", password="davepass")
    login_resp = app_client.post("/api/login", data={"username": "dave", "password": "davepass"})
    assert login_resp.status_code == status.HTTP_200_OK

    response = app_client.put(
        "/api/me/password",
        json={"current_password": "davepass", "new_password": "newpass"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_can_clear_user_allowed_roles(app_client):
    """Regression: PUT /api/admin/users/{u} with allowed_roles= must clear all roles.

    FastAPI's `Optional[str] = Form(None)` coerces empty form values to None,
    making it impossible to distinguish 'field omitted' from 'field present
    but empty'. The endpoint reads request.form() directly and treats
    presence-of-key as 'client wants to set roles'.
    """
    create_user("alice", password="OldPass123", is_admin=False, allowed_roles=["RoleA", "RoleB"])
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/alice",
        data={"is_admin": "false", "allowed_roles": ""},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    users = app_client.get("/api/admin/users", headers=headers).json()["users"]
    alice = next(u for u in users if u["username"] == "alice")
    assert alice["allowed_roles"] == [], f"expected [], got {alice['allowed_roles']}"


def test_admin_can_partially_update_user_omitting_roles(app_client):
    """If allowed_roles key is absent, existing roles must be preserved."""
    create_user("alice", password="OldPass123", is_admin=False, allowed_roles=["RoleA"])
    _, headers = login(app_client)
    # Send only is_admin, no allowed_roles field at all
    response = app_client.put("/api/admin/users/alice", data={"is_admin": "true"}, headers=headers)
    assert response.status_code == 200

    users = app_client.get("/api/admin/users", headers=headers).json()["users"]
    alice = next(u for u in users if u["username"] == "alice")
    assert alice["is_admin"] is True
    assert alice["allowed_roles"] == ["RoleA"], "roles must be preserved when key absent"


def test_admin_empty_is_admin_field_does_not_demote_target(app_client):
    """Regression: PUT /api/admin/users/{u} with is_admin= (empty value) must NOT
    silently demote the target. FastAPI form parsing returns empty string (not None)
    for an empty multipart field, so a naive `is not None` guard wrongly evaluates
    str("") .lower() != "true" → False and clears admin rights for ANY non-self
    administrator. This was a curl/Postman exploit before the fix.
    """
    create_user("other_admin", password="OldPass123", is_admin=True, allowed_roles=[])
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/other_admin",
        data={"is_admin": "", "allowed_roles": ""},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    users = app_client.get("/api/admin/users", headers=headers).json()["users"]
    other = next(u for u in users if u["username"] == "other_admin")
    assert other["is_admin"] is True, "target admin must NOT be demoted on empty is_admin="


# ---------------------------------------------------------------------------
# MCP config fields (Phase 5, Task 6)
# ---------------------------------------------------------------------------


def test_get_config_includes_mcp_fields(app_client):
    """GET /api/config must expose all 4 MCP fields to the admin."""
    _, headers = login(app_client)
    resp = app_client.get("/api/config", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "mcp_enabled" in body
    assert "mcp_disable_writes" in body
    assert "mcp_text_extensions" in body
    assert "mcp_global_max_read_bytes" in body


def test_post_config_persists_mcp_fields(app_client):
    """POST /api/config must accept and persist all 4 MCP fields."""
    _, headers = login(app_client)
    initial = app_client.get("/api/config", headers=headers).json()
    initial["mcp_enabled"] = False
    initial["mcp_disable_writes"] = True
    initial["mcp_text_extensions"] = ["custom"]
    initial["mcp_global_max_read_bytes"] = 2_097_152
    resp = app_client.post("/api/config", json=initial, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_enabled"] is False
    assert after["mcp_disable_writes"] is True
    assert after["mcp_text_extensions"] == ["custom"]
    assert after["mcp_global_max_read_bytes"] == 2_097_152


def test_post_config_validates_mcp_global_max_read_bytes_range(app_client):
    """POST /api/config must reject mcp_global_max_read_bytes > 10MB."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_global_max_read_bytes"] = 999_999_999
    resp = app_client.post("/api/config", json=cfg, headers=headers)
    assert resp.status_code == 422


def test_post_config_preserves_mcp_fields_when_omitted(app_client):
    """POST /api/config without MCP fields must preserve previously saved values."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_enabled"] = False
    app_client.post("/api/config", json=cfg, headers=headers)
    # Submit same payload but without mcp_enabled key
    minimal = {k: v for k, v in cfg.items() if k != "mcp_enabled"}
    resp = app_client.post("/api/config", json=minimal, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_enabled"] is False  # preserved from previous POST


# ---------------------------------------------------------------------------
# MCP kill-switch middleware
# ---------------------------------------------------------------------------


def test_mcp_kill_switch_blocks_when_disabled(app_client, monkeypatch):
    """When mcp_enabled=False in config, /mcp/* returns 503."""
    import another_s3_manager.config as config_module

    original_load = config_module.load_config

    def _disabled_config(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        cfg["mcp_enabled"] = False
        return cfg

    monkeypatch.setattr(config_module, "load_config", _disabled_config)
    resp = app_client.get("/mcp/anything")
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "MCP_DISABLED"


def test_mcp_kill_switch_allows_when_enabled(app_client):
    """Default is mcp_enabled=True. /mcp/* should NOT return 503 from kill-switch."""
    resp = app_client.get("/mcp/anything")
    # MCP routing may return 404/405/etc. — any status except 503 is acceptable.
    assert resp.status_code != 503


# --- /api/buckets/{b}/presigned ---


def test_presigned_endpoint_happy_path(app_client, mocker):
    """Allowed role + bucket + existing path returns 200 with url + expires_at."""
    _, _ = login(app_client)

    mocker.patch(
        "another_s3_manager.main.validate_role_access",
        return_value="default-role",
    )
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://bucket.s3.amazonaws.com/file.txt?X-Amz-Signature=abc",
    )

    response = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "default-role", "path": "file.txt"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["url"].startswith("https://")
    assert "X-Amz-Signature" in body["url"]
    assert "expires_at" in body
    # Parses as ISO8601 with timezone info
    from datetime import datetime

    datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))


def test_presigned_endpoint_permission_denied(app_client, mocker):
    """PermissionError from helper → 403."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=PermissionError("Bucket not allowed for role"),
    )

    response = app_client.get(
        "/api/buckets/forbidden/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 403


def test_presigned_endpoint_not_found(app_client, mocker):
    """FileNotFoundError → 404."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=FileNotFoundError("not there"),
    )

    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "missing.txt"},
    )
    assert response.status_code == 404


def test_presigned_endpoint_invalid_op(app_client):
    """Only op=get supported in v1."""
    _, _ = login(app_client)
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt", "op": "put"},
    )
    assert response.status_code == 400


def test_presigned_endpoint_requires_auth(app_client):
    """Anonymous request → 401."""
    app_client.cookies.clear()
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 401


def test_presigned_endpoint_requires_role_param(app_client):
    """Omitting `role` query param → 422 (FastAPI validation)."""
    _, _ = login(app_client)
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"path": "x.txt"},
    )
    assert response.status_code == 422


def test_presigned_endpoint_boto_error_returns_500(app_client, mocker):
    """ClientError from helper (e.g. STS assume_role failure) → 500 with formatted message."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "STS token expired"}},
            "AssumeRole",
        ),
    )

    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 500
    # format_boto_error produces a user-friendly message rather than raw repr
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)


def test_to_http_exception_uses_typed_status_and_dict_detail():
    """_s3_error_to_http maps each typed S3 error to its http_status + structured detail."""
    from fastapi import HTTPException

    from another_s3_manager.errors import S3AccessDeniedError, S3NotFoundError
    from another_s3_manager.main import _s3_error_to_http

    err = S3AccessDeniedError("AccessDenied", "no perms")
    http = _s3_error_to_http(err)
    assert isinstance(http, HTTPException)
    assert http.status_code == 403
    assert http.detail == {"code": "AccessDenied", "message": "no perms"}

    nf = S3NotFoundError("NoSuchBucket", "missing")
    http2 = _s3_error_to_http(nf)
    assert http2.status_code == 404
    assert http2.detail == {"code": "NoSuchBucket", "message": "missing"}


def test_list_buckets_typed_access_denied_returns_403_with_dict_detail(app_client, mocker):
    """When the s3_client probe / op raises S3AccessDeniedError, /api/buckets
    returns 403 with detail={'code': 'AccessDenied', 'message': '...'}."""
    from another_s3_manager.errors import S3AccessDeniedError

    def _boom(role_name, operation, callback):
        raise S3AccessDeniedError("AccessDenied", "scoped token cannot list")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=_boom)
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets", headers=headers)
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "AccessDenied"
    assert "scoped token cannot list" in body["detail"]["message"]


def test_list_files_typed_no_such_bucket_returns_404_with_dict_detail(app_client, mocker):
    """list_files maps S3NotFoundError to 404 with structured detail."""
    from another_s3_manager.errors import S3NotFoundError

    def _boom(role_name, operation, callback):
        raise S3NotFoundError("NoSuchBucket", "bucket missing")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=_boom)
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets/missing-bucket/files", headers=headers)
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["code"] == "NoSuchBucket"
    assert body["detail"]["message"] == "bucket missing"


def test_list_files_generic_exception_logs_and_returns_500(app_client, mocker, caplog):
    """Generic uncaught Exception in list_files: response is 500 with INTERNAL,
    AND the server logs include the stack trace (was missing before)."""
    import logging

    def _boom(role_name, operation, callback):
        raise RuntimeError("totally unexpected")

    mocker.patch("another_s3_manager.main.execute_with_s3_retry", side_effect=_boom)
    _, headers = login(app_client)

    with caplog.at_level(logging.ERROR, logger="another_s3_manager.main"):
        resp = app_client.get("/api/buckets/some/files", headers=headers)

    assert resp.status_code == 500
    # Must contain the stack trace (logger.exception writes ERROR level + exc_info).
    assert any("totally unexpected" in record.message or record.exc_info is not None for record in caplog.records)
