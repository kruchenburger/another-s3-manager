"""Tests for the first-login forced password change feature (Phase 6a-8)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


def _test_password_hash() -> str:
    from another_s3_manager.auth import hash_password

    return hash_password("test-password-1A")


def _login_as(client, username: str) -> None:
    login_response = client.post(
        "/api/login",
        data={"username": username, "password": "test-password-1A"},
    )
    assert login_response.status_code == 200, login_response.text
    me_response = client.get("/api/me")
    assert me_response.status_code == 200, me_response.text
    csrf = me_response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf


def test_users_table_has_must_change_password_column():
    """Migration must add a non-nullable boolean `must_change_password` column."""
    inspector = inspect(get_engine())
    columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "must_change_password" in columns, "must_change_password column missing"
    assert columns["must_change_password"]["nullable"] is False, "must_change_password must be NOT NULL"


def test_create_user_defaults_must_change_password_true(app_client):
    """create_user without explicit kwarg defaults must_change_password=True (paranoid default)."""
    from another_s3_manager import users

    user = users.create_user(
        username="newcomer",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    assert user["must_change_password"] is True, user


def test_create_user_accepts_explicit_must_change_password_false(app_client):
    """Admin can opt out of the forced change (service accounts / test users)."""
    from another_s3_manager import users

    user = users.create_user(
        username="service",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
        must_change_password=False,
    )
    assert user["must_change_password"] is False, user


def test_update_user_accepts_must_change_password(app_client):
    """update_user(must_change_password=False) clears the flag."""
    from another_s3_manager import users

    users.create_user(
        username="changer",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    updated = users.update_user("changer", must_change_password=False)
    assert updated["must_change_password"] is False


def test_save_users_preserves_must_change_password(app_client):
    """Admin bulk-upsert must preserve the flag."""
    from another_s3_manager import users

    users.create_user(
        username="bulkguy",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )

    users.save_users(
        {
            "users": [
                {
                    "username": "bulkguy",
                    "password_hash": "hash-irrelevant",
                    "is_admin": False,
                    "theme": "auto",
                    "allowed_roles": ["RoleA", "RoleB"],
                    "must_change_password": True,
                }
            ]
        }
    )

    me = users.get_user_by_username("bulkguy")
    assert me["must_change_password"] is True


def test_api_me_returns_must_change_password(app_client):
    """GET /api/me must include the must_change_password flag."""
    from another_s3_manager import users

    users.create_user(
        username="freshie",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    # create_user defaults must_change_password=True (Task 3).

    _login_as(app_client, "freshie")
    response = app_client.get("/api/me")
    assert response.status_code == 200
    body = response.json()
    assert body["must_change_password"] is True, body


def test_self_password_change_clears_must_change_password(app_client):
    """After PUT /api/me/password the flag must flip to False."""
    from another_s3_manager import users

    users.create_user(
        username="resetter",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    _login_as(app_client, "resetter")
    # Confirm flag is True initially (from Task 3 default).
    assert app_client.get("/api/me").json()["must_change_password"] is True

    response = app_client.put(
        "/api/me/password",
        json={
            "current_password": "test-password-1A",
            "new_password": "fresh-pass-1A!",
        },
    )
    assert response.status_code == 200, response.text

    # /api/me now shows False.
    me = app_client.get("/api/me").json()
    assert me["must_change_password"] is False, me


def test_self_password_change_with_wrong_current_does_not_clear_flag(app_client):
    """Failed password change must NOT clear the flag."""
    from another_s3_manager import users

    users.create_user(
        username="failer",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    _login_as(app_client, "failer")

    response = app_client.put(
        "/api/me/password",
        json={
            "current_password": "wrong-password-1A",
            "new_password": "anything-fresh-1A!",
        },
    )
    assert response.status_code == 401

    me = app_client.get("/api/me").json()
    assert me["must_change_password"] is True, "flag must not change on auth failure"


def test_admin_reset_password_default_sets_must_change_password_true(app_client):
    """Admin reset without explicit flag defaults to True."""
    from another_s3_manager import users

    # Trigger admin seeding before adding another user.
    users.load_users()

    users.create_user(
        username="target_default",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    users.update_user("target_default", must_change_password=False)
    assert users.get_user_by_username("target_default")["must_change_password"] is False

    # Log in as admin (password set by ADMIN_PASSWORD env which defaults to admin123 in tests).
    app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    csrf = app_client.get("/api/me").json()["csrf_token"]
    app_client.headers["X-CSRF-Token"] = csrf

    # Admin resets without specifying must_change_password — default = True.
    response = app_client.put(
        "/api/admin/users/target_default/password",
        json={"password": "admin-reset-1A!"},
    )
    assert response.status_code == 200, response.text

    target = users.get_user_by_username("target_default")
    assert target["must_change_password"] is True, target


def test_admin_reset_password_can_opt_out(app_client):
    """Admin can explicitly set must_change_password=False (service account use case)."""
    from another_s3_manager import users

    # Trigger admin seeding before adding another user.
    users.load_users()

    users.create_user(
        username="target_optout",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    users.update_user("target_optout", must_change_password=False)

    # Log in as admin (password set by ADMIN_PASSWORD env which defaults to admin123 in tests).
    app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    csrf = app_client.get("/api/me").json()["csrf_token"]
    app_client.headers["X-CSRF-Token"] = csrf

    # Admin resets with explicit must_change_password=False.
    response = app_client.put(
        "/api/admin/users/target_optout/password",
        json={"password": "admin-reset-1A!", "must_change_password": False},
    )
    assert response.status_code == 200, response.text

    target = users.get_user_by_username("target_optout")
    assert target["must_change_password"] is False, target


def test_admin_create_user_default_sets_must_change_password_true(app_client):
    """POST /api/admin/users without explicit flag defaults must_change_password=True."""
    from another_s3_manager import users

    # Force admin seeding via load_users() (test conftest pattern).
    users.load_users()

    # Log in as admin.
    app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    csrf = app_client.get("/api/me").json()["csrf_token"]
    app_client.headers["X-CSRF-Token"] = csrf

    response = app_client.post(
        "/api/admin/users",
        data={
            "username": "freshcreated",
            "password": "fresh-create-1A!",
            "is_admin": "false",
            "allowed_roles": "",
        },
    )
    assert response.status_code == 200, response.text

    new_user = users.get_user_by_username("freshcreated")
    assert new_user["must_change_password"] is True, new_user


def test_admin_create_user_can_opt_out(app_client):
    """Admin can opt out via form field (service account use case)."""
    from another_s3_manager import users

    users.load_users()

    app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    csrf = app_client.get("/api/me").json()["csrf_token"]
    app_client.headers["X-CSRF-Token"] = csrf

    response = app_client.post(
        "/api/admin/users",
        data={
            "username": "servicecreated",
            "password": "service-create-1A!",
            "is_admin": "false",
            "allowed_roles": "",
            "must_change_password": "false",
        },
    )
    assert response.status_code == 200, response.text

    new_user = users.get_user_by_username("servicecreated")
    assert new_user["must_change_password"] is False, new_user
