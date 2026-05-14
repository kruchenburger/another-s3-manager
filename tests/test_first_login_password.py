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
