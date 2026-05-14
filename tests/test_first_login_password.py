"""Tests for the first-login forced password change feature (Phase 6a-8)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


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
