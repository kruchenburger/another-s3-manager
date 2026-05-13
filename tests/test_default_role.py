"""Tests for the per-user default role feature (Phase 6a-4)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


def test_users_table_has_default_role_column():
    """Migration must add a nullable `default_role` column to `users`."""
    inspector = inspect(get_engine())
    columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "default_role" in columns, "default_role column missing from users table"
    assert columns["default_role"]["nullable"] is True, "default_role must be nullable"


def test_create_user_auto_sets_default_role_when_single_allowed_role(app_client):
    """create_user(allowed_roles=[X]) should set default_role=X automatically."""
    from another_s3_manager import users

    user = users.create_user(
        username="solo",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    assert user["default_role"] == "RoleA", user


def test_create_user_does_not_auto_set_default_role_when_multiple_allowed_roles(app_client):
    """Multiple roles → no auto-default; user must pick explicitly."""
    from another_s3_manager import users

    user = users.create_user(
        username="multi",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    assert user["default_role"] is None, user


def test_update_user_clears_default_role_when_no_longer_in_allowed_roles(app_client):
    """If admin removes the role that is the user's default, fall back to the first remaining."""
    from another_s3_manager import users

    users.create_user(
        username="shifter",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    users.update_user("shifter", default_role="RoleA")
    updated = users.update_user("shifter", allowed_roles=["RoleB", "RoleC"])
    assert updated["default_role"] == "RoleB", updated


def test_update_user_accepts_explicit_default_role(app_client):
    """update_user(default_role=X) sets the explicit choice."""
    from another_s3_manager import users

    users.create_user(
        username="picker",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    updated = users.update_user("picker", default_role="RoleB")
    assert updated["default_role"] == "RoleB"
