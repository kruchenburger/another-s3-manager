"""Tests for the per-user default role feature (Phase 6a-4)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


def test_users_table_has_default_role_column():
    """Migration must add a nullable `default_role` column to `users`."""
    inspector = inspect(get_engine())
    columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "default_role" in columns, "default_role column missing from users table"
    assert columns["default_role"]["nullable"] is True, "default_role must be nullable"
