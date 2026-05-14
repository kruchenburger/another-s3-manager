"""Tests for the first-login forced password change feature (Phase 6a-8)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


def test_users_table_has_must_change_password_column():
    """Migration must add a non-nullable boolean `must_change_password` column."""
    inspector = inspect(get_engine())
    columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "must_change_password" in columns, "must_change_password column missing"
    assert columns["must_change_password"]["nullable"] is False, "must_change_password must be NOT NULL"
