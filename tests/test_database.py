"""Tests for the SQLAlchemy engine + session_scope() context manager."""

import pytest
from sqlalchemy import text


def test_get_engine_creates_sqlite_engine(monkeypatch, tmp_path):
    """get_engine() returns a working SQLite engine using DATA_DIR."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    assert engine is not None
    # Sanity: can execute a trivial query
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
        assert result == 1


def test_session_scope_commits_on_success(monkeypatch, tmp_path):
    """session_scope() commits when block exits without error."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (val INTEGER)"))

    with database.session_scope() as session:
        session.execute(text("INSERT INTO t (val) VALUES (42)"))

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT val FROM t")).fetchall()
        assert rows == [(42,)]


def test_session_scope_rolls_back_on_exception(monkeypatch, tmp_path):
    """session_scope() rolls back when the block raises."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (val INTEGER)"))
        conn.execute(text("INSERT INTO t (val) VALUES (1)"))

    with pytest.raises(RuntimeError, match="boom"):
        with database.session_scope() as session:
            session.execute(text("INSERT INTO t (val) VALUES (2)"))
            raise RuntimeError("boom")

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT val FROM t ORDER BY val")).fetchall()
        assert rows == [(1,)]  # the (2,) insert was rolled back
