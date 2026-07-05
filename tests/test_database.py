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


def test_get_engine_is_idempotent(monkeypatch, tmp_path):
    """Calling get_engine() twice returns the same engine (module-level singleton)."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine1 = database.get_engine()
    engine2 = database.get_engine()
    assert engine1 is engine2


def test_sqlite_foreign_keys_pragma_is_enabled():
    """Production engine must enable PRAGMA foreign_keys so DB-level CASCADE works."""
    from sqlalchemy import text

    from another_s3_manager.database import session_scope

    with session_scope() as session:
        result = session.execute(text("PRAGMA foreign_keys")).scalar()
        assert result == 1, "FK enforcement should be ON for SQLite"


def test_db_query_metric_records_select():
    from sqlalchemy import select

    from another_s3_manager import metrics
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    def count(op: str) -> float:
        for sample in metrics.app_db_query_duration_seconds.collect()[0].samples:
            if sample.name.endswith("_count") and sample.labels.get("operation") == op:
                return sample.value
        return 0.0

    before = count("SELECT")
    with session_scope() as s:
        s.execute(select(User).limit(1))
    after = count("SELECT")
    assert after >= before + 1


def test_db_level_cascade_works_in_production_engine():
    """Raw SQL DELETE on a user must cascade to api_tokens via ON DELETE CASCADE."""
    import hashlib

    from sqlalchemy import func, select, text

    from another_s3_manager.database import session_scope
    from another_s3_manager.models import ApiToken, User

    with session_scope() as session:
        user = User(username="raw_cascade_user", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        user_id = user.id
        session.add(
            ApiToken(
                user_id=user_id,
                token_hash=hashlib.sha256(b"raw_test").hexdigest(),
                name="raw_t",
                is_read_only=True,
                max_read_bytes=1024,
            )
        )

    # Bypass ORM — emit raw SQL DELETE
    with session_scope() as session:
        session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})

    with session_scope() as session:
        remaining = session.execute(select(func.count(ApiToken.id)).where(ApiToken.user_id == user_id)).scalar_one()
        assert remaining == 0, "Raw SQL DELETE on user should cascade to api_tokens"
