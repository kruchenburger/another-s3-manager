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
        for sample in metrics.db_query_duration_seconds.collect()[0].samples:
            if sample.name.endswith("_count") and sample.labels.get("operation") == op:
                return sample.value
        return 0.0

    before = count("SELECT")
    with session_scope() as s:
        s.execute(select(User).limit(1))
    after = count("SELECT")
    assert after >= before + 1


def test_journal_mode_is_wal_on_real_connection(monkeypatch, tmp_path):
    """The pragma listener must actually flip SQLite into WAL — not merely fire.

    Asserts the *effect* (PRAGMA journal_mode read back from a real connection),
    not that the listener ran.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.connect() as conn:
        mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
    assert mode is not None and mode.lower() == "wal"


def test_busy_timeout_is_set(monkeypatch, tmp_path):
    """PRAGMA busy_timeout must be a positive value, not SQLite's default of 0."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.connect() as conn:
        timeout_ms = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
    assert timeout_ms == database._BUSY_TIMEOUT_MS
    assert timeout_ms > 0


def test_wal_reader_not_blocked_by_uncommitted_exclusive_writer(monkeypatch, tmp_path):
    """The whole point of enabling WAL: a reader is never blocked by an in-flight
    writer, even one holding SQLite's strongest (EXCLUSIVE) write lock.

    Uses raw sqlite3 connections (not the SQLAlchemy engine) so the writer and
    reader are independent connections to the same on-disk file, and forces
    BEGIN EXCLUSIVE rather than a plain uncommitted write: an ordinary write only
    takes SQLite's true EXCLUSIVE lock for a few microseconds at COMMIT time,
    which is too timing-dependent to assert on reliably in a single-threaded
    test. BEGIN EXCLUSIVE holds that lock for the whole transaction, making the
    scenario deterministic instead of racy.

    The reader sets busy_timeout=0 so success can only mean "was never blocked",
    not "blocked, then waited it out" — a slower false negative would show up as
    an OperationalError here, not a flaky pass.
    """
    import sqlite3

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE wal_probe (val INTEGER)")

    db_path = str(constants.get_db_path())
    writer = sqlite3.connect(db_path)
    reader = sqlite3.connect(db_path)
    try:
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute("INSERT INTO wal_probe (val) VALUES (1)")
        # writer transaction is deliberately left open (uncommitted) here

        reader.execute("PRAGMA busy_timeout=0")
        row = reader.execute("SELECT COUNT(*) FROM wal_probe").fetchone()
        # Under WAL the reader sees a stable pre-transaction snapshot and is
        # never blocked — it must succeed, and must not see the uncommitted row.
        assert row == (0,)
    finally:
        writer.rollback()
        writer.close()
        reader.close()


def test_delete_mode_reader_blocked_by_exclusive_writer(monkeypatch, tmp_path):
    """Contrast case proving the WAL test above genuinely discriminates: the exact
    same reader-vs-uncommitted-EXCLUSIVE-writer scenario DOES fail under SQLite's
    default (DELETE / rollback-journal) mode, which is what SQLITE_JOURNAL_MODE=delete
    opts an operator back into.
    """
    import sqlite3

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SQLITE_JOURNAL_MODE", "delete")
    import importlib

    from another_s3_manager import constants, database

    importlib.reload(constants)
    importlib.reload(database)

    engine = database.get_engine()
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE wal_probe (val INTEGER)")
        mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
    assert mode.lower() == "delete"  # sanity: this run really is in rollback-journal mode

    db_path = str(constants.get_db_path())
    writer = sqlite3.connect(db_path)
    reader = sqlite3.connect(db_path)
    try:
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute("INSERT INTO wal_probe (val) VALUES (1)")

        reader.execute("PRAGMA busy_timeout=0")
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            reader.execute("SELECT COUNT(*) FROM wal_probe")
    finally:
        writer.rollback()
        writer.close()
        reader.close()


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
