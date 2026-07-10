"""SQLAlchemy engine and session management.

Sync engine for SQLite. Used by users.py and migration.py.
The engine is module-level (lazy-initialized) so callers don't pass it around.
"""

import threading
import time
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from another_s3_manager.constants import get_db_path


@event.listens_for(Engine, "connect")
def _enable_sqlite_fk(dbapi_connection, _connection_record):
    # SQLite ships with FK enforcement OFF by default — we need it ON
    # so DB-level ON DELETE CASCADE actually works.
    if dbapi_connection.__class__.__module__.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker[Session]] = None
_init_lock = threading.Lock()


def _register_query_metrics(engine: Engine) -> None:
    """Emit as3m_db_query_duration_seconds for every SQLAlchemy query."""
    from another_s3_manager.metrics import db_query_duration_seconds

    @event.listens_for(engine, "before_cursor_execute")
    def _q_start(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        conn.info["_q_start"] = time.perf_counter()

    @event.listens_for(engine, "after_cursor_execute")
    def _q_end(conn, cursor, statement, parameters, context, executemany):  # noqa: ARG001
        start = conn.info.pop("_q_start", time.perf_counter())
        duration = time.perf_counter() - start
        op = statement.lstrip().split(" ", 1)[0].upper() if statement else "OTHER"
        if op not in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            op = "OTHER"
        db_query_duration_seconds.labels(operation=op).observe(duration)


def get_engine() -> Engine:
    """Lazy-initialize the module-level engine. Thread-safe via double-checked locking."""
    global _engine, _SessionLocal
    if _engine is None:
        with _init_lock:
            if _engine is None:  # double-checked locking — re-check after acquiring lock
                db_path = get_db_path()
                # check_same_thread=False — FastAPI sync deps run in a threadpool
                _engine = create_engine(
                    f"sqlite:///{db_path}",
                    connect_args={"check_same_thread": False},
                    future=True,
                )
                _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False, future=True)
                _register_query_metrics(_engine)
    return _engine


def reset_engine_for_tests() -> None:
    """Tests reload the module — wipe cached engine to honor monkeypatched env.

    Best-effort cleanup: dispose() failures are swallowed so the next test gets a fresh engine.
    """
    global _engine, _SessionLocal
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass  # best-effort cleanup in test context
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    get_engine()  # ensure _SessionLocal is initialized
    # Invariant: get_engine() always sets _SessionLocal; assert satisfies the type checker
    assert _SessionLocal is not None  # noqa: S101
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
