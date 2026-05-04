"""SQLAlchemy engine and session management.

Sync engine for SQLite. Used by users.py and migration.py.
The engine is module-level (lazy-initialized) so callers don't pass it around.
"""

import threading
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
