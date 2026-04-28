"""SQLAlchemy engine and session management.

Sync engine for SQLite. Used by users.py and migration.py.
The engine is module-level (lazy-initialized) so callers don't pass it around.
"""

from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from another_s3_manager.constants import get_db_path

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker[Session]] = None


def get_engine() -> Engine:
    """Lazy-initialize the module-level engine."""
    global _engine, _SessionLocal
    if _engine is None:
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
    """Tests reload the module — wipe cached engine to honor monkeypatched env."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    get_engine()  # ensure _SessionLocal is initialized
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
