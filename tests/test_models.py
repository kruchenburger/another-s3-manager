"""Tests for ORM models — schema, defaults, cascades, constraints."""

import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from another_s3_manager.models import Ban, Base, User, UserRole


@pytest.fixture
def session():
    """Fresh in-memory SQLite + all tables, isolated per test."""
    engine = create_engine("sqlite:///:memory:", future=True)
    # SQLite needs FKs explicitly enabled per connection
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    s = Session()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def test_user_minimal_create(session):
    user = User(username="alice", password_hash="hash")
    session.add(user)
    session.commit()
    assert user.id is not None
    assert user.is_admin is False
    assert user.theme == "auto"
    assert user.created_at is not None
    assert user.updated_at is not None


def test_user_username_unique(session):
    session.add(User(username="alice", password_hash="h1"))
    session.commit()
    session.add(User(username="alice", password_hash="h2"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_user_role_unique_per_user(session):
    user = User(username="alice", password_hash="h")
    session.add(user)
    session.commit()
    session.add(UserRole(user_id=user.id, role_name="readonly"))
    session.commit()
    session.add(UserRole(user_id=user.id, role_name="readonly"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_user_roles_cascade_delete(session):
    user = User(username="alice", password_hash="h")
    session.add(user)
    session.commit()
    session.add_all(
        [
            UserRole(user_id=user.id, role_name="r1"),
            UserRole(user_id=user.id, role_name="r2"),
        ]
    )
    session.commit()

    session.delete(user)
    session.commit()

    assert session.query(UserRole).count() == 0


def test_ban_one_per_user(session):
    user = User(username="alice", password_hash="h")
    session.add(user)
    session.commit()
    now = time.time()
    session.add(Ban(user_id=user.id, banned_until=now + 3600, banned_at=now))
    session.commit()
    session.add(Ban(user_id=user.id, banned_until=now + 7200, banned_at=now))
    with pytest.raises(IntegrityError):
        session.commit()


def test_ban_cascade_delete_with_user(session):
    user = User(username="alice", password_hash="h")
    session.add(user)
    session.commit()
    now = time.time()
    session.add(Ban(user_id=user.id, banned_until=now + 3600, banned_at=now))
    session.commit()

    session.delete(user)
    session.commit()

    assert session.query(Ban).count() == 0


def test_updated_at_changes_on_update(session):
    user = User(username="alice", password_hash="h")
    session.add(user)
    session.commit()
    original_updated = user.updated_at

    # Sleep enough to register a difference at the second-precision level
    time.sleep(1.1)
    user.theme = "dark"
    session.commit()
    session.refresh(user)
    assert user.updated_at > original_updated


def test_api_token_model_basic_columns():
    """Verify ApiToken model has the columns the spec defines."""
    from another_s3_manager.models import ApiToken

    cols = {c.name for c in ApiToken.__table__.columns}
    assert cols == {
        "id", "user_id", "token_hash", "name",
        "created_at", "last_used_at", "revoked_at",
        "is_read_only", "max_read_bytes",
    }


def test_api_token_unique_user_name_constraint():
    from another_s3_manager.models import ApiToken

    constraint_names = {c.name for c in ApiToken.__table__.constraints}
    assert "uq_api_token_user_name" in constraint_names


def test_api_token_check_max_read_bytes_constraint():
    from another_s3_manager.models import ApiToken

    constraint_names = {c.name for c in ApiToken.__table__.constraints}
    assert "ck_api_token_max_read_bytes_range" in constraint_names


def test_api_token_user_relationship_cascade():
    from another_s3_manager.models import User
    rel = User.__mapper__.relationships["api_tokens"]
    # delete-orphan semantics: deleting a User must delete their tokens
    assert "delete-orphan" in rel.cascade


def test_api_token_token_hash_indexed_unique():
    """token_hash is the hot-path lookup column — must be indexed AND unique."""
    from another_s3_manager.models import ApiToken
    col = ApiToken.__table__.columns["token_hash"]
    assert col.unique is True
    assert col.index is True
