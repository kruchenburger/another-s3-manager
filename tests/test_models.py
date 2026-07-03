"""Tests for ORM models — schema, defaults, cascades, constraints."""

import hashlib
import time

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from another_s3_manager.models import ApiToken, Ban, Base, User, UserRole


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
        "id",
        "user_id",
        "token_hash",
        "name",
        "created_at",
        "last_used_at",
        "revoked_at",
        "is_read_only",
        "max_read_bytes",
    }


def test_api_token_unique_active_user_name_partial_index():
    """Name uniqueness is a PARTIAL index (active tokens only): revoke is a
    soft delete, so revoked tokens must not block their name from reuse."""
    from another_s3_manager.models import ApiToken

    idx = next(
        (i for i in ApiToken.__table__.indexes if i.name == "uq_api_token_user_name_active"),
        None,
    )
    assert idx is not None
    assert idx.unique is True
    assert [c.name for c in idx.columns] == ["user_id", "name"]
    # The partial predicate is what makes revoked names reusable.
    assert "revoked_at IS NULL" in str(idx.dialect_options["sqlite"]["where"])
    # The old absolute constraint must be gone.
    constraint_names = {c.name for c in ApiToken.__table__.constraints}
    assert "uq_api_token_user_name" not in constraint_names


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


def test_api_token_user_id_indexed():
    """user_id is the lookup column for list_tokens_for_user — must be indexed."""
    from another_s3_manager.models import ApiToken

    col = ApiToken.__table__.columns["user_id"]
    assert col.index is True


def test_api_token_cascades_when_user_deleted(session):
    """Deleting a user must cascade-delete their api_tokens at the DB level (FK ON DELETE CASCADE).

    This test uses the session fixture which enables PRAGMA foreign_keys=ON,
    proving the cascade works at the DB layer — not just via ORM cascade logic.
    """
    user = User(username="cascade_user", password_hash="x", is_admin=False)
    session.add(user)
    session.flush()

    token = ApiToken(
        user_id=user.id,
        token_hash=hashlib.sha256(b"test-cascade").hexdigest(),
        name="cascade-token",
        is_read_only=True,
        max_read_bytes=1024,
    )
    session.add(token)
    session.flush()
    token_id = token.id

    # Delete user — FK ON DELETE CASCADE must remove the token at DB level
    session.delete(user)
    session.commit()

    remaining = session.execute(select(func.count(ApiToken.id)).where(ApiToken.id == token_id)).scalar_one()
    assert remaining == 0


def test_api_token_max_read_bytes_check_rejects_zero_and_above_ceiling(session):
    """CHECK constraint must reject max_read_bytes <= 0 and > 10MB, accept exactly 10MB."""
    user = User(username="check_user", password_hash="x", is_admin=False)
    session.add(user)
    session.flush()
    user_id = user.id

    # Below range: 0 must be rejected
    with pytest.raises(IntegrityError):
        session.add(
            ApiToken(
                user_id=user_id,
                token_hash=hashlib.sha256(b"check-below").hexdigest(),
                name="below",
                is_read_only=True,
                max_read_bytes=0,
            )
        )
        session.flush()
    session.rollback()

    # Rebuild user after rollback wiped it
    user = User(username="check_user2", password_hash="x", is_admin=False)
    session.add(user)
    session.flush()
    user_id = user.id

    # Above ceiling: 10_485_761 must be rejected
    with pytest.raises(IntegrityError):
        session.add(
            ApiToken(
                user_id=user_id,
                token_hash=hashlib.sha256(b"check-above").hexdigest(),
                name="above",
                is_read_only=True,
                max_read_bytes=10_485_761,
            )
        )
        session.flush()
    session.rollback()

    # Rebuild user again after second rollback
    user = User(username="check_user3", password_hash="x", is_admin=False)
    session.add(user)
    session.flush()
    user_id = user.id

    # Exactly at ceiling: 10_485_760 must succeed
    session.add(
        ApiToken(
            user_id=user_id,
            token_hash=hashlib.sha256(b"check-ceiling").hexdigest(),
            name="at-ceiling",
            is_read_only=True,
            max_read_bytes=10_485_760,
        )
    )
    session.flush()  # must not raise
