"""Tests for api_tokens service module."""

import hashlib
import time

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.models import User


@pytest.fixture
def alice_user():
    """Insert a test user, return its id. Fixture cleans up via tx rollback in conftest."""
    with session_scope() as session:
        user = User(username="alice", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        return user.id


def test_generate_token_returns_prefixed_plaintext_and_sha256_hash():
    plaintext, digest = svc.generate_token()
    assert plaintext.startswith("as3m_")
    assert len(plaintext) > len("as3m_")
    expected = hashlib.sha256(plaintext.encode()).hexdigest()
    assert digest == expected
    assert len(digest) == 64  # SHA-256 hex


def test_generate_token_produces_unique_values():
    a, _ = svc.generate_token()
    b, _ = svc.generate_token()
    assert a != b


def test_create_token_returns_row_and_plaintext(alice_user):
    token, plaintext = svc.create_token(alice_user, "Claude Desktop", is_read_only=True, max_read_bytes=1024)
    assert token.user_id == alice_user
    assert token.name == "Claude Desktop"
    assert token.is_read_only is True
    assert token.max_read_bytes == 1024
    assert token.token_hash == hashlib.sha256(plaintext.encode()).hexdigest()


def test_create_token_enforces_per_user_limit(alice_user):
    for i in range(svc.PER_USER_TOKEN_LIMIT):
        svc.create_token(alice_user, f"t{i}", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(ValueError, match="limit"):
        svc.create_token(alice_user, "overflow", is_read_only=True, max_read_bytes=1024)


def test_create_token_revoked_tokens_dont_count_toward_limit(alice_user):
    tokens = [
        svc.create_token(alice_user, f"t{i}", is_read_only=True, max_read_bytes=1024)[0]
        for i in range(svc.PER_USER_TOKEN_LIMIT)
    ]
    svc.revoke_token(tokens[0].id, by_user_id=alice_user, by_is_admin=False)
    # Should now succeed because one slot freed
    new_token, _ = svc.create_token(alice_user, "new", is_read_only=True, max_read_bytes=1024)
    assert new_token.id != tokens[0].id


def test_create_token_duplicate_name_raises(alice_user):
    svc.create_token(alice_user, "dup", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(Exception):  # IntegrityError surfaces
        svc.create_token(alice_user, "dup", is_read_only=True, max_read_bytes=1024)


def test_find_active_token_by_hash_returns_active(alice_user):
    _, plaintext = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    found = svc.find_active_token_by_hash(digest)
    assert found is not None
    assert found.user_id == alice_user


def test_find_active_token_by_hash_ignores_revoked(alice_user):
    token, plaintext = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    svc.revoke_token(token.id, by_user_id=alice_user, by_is_admin=False)
    assert svc.find_active_token_by_hash(digest) is None


def test_find_active_token_by_hash_unknown_returns_none():
    assert svc.find_active_token_by_hash("0" * 64) is None


def test_revoke_token_non_admin_cannot_revoke_others(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(PermissionError):
        svc.revoke_token(token.id, by_user_id=99999, by_is_admin=False)


def test_revoke_token_admin_can_revoke_any(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    svc.revoke_token(token.id, by_user_id=99999, by_is_admin=True)
    assert svc.find_active_token_by_hash(token.token_hash) is None


def test_touch_last_used_throttle_initial_write(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    assert token.last_used_at is None
    svc.touch_last_used(token.id, throttle_seconds=60)
    with session_scope() as session:
        from another_s3_manager.models import ApiToken

        refreshed = session.get(ApiToken, token.id)
        assert refreshed.last_used_at is not None


def test_touch_last_used_throttle_skips_within_window(alice_user):
    """Two touches within the throttle window: second is a no-op."""
    from another_s3_manager.models import ApiToken

    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    svc.touch_last_used(token.id, throttle_seconds=60)
    with session_scope() as s:
        first_ts = s.get(ApiToken, token.id).last_used_at
    time.sleep(0.05)
    svc.touch_last_used(token.id, throttle_seconds=60)
    with session_scope() as s:
        second_ts = s.get(ApiToken, token.id).last_used_at
    assert first_ts == second_ts  # not updated (within throttle)


def test_count_active_tokens_for_user_excludes_revoked(alice_user):
    t1, _ = svc.create_token(alice_user, "t1", is_read_only=True, max_read_bytes=1024)
    svc.create_token(alice_user, "t2", is_read_only=True, max_read_bytes=1024)
    svc.revoke_token(t1.id, by_user_id=alice_user, by_is_admin=False)
    assert svc.count_active_tokens_for_user(alice_user) == 1


def test_list_tokens_for_user_default_excludes_revoked(alice_user):
    t1, _ = svc.create_token(alice_user, "t1", is_read_only=True, max_read_bytes=1024)
    svc.create_token(alice_user, "t2", is_read_only=True, max_read_bytes=1024)
    svc.revoke_token(t1.id, by_user_id=alice_user, by_is_admin=False)
    active = svc.list_tokens_for_user(alice_user)
    assert len(active) == 1
    everything = svc.list_tokens_for_user(alice_user, include_revoked=True)
    assert len(everything) == 2


def test_list_all_tokens_returns_detached_objects_safe_to_read(alice_user):
    """Regression: list_all_tokens must return objects that are safely
    readable AFTER the session closes. The previous implementation called
    expunge(token) and expunge(user) separately, which raised
    InvalidRequestError when the User was already loaded into the session
    via the ApiToken.user relationship — they shared identity.

    Symptom in production: GET /api/admin/tokens returned 500 and the admin
    page rendered an empty list.
    """
    svc.create_token(alice_user, "list-all-test", is_read_only=True, max_read_bytes=1024)
    rows = svc.list_all_tokens(include_revoked=False)
    assert len(rows) >= 1
    # Caller reads attributes outside any session — must not raise.
    for token, user in rows:
        # These attribute reads would raise DetachedInstanceError if the
        # state wasn't materialized before expunge.
        assert token.name
        assert user.username
        assert token.is_read_only is True or token.is_read_only is False


# ---------------------------------------------------------------------------
# update_token — Phase 6a-1 (token edit metadata without revoke+recreate)
# ---------------------------------------------------------------------------


@pytest.fixture
def bob_user():
    """A second user for cross-user authorization tests."""
    with session_scope() as session:
        user = User(username="bob", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        return user.id


def test_update_token_rename_only(alice_user):
    token, _ = svc.create_token(alice_user, "old-name", is_read_only=True, max_read_bytes=1024)
    updated = svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False, name="new-name")
    assert updated.name == "new-name"
    assert updated.is_read_only is True
    assert updated.max_read_bytes == 1024


def test_update_token_toggle_read_only(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    updated = svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False, is_read_only=False)
    assert updated.is_read_only is False


def test_update_token_change_max_read_bytes(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    updated = svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False, max_read_bytes=2048)
    assert updated.max_read_bytes == 2048


def test_update_token_combined_fields(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    updated = svc.update_token(
        token_id=token.id,
        by_user_id=alice_user,
        by_is_admin=False,
        name="renamed",
        is_read_only=False,
        max_read_bytes=4096,
    )
    assert updated.name == "renamed"
    assert updated.is_read_only is False
    assert updated.max_read_bytes == 4096


def test_update_token_no_fields_raises(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(ValueError, match="no fields to update"):
        svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False)


def test_update_token_max_read_bytes_too_small_raises(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(ValueError, match="max_read_bytes out of range"):
        svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False, max_read_bytes=0)


def test_update_token_max_read_bytes_too_large_raises(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(ValueError, match="max_read_bytes out of range"):
        svc.update_token(
            token_id=token.id,
            by_user_id=alice_user,
            by_is_admin=False,
            max_read_bytes=10 * 1024 * 1024 + 1,
        )


def test_update_token_revoked_raises(alice_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    svc.revoke_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False)
    with pytest.raises(ValueError, match="is revoked"):
        svc.update_token(token_id=token.id, by_user_id=alice_user, by_is_admin=False, name="x")


def test_update_token_missing_raises(alice_user):
    with pytest.raises(ValueError, match="not found"):
        svc.update_token(token_id=999_999, by_user_id=alice_user, by_is_admin=False, name="x")


def test_update_token_third_party_forbidden(alice_user, bob_user):
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    with pytest.raises(PermissionError):
        svc.update_token(token_id=token.id, by_user_id=bob_user, by_is_admin=False, name="x")


def test_update_token_admin_can_edit_other_user(alice_user):
    # An admin user (separate from alice). Admin's user_id doesn't need to match owner's.
    with session_scope() as session:
        admin = User(username="admin_for_update", password_hash="x", is_admin=True)
        session.add(admin)
        session.flush()
        admin_id = admin.id
    token, _ = svc.create_token(alice_user, "t", is_read_only=True, max_read_bytes=1024)
    updated = svc.update_token(
        token_id=token.id,
        by_user_id=admin_id,
        by_is_admin=True,
        name="renamed-by-admin",
    )
    assert updated.name == "renamed-by-admin"


def test_update_token_name_collision_raises_integrity_error(alice_user):
    from sqlalchemy.exc import IntegrityError

    svc.create_token(alice_user, "taken", is_read_only=True, max_read_bytes=1024)
    other_token, _ = svc.create_token(alice_user, "other", is_read_only=True, max_read_bytes=1024)

    with pytest.raises(IntegrityError):
        svc.update_token(token_id=other_token.id, by_user_id=alice_user, by_is_admin=False, name="taken")
