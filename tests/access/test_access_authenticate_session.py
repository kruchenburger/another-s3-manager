from datetime import UTC, datetime, timedelta

import pytest
from jose import jwt

from another_s3_manager import access


@pytest.mark.parametrize(
    "payload,key",
    [
        ({"sub": "alice", "exp": 1}, "test-secret-key"),
        ({"sub": "alice"}, "wrong"),
        ({}, "test-secret-key"),
        ({"sub": 123}, "test-secret-key"),
    ],
)
def test_invalid_session_is_rejected(payload, key):
    token = jwt.encode(payload, key, algorithm="HS256")
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(token)
    assert error.value.code == "invalid_session"
    assert not access.session_token_is_wellformed(token)


def test_session_looks_up_current_user_and_preserves_csrf():
    from another_s3_manager import users

    users.create_user("alice", "hash", allowed_roles=["raw"])
    token = access.create_access_token({"sub": "alice", "csrf_token": "csrf"})
    principal = access.authenticate_session(token)
    assert principal.username == "alice"
    assert principal.granted_roles == ["raw"]
    assert principal.to_user_dict()["csrf_token"] == "csrf"
    users.delete_user("alice")
    assert access.session_token_is_wellformed(token)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(token)
    assert error.value.code == "user_not_found"


def test_prefilter_is_db_free(monkeypatch):
    from another_s3_manager.access import users

    def fail(*args):
        raise AssertionError("DB access")

    monkeypatch.setattr(users, "get_user_by_username", fail)
    token = access.create_access_token({"sub": "gone"})
    assert access.session_token_is_wellformed(token)
    assert not access.session_token_is_wellformed("")


def test_session_signing_defaults_and_hs256_only():
    before = datetime.now(UTC)
    payload = jwt.decode(access.create_access_token({"sub": "alice"}), "test-secret-key", algorithms=["HS256"])
    assert 10798 <= payload["exp"] - before.timestamp() <= 10801
    assert set(payload) == {"sub", "csrf_token", "exp"}
    bad = jwt.encode(
        {"sub": "alice", "exp": datetime.now(UTC) + timedelta(minutes=1)}, "test-secret-key", algorithm="HS384"
    )
    assert not access.session_token_is_wellformed(bad)


def test_principal_identity_normalizes_sqlite_utc():
    user = {"id": 3, "username": "alice", "created_at": "2026-11-13T12:00:00"}
    assert access.account_identity(user) == (3, "alice", "2026-11-13T12:00:00+00:00")


def test_principal_for_checks_expected_identity():
    from another_s3_manager import users

    user = users.create_user("alice", "hash")
    principal = access.principal_for(user["id"], expected_identity=access.account_identity(user))
    assert principal.username == "alice"
    with pytest.raises(access.AuthenticationError):
        access.principal_for(user["id"], expected_identity=(0, "different", None))


def test_download_empty_subject_skips_lookup_but_cookie_keeps_lookup(monkeypatch):
    from another_s3_manager.access import users

    def fail(username):
        assert username == ""
        raise RuntimeError("lookup reached")

    monkeypatch.setattr(users, "get_user_by_username", fail)
    token = access.create_access_token({"sub": ""})
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(token, require_subject=True)
    assert error.value.code == "invalid_session"
    with pytest.raises(RuntimeError, match="lookup reached"):
        access.authenticate_session(token)
