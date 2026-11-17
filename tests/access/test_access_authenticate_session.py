import pytest
from jose import jwt

from another_s3_manager import access, users


def issued():
    user = users.create_user("alice", "hash", allowed_roles=["raw"])
    token = access.issue_session(access.Principal(user), method="pwd", lifetime_minutes=180)
    return user, token


def resign(payload, algorithm="HS256"):
    return jwt.encode(payload, "test-secret-key", algorithm=algorithm)


@pytest.mark.parametrize("claim", ["sub", "csrf_token", "exp", "iat", "uid", "ugen", "sv", "amr", "sid"])
def test_required_claims(claim):
    _, token = issued()
    payload = access.decode_session_payload(token)
    del payload[claim]
    with pytest.raises(access.AuthenticationError):
        access.authenticate_session(resign(payload))


@pytest.mark.parametrize(
    "claim,value",
    [
        ("uid", True),
        ("uid", "1"),
        ("sv", False),
        ("sv", -1),
        ("iat", "1"),
        ("exp", True),
        ("exp", None),
        ("exp", {}),
        ("exp", []),
        ("iat", None),
        ("iat", {}),
        ("ugen", ""),
        ("sid", None),
        ("sub", ""),
        ("amr", "other"),
        ("csrf_token", 1),
    ],
)
def test_required_claim_types(claim, value):
    _, token = issued()
    payload = access.decode_session_payload(token)
    payload[claim] = value
    with pytest.raises(access.AuthenticationError):
        access.authenticate_session(resign(payload))


def test_session_looks_up_current_user_and_preserves_csrf():
    user, token = issued()
    principal = access.authenticate_session(token)
    assert principal.username == "alice"
    assert principal.granted_roles == ["raw"]
    assert principal.user["csrf_token"] == access.decode_session_payload(token)["csrf_token"]
    users.delete_user("alice")
    assert access.session_token_is_wellformed(token)
    with pytest.raises(access.AuthenticationError, match="User not found"):
        access.authenticate_session(token)


def test_prefilter_is_db_free(monkeypatch):
    _, token = issued()

    def fail(*args, **kwargs):
        raise AssertionError("DB access")

    monkeypatch.setattr(access, "principal_for", fail)
    from another_s3_manager.access import users as repository

    monkeypatch.setattr(repository, "get_user_by_id", fail)
    assert access.session_token_is_wellformed(token)
    assert not access.session_token_is_wellformed("")


def test_session_signing_defaults_and_hs256_only():
    _, token = issued()
    payload = access.decode_session_payload(token)
    assert set(payload) == {"sub", "csrf_token", "exp", "iat", "uid", "ugen", "sv", "amr", "sid"}
    assert payload["exp"] - payload["iat"] == 10800
    assert len(payload["sid"]) == 22
    assert payload["amr"] == "pwd"
    assert not access.session_token_is_wellformed(resign(payload, "HS384"))
    assert not access.session_token_is_wellformed(access.create_access_token({"sub": "alice"}))


@pytest.mark.parametrize(
    "change,code",
    [
        ({"uid": 999}, "user_not_found"),
        ({"ugen": "other"}, "ACCOUNT_REPLACED"),
        ({"sub": "bob"}, "ACCOUNT_REPLACED"),
        ({"sv": 1}, "SESSION_EPOCH_MISMATCH"),
        ({"exp": 1}, "invalid_session"),
    ],
)
def test_wrong_binding_and_expiry(change, code):
    _, token = issued()
    payload = access.decode_session_payload(token)
    payload.update(change)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(resign(payload))
    assert error.value.code == code


@pytest.mark.parametrize("value", [0, 10081, True, "180", 1.5])
def test_invalid_session_lifetime(value):
    with pytest.raises(ValueError):
        access.validate_lifetime_minutes(value)


def test_invalid_inherited_lifetime_fails(monkeypatch):
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "10081")
    with pytest.raises(ValueError):
        access.validate_lifetime_minutes()


def test_empty_inherited_lifetime_means_default(monkeypatch):
    # compose "${VAR:-}" passes an empty string; it counts as unset, like constants.py.
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "")
    assert access.validate_lifetime_minutes() == 180


def test_session_identity_is_projected_from_verified_account_and_session():
    user, token = issued()
    identity = access.authenticate_session(token).to_user_dict()["session_identity"]
    assert len(identity) == 64 and set(identity) <= set("0123456789abcdef")
    assert access.authenticate_session(token).to_user_dict()["session_identity"] == identity
    other_session = resign({**access.decode_session_payload(token), "sid": "different-session"})
    assert access.authenticate_session(other_session).user["session_identity"] != identity
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    other = users.create_user("bob", "hash")
    # Hold generation and sid fixed to isolate the account id's contribution.
    with session_scope() as session:
        session.get(User, other["id"]).auth_generation = user["auth_generation"]
    payload = access.decode_session_payload(token)
    other_token = resign({**payload, "uid": other["id"], "sub": "bob"})
    assert access.authenticate_session(other_token).user["session_identity"] != identity
    with session_scope() as session:
        session.get(User, user["id"]).auth_generation = "replacement-generation"
    replacement = users.get_user_by_username("alice")
    replacement_token = resign({**payload, "ugen": replacement["auth_generation"]})
    assert access.authenticate_session(replacement_token).user["session_identity"] != identity
    with pytest.raises(access.AuthenticationError):
        access.authenticate_session(token)
