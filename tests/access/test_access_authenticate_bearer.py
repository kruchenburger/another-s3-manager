import pytest

from another_s3_manager import access, api_tokens, users


@pytest.mark.parametrize(
    "header,code,message",
    [
        ("", "malformed_bearer", "Missing or malformed Bearer token"),
        ("Basic abc", "malformed_bearer", "Missing or malformed Bearer token"),
        ("bearer as3m_x", "malformed_bearer", "Missing or malformed Bearer token"),
        ("Bearer wrong", "wrong_token_prefix", "Token does not start with as3m_"),
        ("Bearer as3m_unknown", "invalid_token", "Invalid or revoked token"),
    ],
)
def test_bearer_denial(header, code, message):
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer(header, _unexpected_config)
    assert (error.value.code, error.value.message) == (code, message)


def test_bearer_hash_lookup_touch_and_raw_admin_grants():
    user = users.create_user("alice", "hash", is_admin=True, allowed_roles=["raw"])
    token, plaintext = api_tokens.create_token(user["id"], "token", False, 100)
    config = {"roles": [{"name": "configured"}]}
    result = access.authenticate_bearer("Bearer " + plaintext, lambda: config)
    assert result.token.id == token.id
    assert result.principal.granted_roles == ["raw"]
    assert access.allowed_roles(result.principal.to_user_dict(), config) == ["configured"]
    first = api_tokens.list_tokens_for_user(user["id"])[0].last_used_at
    assert first is not None
    access.authenticate_bearer("Bearer " + plaintext, lambda: config)
    assert api_tokens.list_tokens_for_user(user["id"])[0].last_used_at == first
    api_tokens.revoke_token(token.id, user["id"], False)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer " + plaintext, lambda: config)
    assert error.value.code == "invalid_token"


def test_orphan_is_not_touched(monkeypatch):
    from types import SimpleNamespace

    from another_s3_manager.access import tokens

    # An outer joined snapshot preserves the historical corrupt-orphan answer.
    monkeypatch.setattr(tokens, "find_active_token_with_owner", lambda digest: (SimpleNamespace(id=9), None))
    monkeypatch.setattr(tokens, "touch_last_used", lambda *args: pytest.fail("orphan PAT touched"))
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer as3m_orphan", _unexpected_config)
    assert (error.value.code, error.value.message) == ("orphan_token", "Token's user no longer exists")


def _unexpected_config():
    raise AssertionError("config must not load before token and owner validation")


def test_revoked_token_does_not_load_config():
    user = users.create_user("alice", "hash")
    token, plaintext = api_tokens.create_token(user["id"], "revoked", False, 100)
    api_tokens.revoke_token(token.id, user["id"], False)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer " + plaintext, _unexpected_config)
    assert error.value.code == "invalid_token"


def test_role_projection_failure_does_not_touch(monkeypatch):
    from another_s3_manager.access import tokens

    user = users.create_user("alice", "hash", is_admin=True)
    _, plaintext = api_tokens.create_token(user["id"], "broken-roles", False, 100)
    touched = []
    monkeypatch.setattr(tokens, "touch_last_used", touched.append)
    with pytest.raises(AttributeError):
        access.authenticate_bearer("Bearer " + plaintext, lambda: {"roles": ["broken"]})
    assert touched == []


def test_bearer_returns_projected_roles():
    user = users.create_user("alice", "hash", is_admin=True, allowed_roles=["raw"])
    _, plaintext = api_tokens.create_token(user["id"], "roles", False, 100)
    result = access.authenticate_bearer("Bearer " + plaintext, lambda: {"roles": [{"name": "configured"}]})
    assert result.projected_roles == ["configured"]
    assert result.principal.granted_roles == ["raw"]


def test_disable_reenable_preserves_pat_but_not_session():
    admin = users.create_user("admin", "hash", is_admin=True)
    owner = users.create_user("alice", "hash")
    _, plaintext = api_tokens.create_token(owner["id"], "active", False, 100)
    cookie = access.issue_session(access.Principal(owner), method="pwd", lifetime_minutes=180)
    access.update_account(admin, "alice", {"is_disabled": True})
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer " + plaintext, lambda: {})
    assert error.value.code == "ACCOUNT_DISABLED"
    access.update_account(admin, "alice", {"is_disabled": False})
    assert access.authenticate_bearer("Bearer " + plaintext, lambda: {}).principal.id == owner["id"]
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(cookie)
    assert error.value.code == "SESSION_EPOCH_MISMATCH"


def test_pat_delete_recreate_between_lookup_and_principal_never_rebinds(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from another_s3_manager.access import tokens
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    owner = users.create_user("alice", "hash")
    _, plaintext = api_tokens.create_token(owner["id"], "active", False, 100)
    reached, replaced = Barrier(2), Barrier(2)
    original = tokens.find_active_token_with_owner

    def lookup(digest):
        result = original(digest)
        reached.wait(timeout=10)
        replaced.wait(timeout=10)
        return result

    monkeypatch.setattr(tokens, "find_active_token_with_owner", lookup)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(access.authenticate_bearer, "Bearer " + plaintext, lambda: {})
        reached.wait(timeout=10)
        users.delete_user("alice")
        with session_scope() as session:
            session.add(User(id=owner["id"], username="alice", password_hash="replacement"))
        replaced.wait(timeout=10)
        with pytest.raises(access.AuthenticationError) as error:
            future.result(timeout=10)
        assert error.value.code == "ACCOUNT_REPLACED"
    with pytest.raises(access.AuthenticationError):
        access.principal_for(owner["id"], expected_identity=access.account_identity(owner))
    assert api_tokens.list_tokens_for_user(owner["id"]) == []
