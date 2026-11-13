from types import SimpleNamespace

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
        access.authenticate_bearer(header, {})
    assert (error.value.code, error.value.message) == (code, message)


def test_bearer_hash_lookup_touch_and_raw_admin_grants():
    user = users.create_user("alice", "hash", is_admin=True, allowed_roles=["raw"])
    token, plaintext = api_tokens.create_token(user["id"], "token", False, 100)
    config = {"roles": [{"name": "configured"}]}
    result = access.authenticate_bearer("Bearer " + plaintext, config)
    assert result.token.id == token.id
    assert result.principal.granted_roles == ["raw"]
    assert access.allowed_roles(result.principal.to_user_dict(), config) == ["configured"]
    first = api_tokens.list_tokens_for_user(user["id"])[0].last_used_at
    assert first is not None
    access.authenticate_bearer("Bearer " + plaintext, config)
    assert api_tokens.list_tokens_for_user(user["id"])[0].last_used_at == first
    api_tokens.revoke_token(token.id, user["id"], False)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer " + plaintext, config)
    assert error.value.code == "invalid_token"


def test_orphan_is_not_touched(monkeypatch):
    from another_s3_manager.access import tokens

    token = SimpleNamespace(id=9, user_id=9999)
    monkeypatch.setattr(tokens, "find_active_token_by_hash", lambda digest: token)

    def unexpected_touch(*args):
        raise AssertionError("orphan must not be touched")

    monkeypatch.setattr(tokens, "touch_last_used", unexpected_touch)
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer("Bearer as3m_orphan", {})
    assert (error.value.code, error.value.message) == ("orphan_token", "Token's user no longer exists")
