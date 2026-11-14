import asyncio

from tests.test_oidc_login_integration import begin

from another_s3_manager import access, config
from another_s3_manager.access import users
from another_s3_manager.access.oidc.identities import normalized_username


def test_normalization_bounds():
    assert normalized_username("  ＡＤＭＩＮ  ") == "admin"
    assert len(normalized_username("x" * 100)) == 64
    assert normalized_username(123) == "sso-user"


def test_identity_and_username_races_have_no_ghosts(oidc):
    from concurrent.futures import ThreadPoolExecutor

    queries = [begin(oidc), begin(oidc)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda args: asyncio.run(access.complete_oidc_login(*args)), queries))
    assert all(result.session for result in results)
    assert users.count_users() == 2  # One local seed and one identity, no losing candidate.
    oidc.claims = {"sub": "second-person", "preferred_username": "reader", "groups": ["data-team"]}
    q, c = begin(oidc)
    result = asyncio.run(access.complete_oidc_login(q, c))
    assert access.authenticate_session(result.session).username == "reader-sso"
    assert users.count_users() == 3
    assert users.get_user_by_username("admin")["auth_source"] == "local"


def test_collision_preserves_case_insensitive_local_admin(oidc):
    local = users.create_user("ADMIN", "local-hash", is_admin=True)
    oidc.claims = {"sub": "claim-admin", "preferred_username": "ＡＤＭＩＮ", "groups": ["data-team"]}
    q, c = begin(oidc)
    result = asyncio.run(access.complete_oidc_login(q, c))
    assert access.authenticate_session(result.session).username == "admin-sso"
    assert users.get_user_by_id(local["id"])["password_hash"] == "local-hash"


def test_initial_denial_preserves_manual_access_bumps_epoch_and_keeps_pat(oidc):
    cfg = config.load_config()
    cfg["auth"]["oidc"]["role_mapping"]["mode"] = "initial"
    config.save_config(cfg)
    # Discovery settings change with the mode; preserve the injected outbound fixture.
    from another_s3_manager.access.oidc import discovery

    discovery._discovery.settings = access.oidc_settings(cfg)
    q, cookies = begin(oidc)
    first = asyncio.run(access.complete_oidc_login(q, cookies))
    before = users.get_user_by_username("reader")
    from another_s3_manager.access import tokens

    _, pat = tokens.create_token(before["id"], "initial-pat", True, 1024)
    cfg["auth"]["oidc"]["role_mapping"]["rules"] = []
    config.save_config(cfg)
    q, cookies = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(q, cookies)).code == "no_access"
    after = users.get_user_by_username("reader")
    assert after["allowed_roles"] == ["Default"]
    assert after["session_epoch"] == before["session_epoch"] + 1
    assert after["sso_authz_valid_until"] is None
    assert access.authenticate_bearer("Bearer " + pat, config.load_config).principal.id == before["id"]
    try:
        access.authenticate_session(first.session)
    except access.AuthenticationError as error:
        assert error.code == "SESSION_EPOCH_MISMATCH"
    else:
        raise AssertionError("Old session survived mapping denial")
