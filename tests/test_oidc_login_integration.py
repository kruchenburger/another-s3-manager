import asyncio
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from another_s3_manager import access, config


def begin(op):
    start = access.start_oidc_login("/files?path=a", {})
    assert start.code is None
    cookies = {item.name: item.value for item in start.cookies if item.max_age}
    authorize = {key: value[0] for key, value in parse_qs(urlsplit(start.redirect).query).items()}
    callback = {key: value[0] for key, value in parse_qs(urlsplit(op.authorize(authorize)).query).items()}
    return callback, cookies


def test_full_real_signature_login_and_replay(oidc):
    query, cookies = begin(oidc)
    result = asyncio.run(access.complete_oidc_login(query, cookies))
    assert result.code is None
    assert result.redirect == "/files?path=a"
    principal = access.authenticate_session(result.session)
    assert principal.username == "reader"
    assert principal.granted_roles == ["Default"]
    assert principal.user["amr"] == "oidc"
    assert oidc.calls == 1
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session is None
    assert oidc.calls == 1


def test_fake_op_rejects_pkce_client_redirect_reuse_and_cross_transaction_code(oidc):
    a, ac = begin(oidc)
    b, bc = begin(oidc)
    a["code"], b["code"] = b["code"], a["code"]
    assert asyncio.run(access.complete_oidc_login(a, ac)).session is None
    assert asyncio.run(access.complete_oidc_login(b, bc)).session is None
    assert oidc.calls == 2
    assert access.find_identity(oidc.issuer, "reader") is None
    from another_s3_manager.access.oidc.transactions import decode_transaction

    for changes in (
        {"code_verifier": ""},
        {"code_verifier": "wrong"},
        {"client_id": "foreign"},
        {"redirect_uri": "https://foreign.example/callback"},
    ):
        q, c = begin(oidc)
        tx = decode_transaction(next(iter(c.values())))
        data = {
            "client_id": "asm",
            "redirect_uri": oidc.redirect_uri,
            "code": q["code"],
            "code_verifier": tx["cv"],
            **changes,
        }
        response = oidc.handle(httpx.Request("POST", oidc.issuer + "/token", data=data))
        assert response.status_code == 400
        assert asyncio.run(access.complete_oidc_login(q, c)).session is None
    q, c = begin(oidc)
    tx = decode_transaction(next(iter(c.values())))
    data = {"client_id": "asm", "redirect_uri": oidc.redirect_uri, "code": q["code"], "code_verifier": tx["cv"]}
    assert oidc.handle(httpx.Request("POST", oidc.issuer + "/token", data=data)).status_code == 200
    assert oidc.handle(httpx.Request("POST", oidc.issuer + "/token", data=data)).status_code == 400
    with pytest.raises(ValueError):
        oidc.authorize(
            {
                "client_id": "asm",
                "redirect_uri": oidc.redirect_uri,
                "code_challenge_method": "plain",
                "code_challenge": "x",
                "nonce": "x",
            }
        )


@pytest.mark.parametrize("query,cookies", [({}, {}), ({"state": "wrong", "code": "wrong"}, {})])
def test_invalid_state_never_exchanges(oidc, query, cookies):
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session is None
    assert oidc.calls == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"sub": None},
        {"sub": 123},
        {"sub": "é"},
        {"sub": "x" * 256},
        {"iss": "https://foreign"},
        {"aud": "asm-other"},
        {"aud": ["asm", "other"]},
        {"azp": "wrong"},
        {"nonce": "wrong"},
        {"exp": 1},
        {"iat": 9999999999},
        {"nbf": 9999999999},
    ],
)
def test_invalid_signed_tokens_have_no_identity_user_or_session_writes(oidc, changes):
    from another_s3_manager.access import users

    oidc.token_changes = changes
    q, c = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(q, c)).session is None
    assert users.count_users() == 0
    assert access.find_identity(oidc.issuer, "reader") is None
    assert oidc.calls == 1


def test_rotated_same_kid_refreshes_once_and_removed_key_fails_closed(oidc):
    from another_s3_manager.access import users
    from tests.oidc.fake_op import FakeOP

    old_key = oidc.key
    replacement = FakeOP()
    oidc.key, oidc.jwk = replacement.key, replacement.jwk
    q, c = begin(oidc)
    accepted = asyncio.run(access.complete_oidc_login(q, c))
    assert accepted.session
    before = users.get_user_by_username("reader")
    oidc.key = old_key
    q, c = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(q, c)).session is None
    assert users.get_user_by_username("reader")["sso_authz_valid_until"] == before["sso_authz_valid_until"]


def test_timeout_is_not_retried_and_ledger_stays_consumed(oidc, monkeypatch):
    from another_s3_manager.access.oidc import discovery

    query, cookies = begin(oidc)
    calls = []

    def timeout(*args, **kwargs):
        calls.append(1)
        raise discovery.OidcUnavailable("timeout")

    monkeypatch.setattr(discovery._discovery.outbound, "json", timeout)
    assert asyncio.run(access.complete_oidc_login(query, cookies)).code == "idp_unavailable"
    assert asyncio.run(access.complete_oidc_login(query, cookies)).code == "expired"
    assert len(calls) == 1


def test_commit_failure_does_not_publish_session_or_renewal(oidc, monkeypatch):
    from contextlib import contextmanager

    from sqlalchemy.exc import SQLAlchemyError

    from another_s3_manager.access import users

    q, c = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(q, c)).session
    before = users.get_user_by_username("reader")
    original = users.write_scope

    @contextmanager
    def failing_scope():
        with original() as session:
            yield session
            raise SQLAlchemyError("commit fixture failure")

    # Inject failure only into the mapping commit, after validation/lookup/consume.
    from another_s3_manager.access.oidc import identities

    commit = identities.commit_login

    def failing_commit(*args, **kwargs):
        with monkeypatch.context() as patch:
            patch.setattr(users, "write_scope", failing_scope)
            return commit(*args, **kwargs)

    monkeypatch.setattr(identities, "commit_login", failing_commit)
    q, c = begin(oidc)
    result = asyncio.run(access.complete_oidc_login(q, c))
    assert result.session is None
    assert result.cookies[0].max_age == 0
    after = users.get_user_by_username("reader")
    assert after["sso_authz_valid_until"] == before["sso_authz_valid_until"]
    assert after["session_epoch"] == before["session_epoch"]


def finish_callback_racing(op, monkeypatch, mutate):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from another_s3_manager.access.oidc import identities

    original = identities.login_snapshot
    entered, release = Event(), Event()

    def gated(*args):
        snapshot = original(*args)
        entered.set()
        assert release.wait(10)
        return snapshot

    monkeypatch.setattr(identities, "login_snapshot", gated)
    query, cookies = begin(op)
    with ThreadPoolExecutor(max_workers=1) as pool:
        callback = pool.submit(asyncio.run, access.complete_oidc_login(query, cookies))
        assert entered.wait(10)
        try:
            mutate()
        finally:
            release.set()
        return callback.result(10)


def test_disabled_callback_and_disable_before_commit_do_not_renew(oidc, monkeypatch):
    from another_s3_manager.access import users

    query, cookies = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session
    before = users.get_user_by_username("reader")
    result = finish_callback_racing(oidc, monkeypatch, lambda: users.update_user("reader", is_disabled=True))
    assert result.code == "disabled" and result.session is None
    after = users.get_user_by_username("reader")
    assert after["session_epoch"] == before["session_epoch"] + 1
    assert after["sso_authz_valid_until"] == before["sso_authz_valid_until"]
    assert after["allowed_roles"] == before["allowed_roles"]
    assert after["mapping_mode_applied"] == before["mapping_mode_applied"]
    query, cookies = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(query, cookies)).code == "disabled"
    assert users.get_user_by_username("reader") == after
    access.recover_local_account("reader", enable=True)
    assert users.get_user_by_username("reader")["sso_authz_valid_until"] == before["sso_authz_valid_until"]


def test_local_recovery_racing_callback_cannot_restore_oidc_access(oidc, monkeypatch):
    from another_s3_manager.access import users

    query, cookies = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session
    result = finish_callback_racing(
        oidc, monkeypatch, lambda: access.recover_local_account("reader", password="RecoveredPassword1")
    )
    assert result.session is None
    after = users.get_user_by_username("reader")
    assert after["auth_source"] == "local"
    assert after["mapping_mode_applied"] is None
    assert after["sso_authz_valid_until"] is None
    assert after["allowed_roles"] == ["Default"]
    query, cookies = begin(oidc)
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session is None
    assert users.get_user_by_username("reader") == after


@pytest.mark.parametrize("publication", ["file", "post"])
def test_external_file_reload_serializes_with_callback_grants(oidc, monkeypatch, app_client, publication):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from another_s3_manager.access import users
    from another_s3_manager.access.oidc import identities
    from tests.test_web_user_lifecycle import authenticate

    actor = users.create_user("publisher", "hash", is_admin=True)
    headers = authenticate(app_client, actor)
    entered, release, attempted = Event(), Event(), Event()
    original = identities.commit_login

    def gated(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(identities, "commit_login", gated)
    query, cookies = begin(oidc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        callback = pool.submit(asyncio.run, access.complete_oidc_login(query, cookies))
        assert entered.wait(10)
        # A raw edit is not published until load_config obtains coordination.
        candidate = json.loads(config.CONFIG_FILE.read_text())
        candidate["roles"] = []

        def publish():
            attempted.set()
            if publication == "file":
                config.CONFIG_FILE.write_text(json.dumps(candidate))
                return config.load_config(True)
            response = app_client.post("/api/config", json=candidate, headers=headers)
            assert response.status_code == 200
            assert response.json()["removed_mapping_rules"] == [0]
            return config.load_config()

        reload = pool.submit(publish)
        assert attempted.wait(10)
        assert not reload.done()
        release.set()
        assert callback.result(10).session
        assert reload.result(10)["roles"] == []
    from another_s3_manager.access import users

    assert access.allowed_roles(users.get_user_by_username("reader"), config.load_config()) == []


@pytest.fixture
def live_op(monkeypatch, tmp_path):
    """A FakeOP behind a real loopback server and the real outbound path.

    Unlike the `oidc` fixture nothing is shortcut: discovery_for builds the instance,
    current() performs the first refresh, resolve_destination validates the patched
    resolver answer and PinnedBackend connects to the pinned address. The client
    secret comes from a real file.
    """
    from tests.oidc.fake_op import FakeOP
    from tests.oidc.local_http import resolver_for, serve

    holder = {}
    with serve(lambda request: holder["op"].handle(request)) as port:
        issuer = f"http://op.example:{port}"
        op = FakeOP(issuer, "asm", "https://asm.example/api/auth/oidc/callback")
        holder["op"] = op
        secret = tmp_path / "client-secret"
        secret.write_text("first-secret\n")
        monkeypatch.setenv("OIDC_ISSUER", issuer)
        monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
        monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
        monkeypatch.setenv("COOKIE_SECURE", "true")
        monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
        monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", issuer)
        monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret))
        resolver_for(monkeypatch, {"op.example": ["127.0.0.1"]})
        cfg = config.load_config()
        cfg["auth"] = {
            "oidc": {"role_mapping": {"rules": [{"claim": "groups", "value": "data-team", "roles": ["Default"]}]}}
        }
        config.save_config(cfg)
        access.oidc_startup(config.load_config())
        op.secret_file = secret
        yield op


def basic(secret):
    import base64

    return "Basic " + base64.b64encode(f"asm:{secret}".encode()).decode()


def test_rotated_secret_file_is_used_by_the_next_exchange_on_the_same_discovery(live_op):
    from another_s3_manager.access.oidc import discovery

    query, cookies = begin(live_op)
    published = discovery._discovery
    assert published is not None and live_op.discovery_fetches == 1
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session
    assert live_op.token_authorizations == [basic("first-secret")]

    live_op.secret_file.write_text("second-secret\n")
    query, cookies = begin(live_op)
    result = asyncio.run(access.complete_oidc_login(query, cookies))
    assert result.session and result.code is None
    assert live_op.token_authorizations == [basic("first-secret"), basic("second-secret")]
    assert discovery._discovery is published
    assert access.discovery_for(access.oidc_settings(config.load_config())) is published
    # The rotation needed no new discovery fetch.
    assert live_op.discovery_fetches == 1


def test_removed_secret_file_blocks_only_sso(live_op, app_client, caplog):
    from another_s3_manager.access import users

    users.create_user("admin", access.hash_password("LocalPassword1"), is_admin=True)
    query, cookies = begin(live_op)
    live_op.secret_file.unlink()

    info = app_client.get("/api/app-info")
    assert info.status_code == 200
    assert info.json()["auth"]["oidc_enabled"] is True
    login = app_client.post("/api/login", data={"username": "admin", "password": "LocalPassword1"})
    assert login.status_code == 200
    assert config.load_config(force_reload=True)["auth"]["oidc"]["role_mapping"]["rules"]

    start = app_client.get("/api/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 503
    assert start.json() == {"detail": {"code": "OIDC_UNAVAILABLE"}}
    result = asyncio.run(access.complete_oidc_login(query, cookies))
    assert result.code == "idp_unavailable" and result.session is None
    assert live_op.calls == 0
    assert "category=client_secret_unavailable" in caplog.text
    assert str(live_op.secret_file) not in caplog.text


def test_unreadable_secret_file_fails_startup(live_op):
    live_op.secret_file.write_text("")
    with pytest.raises(ValueError, match="Empty OIDC client secret file"):
        access.oidc_startup(config.load_config())
    live_op.secret_file.unlink()
    with pytest.raises(ValueError, match="Cannot read OIDC client secret file"):
        access.oidc_startup(config.load_config())
