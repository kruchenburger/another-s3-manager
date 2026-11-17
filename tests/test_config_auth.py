import pytest

from another_s3_manager import access, config


def test_nested_auth_omission_preserves_off_short_ttl_and_rules(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://identity.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    old = {
        "roles": [{"name": "reader"}],
        "auth": {
            "local_login": "off",
            "oidc": {
                "session_max_minutes": 5,
                "role_mapping": {
                    "mode": "initial",
                    "require_match": True,
                    "rules": [{"claim": "groups", "value": "readers", "roles": ["reader"]}],
                },
            },
        },
    }
    result = config.merge_and_validate_update({"auth": {"oidc": {"display_name": "SSO"}}}, old)
    assert result["auth"]["local_login"] == "off"
    assert result["auth"]["oidc"]["session_max_minutes"] == 5
    assert result["auth"]["oidc"]["role_mapping"] == old["auth"]["oidc"]["role_mapping"]
    assert (
        config.merge_and_validate_update({"auth": {"oidc": {"role_mapping": {"rules": []}}}}, old)["auth"]["oidc"][
            "role_mapping"
        ]["rules"]
        == []
    )
    for candidate in ({"auth": None}, {"auth": {"oidc": None}}, {"auth": {"oidc": {"role_mapping": {"rules": None}}}}):
        with pytest.raises(ValueError):
            config.merge_and_validate_update(candidate, old)


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_max_minutes", True),
        ("session_max_minutes", "5"),
        ("session_max_minutes", 0),
        ("authz_max_days", 7),
        ("rp_logout", True),
    ],
)
def test_invalid_auth_settings(field, value):
    with pytest.raises(ValueError):
        access.oidc_settings({"auth": {"oidc": {field: value}}})


def test_failed_disk_write_never_publishes_partial_candidate(monkeypatch):
    previous = config.load_config()
    disk = config.CONFIG_FILE.read_bytes()
    candidate = {**previous, "auth": {"oidc": {"display_name": "Candidate"}}}

    def fail(value, stream, **kwargs):
        stream.write('{"incomplete":')
        raise OSError("fixture write failure")

    monkeypatch.setattr(config.json, "dump", fail)
    with pytest.raises(OSError):
        config.save_config(candidate)
    assert config._config_cache == previous
    assert config.CONFIG_FILE.read_bytes() == disk


def test_secret_canaries_absent_from_config_save_get_and_export(app_client, monkeypatch, tmp_path):
    from another_s3_manager import users
    from tests.test_web_user_lifecycle import authenticate

    actor = users.create_user("local-admin", "hash", is_admin=True)
    headers = authenticate(app_client, actor)
    monkeypatch.setenv("OIDC_ISSUER", "https://op.example")
    monkeypatch.setenv("PUBLIC_URL", "http://asm.example")
    monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "env-secret-canary")
    secret = tmp_path / "oidc-secret"
    secret.write_text("file-secret-canary")
    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret))
    response = app_client.post("/api/config", json=config.load_config(), headers=headers)
    assert response.status_code == 200
    response = app_client.get("/api/config")
    assert response.json()["auth_runtime"]["client_id"] == "asm"
    for text in (response.text, app_client.get("/api/config/export").text, config.CONFIG_FILE.read_text()):
        assert "env-secret-canary" not in text and "file-secret-canary" not in text


@pytest.mark.parametrize("force", [True, False])
def test_invalid_reload_and_internal_save_never_publish_defaults(force):
    import json

    previous = config.load_config()
    path = config.CONFIG_FILE
    bad = {**previous, "auth": {"oidc": {"role_mapping": {"mode": "wrong"}}}}
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        config.load_config(force_reload=force)
    assert config._config_cache == previous
    with pytest.raises(ValueError):
        config._save_config_internal(bad)
    assert config._config_cache == previous
    config._config_cache = {}
    with pytest.raises(ValueError):
        config.load_config(force_reload=True)


def test_oidc_origin_secret_precedence_and_secure_cookie_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ISSUER", "https://identity.example/realm")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "env-canary")
    secret = tmp_path / "secret"
    secret.write_text("file-canary\n")
    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret))
    from another_s3_manager.access.oidc.settings import client_secret

    assert client_secret() == "file-canary"
    secret.unlink()
    with pytest.raises(ValueError, match="Cannot read OIDC client secret file"):
        client_secret()
    # Settings never read the secret, so an unreadable file cannot break them (L1).
    assert access.oidc_settings({}).local_login == "all"
    monkeypatch.delenv("OIDC_CLIENT_SECRET_FILE")
    assert client_secret() == "env-canary"
    for public in (
        "https://asm.example/path",
        "https://u@asm.example",
        "https://asm.example?q=1",
        "https://asm.example#f",
        "http://asm.example",
    ):
        monkeypatch.setenv("PUBLIC_URL", public)
        with pytest.raises(ValueError):
            access.oidc_settings({})
    for scheme in ("https", "HTTPS", "HtTpS"):
        monkeypatch.setenv("PUBLIC_URL", f"{scheme}://asm.example")
        monkeypatch.setenv("OIDC_ISSUER", f"{scheme}://identity.example/realm")
        monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", f"{scheme}://Identity.Example:443")
        monkeypatch.setenv("COOKIE_SECURE", "true")
        settings = access.oidc_settings({})
        assert settings.private_origins == frozenset({"https://identity.example:443"})
        assert settings.issuer == f"{scheme}://identity.example/realm"
        monkeypatch.setenv("COOKIE_SECURE", "false")
        with pytest.raises(ValueError, match="secure cookies"):
            access.oidc_settings({})


PREFERRED_USERNAME_DETAIL = (
    "Rules on preferred_username are not allowed: the IdP user can often change it. Use a group or app-role claim."
)


@pytest.mark.parametrize(
    "auth,detail",
    [
        ({"local_login": "private-input-canary"}, "Invalid local login policy"),
        ({"oidc": {"role_mapping": {"mode": "private-input-canary"}}}, "Invalid mapping mode"),
        ({"oidc": {"role_mapping": {"require_match": False}}}, "require_match must be true"),
        (
            {"oidc": {"role_mapping": {"rules": [{"claim": "preferred_username", "value": "boss", "admin": True}]}}},
            PREFERRED_USERNAME_DETAIL,
        ),
    ],
)
def test_config_post_reports_specific_secret_free_auth_error(app_client, monkeypatch, auth, detail):
    from another_s3_manager import users
    from tests.test_web_user_lifecycle import authenticate

    actor = users.create_user("local-admin", "hash", is_admin=True)
    headers = authenticate(app_client, actor)
    previous = config.load_config()
    disk = config.CONFIG_FILE.read_bytes()
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "client-secret-canary")
    response = app_client.post("/api/config", json={**previous, "auth": auth}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": detail}
    assert "canary" not in response.text
    assert config.CONFIG_FILE.read_bytes() == disk
    assert config.load_config() == previous


def test_preferred_username_rule_in_the_file_is_refused_and_last_good_kept():
    import json

    previous = config.load_config()
    bad = {
        **previous,
        "auth": {
            "oidc": {
                "role_mapping": {"rules": [{"claim": "preferred_username", "value": "boss", "roles": ["Default"]}]}
            }
        },
    }
    config.CONFIG_FILE.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="Rules on preferred_username are not allowed"):
        config.load_config(force_reload=True)
    with pytest.raises(ValueError, match="Use a group or app-role claim"):
        config.load_config()
    assert config._config_cache == previous
    # Other claims, including nested ones, stay valid.
    access.oidc_settings(
        {"auth": {"oidc": {"role_mapping": {"rules": [{"claim": "realm_access.roles", "value": "x", "admin": True}]}}}}
    )


SECURED = {
    "local_login": "admins",
    "oidc": {
        "role_mapping": {
            "mode": "initial",
            "rules": [{"claim": "groups", "value": "admins", "admin": True}],
        }
    },
}


@pytest.mark.parametrize("force", [True, False])
@pytest.mark.parametrize(
    "edit,expected",
    [
        (
            lambda auth: auth["oidc"]["role_mapping"].pop("rules"),
            {"local_login": "admins", "oidc": {"role_mapping": {"mode": "initial"}}},
        ),
        (
            lambda auth: auth["oidc"]["role_mapping"].pop("mode"),
            {"local_login": "admins", "oidc": {"role_mapping": {"rules": SECURED["oidc"]["role_mapping"]["rules"]}}},
        ),
        (lambda auth: auth.clear(), {}),
    ],
)
def test_external_reload_treats_the_file_as_authoritative(force, edit, expected):
    import copy
    import json
    import os

    path = config.CONFIG_FILE
    start = {**config.load_config(), "auth": copy.deepcopy(SECURED)}
    config.save_config(start)
    assert config.load_config()["auth"] == SECURED
    changed = copy.deepcopy(start)
    edit(changed["auth"])
    path.write_text(json.dumps(changed) + " " * 7)
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    assert config.load_config(force_reload=force)["auth"] == expected
    # The next internal save does not write the removed keys back.
    config.save_config(config.load_config())
    assert json.loads(path.read_text())["auth"] == expected


def test_removing_the_auth_block_from_the_file_takes_effect_on_reload():
    import json

    config.save_config({**config.load_config(), "auth": SECURED})
    raw = json.loads(config.CONFIG_FILE.read_text())
    raw.pop("auth")
    config.CONFIG_FILE.write_text(json.dumps(raw))
    assert "auth" not in config.load_config(force_reload=True)
    assert access.oidc_settings(config.load_config()).mode == "sync"


def test_partial_api_update_still_preserves_omitted_security_fields(app_client):
    from another_s3_manager import users
    from tests.test_web_user_lifecycle import authenticate

    actor = users.create_user("local-admin", "hash", is_admin=True)
    headers = authenticate(app_client, actor)
    config.save_config({**config.load_config(), "auth": SECURED})
    body = config.load_config()
    body.pop("auth")
    assert app_client.post("/api/config", json=body, headers=headers).status_code == 200
    assert config.load_config(force_reload=True)["auth"] == SECURED


def test_plain_http_issuer_must_be_an_allow_listed_origin(monkeypatch, caplog):
    monkeypatch.setenv("OIDC_ISSUER", "http://op.internal:8091")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("PUBLIC_URL", "http://asm.internal")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    with pytest.raises(ValueError, match="Invalid OIDC URL"):
        access.oidc_settings({})
    monkeypatch.setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(ValueError, match="must be listed in OIDC_ALLOWED_PRIVATE_ORIGINS"):
        access.oidc_settings({})
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "http://op.internal:8092")
    with pytest.raises(ValueError, match="must be listed in OIDC_ALLOWED_PRIVATE_ORIGINS"):
        access.oidc_settings({})
    monkeypatch.setenv("OIDC_ALLOWED_PRIVATE_ORIGINS", "http://op.internal:8091")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "startup-secret-canary")
    caplog.clear()
    assert access.oidc_startup({}).allow_http is True
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert any("OIDC_ALLOW_INSECURE_HTTP is enabled" in record.getMessage() for record in warnings)
    assert "startup-secret-canary" not in caplog.text


def test_no_insecure_http_warning_by_default(monkeypatch, caplog):
    monkeypatch.setenv("OIDC_ISSUER", "https://op.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    caplog.clear()
    access.oidc_startup({})
    assert "OIDC_ALLOW_INSECURE_HTTP" not in caplog.text


@pytest.mark.parametrize(
    ("raw", "secure"),
    [
        (None, True),
        ("true", True),
        ("TRUE", True),
        (" True ", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("1", False),
        ("no", False),
        ("yes", False),
        ("", False),
    ],
)
def test_cookie_secure_keeps_the_v1_3_1_parsing_rule(raw, secure):
    from another_s3_manager.constants import parse_cookie_secure

    # Only a case-insensitive "true" means Secure, exactly as in v1.3.1; nothing raises.
    assert parse_cookie_secure(raw) is secure


@pytest.mark.parametrize("raw", ["False", "TRUE", "0", "1", "yes", "no"])
def test_any_cookie_secure_value_starts_an_install_without_oidc(monkeypatch, raw):
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("COOKIE_SECURE", raw)
    settings = access.oidc_settings({})
    assert settings.enabled is False
    access.oidc_startup({})


def test_invalid_config_file_answers_with_its_reason_not_a_generic_500(app_client):
    import json

    from another_s3_manager import users
    from tests.test_web_user_lifecycle import authenticate

    authenticate(app_client, users.create_user("local-admin", "hash", is_admin=True))
    previous = config.load_config()
    bad = {
        **previous,
        "auth": {
            "oidc": {
                "role_mapping": {"rules": [{"claim": "preferred_username", "value": "boss", "roles": ["Default"]}]}
            }
        },
    }
    config.CONFIG_FILE.write_text(json.dumps(bad))
    response = app_client.get("/api/config")
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail.startswith("config.json is invalid, the last valid configuration is still in use: ")
    assert "Rules on preferred_username are not allowed" in detail
    assert config._config_cache == previous
    config.CONFIG_FILE.write_text(json.dumps(previous))
    assert app_client.get("/api/config").status_code == 200
