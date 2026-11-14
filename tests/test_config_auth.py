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
    assert access.oidc_settings({}).client_secret == "file-canary"
    secret.unlink()
    with pytest.raises(ValueError):
        access.oidc_settings({})
    monkeypatch.delenv("OIDC_CLIENT_SECRET_FILE")
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


@pytest.mark.parametrize(
    "auth,detail",
    [
        ({"local_login": "private-input-canary"}, "Invalid local login policy"),
        ({"oidc": {"role_mapping": {"mode": "private-input-canary"}}}, "Invalid mapping mode"),
        ({"oidc": {"role_mapping": {"require_match": False}}}, "require_match must be true"),
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
