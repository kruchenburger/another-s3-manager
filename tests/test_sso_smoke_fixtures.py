"""Offline fixture contracts, not a second OIDC mapper or a running-IdP test."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def load_checker():
    spec = importlib.util.spec_from_file_location("sso_checker", ROOT / "scripts/smoke/check-sso.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_both_idps_seed_two_users_groups_and_asm_client():
    realm = read_json("docker/sso/keycloak/realm.json")
    assert realm["realm"] == "asm-smoke"
    assert {user["username"] for user in realm["users"]} == {"sso-admin", "sso-reader"}
    assert {group["name"] for group in realm["groups"]} == {"s3-admins", "data-team", "team"}
    assert realm["groups"][2]["subGroups"][0]["name"] == "sub"
    client = realm["clients"][0]
    assert client["clientId"] == "asm"
    assert client["publicClient"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    blueprint = read_json("docker/sso/authentik/blueprint.yaml")
    assert blueprint["version"] == 1
    entries = blueprint["entries"]
    users = [e for e in entries if e["model"] == "authentik_core.user"]
    assert {e["identifiers"]["username"] for e in users} == {"sso-admin", "sso-reader"}
    assert all(e["state"] == "created" and e["attrs"]["password"] == "__SSO_DEMO_PASSWORD__" for e in users)
    groups = [e for e in entries if e["model"] == "authentik_core.group"]
    assert {e["identifiers"]["name"] for e in groups} == {"s3-admins", "data-team", "team", "sub"}
    # Authentik 2026.8 uses plural parent relationships in its native serializer.
    assert groups[3]["attrs"]["parents"] == [groups[2]["identifiers"]["pk"]]
    assert users[0]["attrs"]["groups"] == [groups[0]["identifiers"]["pk"]]
    assert users[1]["attrs"]["groups"] == [groups[1]["identifiers"]["pk"], groups[3]["identifiers"]["pk"]]
    providers = [e for e in entries if e["model"] == "authentik_providers_oauth2.oauth2provider"]
    assert len(providers) == 1
    assert providers[0]["attrs"]["client_id"] == "asm"
    assert providers[0]["attrs"]["client_type"] == "confidential"
    assert providers[0]["attrs"]["signing_key"] == "__SIGNING_KEY__"
    assert all(e["state"] == "created" for e in entries)


def test_keycloak_id_token_groups_include_full_path_and_flat_examples():
    realm = read_json("docker/sso/keycloak/realm.json")
    mappers = realm["clients"][0]["protocolMappers"]
    full, flat = mappers
    assert full["protocolMapper"] == flat["protocolMapper"] == "oidc-group-membership-mapper"
    assert full["config"] == {
        "claim.name": "groups",
        "full.path": "true",
        "id.token.claim": "true",
        "access.token.claim": "false",
        "userinfo.token.claim": "false",
    }
    assert flat["config"] == {
        "claim.name": "groups_flat",
        "full.path": "false",
        "id.token.claim": "true",
        "access.token.claim": "false",
        "userinfo.token.claim": "false",
    }
    assert realm["users"][1]["groups"] == ["/data-team", "/team/sub"]
    rules = read_json("docker/sso/asm/config.json")["auth"]["oidc"]["role_mapping"]["rules"]
    assert {"claim": "groups", "value": "/team/sub", "roles": ["reader"]} in rules
    assert {"claim": "groups_flat", "value": "data-team", "roles": ["reader"]} in rules


def test_authentik_id_token_group_scope_matches_documented_rules():
    entries = read_json("docker/sso/authentik/blueprint.yaml")["entries"]
    scope = next(
        e
        for e in entries
        if e["model"] == "authentik_providers_oauth2.scopemapping" and e["attrs"]["scope_name"] == "groups"
    )
    assert (
        scope["attrs"]["expression"] == 'return {"groups": list(request.user.ak_groups.values_list("name", flat=True))}'
    )
    provider = next(e for e in entries if e["model"] == "authentik_providers_oauth2.oauth2provider")
    assert provider["attrs"]["include_claims_in_id_token"] is True
    assert scope["identifiers"]["pk"] in provider["attrs"]["property_mappings"]
    assert provider["attrs"]["grant_types"] == ["authorization_code"]
    scopes = [e for e in entries if e["model"] == "authentik_providers_oauth2.scopemapping"]
    assert {e["attrs"]["scope_name"] for e in scopes} == {"openid", "profile", "groups"}
    assert {e["identifiers"]["pk"] for e in scopes} == set(provider["attrs"]["property_mappings"])
    cfg = read_json("docker/sso/asm/config.json")
    assert cfg["auth"]["oidc"]["scopes"] == ["openid", "profile", "groups"]
    assert {"claim": "groups", "value": "s3-admins", "admin": True} in cfg["auth"]["oidc"]["role_mapping"]["rules"]
    assert {"claim": "groups", "value": "data-team", "roles": ["reader"]} in cfg["auth"]["oidc"]["role_mapping"][
        "rules"
    ]


def test_callbacks_and_canonical_issuers_match_fixture_environment():
    checker = load_checker()
    assert checker.ISSUERS == {
        "keycloak": "http://keycloak.sso.test:8180/realms/asm-smoke",
        "authentik": "http://authentik.sso.test:9002/application/o/asm/",
    }
    callbacks = ["http://localhost:8080/api/auth/oidc/callback", "http://localhost:5173/api/auth/oidc/callback"]
    assert read_json("docker/sso/keycloak/realm.json")["clients"][0]["redirectUris"] == callbacks
    provider = next(
        e
        for e in read_json("docker/sso/authentik/blueprint.yaml")["entries"]
        if e["model"] == "authentik_providers_oauth2.oauth2provider"
    )
    assert provider["attrs"]["redirect_uris"] == [{"matching_mode": "strict", "url": url} for url in callbacks]
    path = ROOT / "docker/sso/.env.example"
    if not path.exists():
        pytest.skip("manager must supply docker/sso/.env.example; callback/issuer constants already checked")
    env = dict(
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert env["SSO_PROVIDER"] == "keycloak"
    assert env["OIDC_ISSUER"] == "http://keycloak.sso.test:8180/realms/asm-smoke"
    assert env["PUBLIC_URL"] == "http://localhost:8080"


def test_asm_data_is_isolated_per_provider_and_never_ordinary_data():
    compose = (ROOT / "docker/docker-compose.sso.yml").read_text(encoding="utf-8")
    assert "asm-sso-smoke-${SSO_PROVIDER:-keycloak}-data" in compose
    assert "asm-data:/app/data" in compose
    assert "./data:/" not in compose
    assert "./docker/sso/asm/config.json:/fixture/config.json:ro" in compose
    assert "keycloak-data:/opt/keycloak/data" in compose
    assert "authentik-db:/var/lib/postgresql/data" in compose


def test_no_production_credentials_or_private_keys_in_fixtures(monkeypatch):
    from another_s3_manager import config

    for key in (
        "OIDC_ISSUER",
        "OIDC_CLIENT_SECRET_FILE",
        "OIDC_ALLOWED_PRIVATE_ORIGINS",
        "LOCAL_LOGIN",
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
    ):
        monkeypatch.delenv(key, raising=False)
    fixture = read_json("docker/sso/asm/config.json")
    assert config.merge_and_validate_update(fixture, {}) == fixture
    assert fixture["auth"]["oidc"]["role_mapping"]["require_match"] is True
    assert {r["name"] for r in fixture["roles"]} == {"reader", "admin"}
    for path in (ROOT / "docker/sso").rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            assert "PRIVATE KEY-----" not in content
            assert "gojet" not in content.lower()
    realm = read_json("docker/sso/keycloak/realm.json")
    assert realm["clients"][0]["secret"] == "${SSO_CLIENT_SECRET}"
    assert all(u["credentials"][0]["value"] == "${SSO_DEMO_PASSWORD}" for u in realm["users"])


def test_smoke_app_uses_explicit_image_without_build():
    compose = (ROOT / "docker/docker-compose.sso.yml").read_text(encoding="utf-8")
    assert "image: ${ASM_SMOKE_IMAGE:?" in compose
    assert "build:" not in compose
    assert "env_file: .env" not in compose
    assert ":latest" not in compose
    assert "ports: !override" in compose


def test_merged_compose_bindings_reject_wildcards_including_minio():
    validate = load_checker().validate_compose_bindings
    valid = {"host_ip": "127.0.0.1", "published": "9000", "target": 9000}
    assert validate({"services": {"minio": {"ports": [valid]}, "database": {}}}) == []
    assert validate({"services": {"ipv6": {"ports": [dict(valid, host_ip="::1")]}}}) == []
    for host in (None, "", "0.0.0.0", "::", "192.168.1.1"):
        bad = dict(valid, host_ip=host)
        assert validate({"services": {"minio": {"ports": [bad, valid]}}}) == ["minio:9000"]
    absent = {"published": "9001", "target": 9001}
    assert validate({"services": {"minio": {"ports": [absent, valid]}}}) == ["minio:9001"]
    assert validate({"services": {"minio": {"ports": [{"target": 9000}]}}}) == ["minio:9000"]


@pytest.mark.parametrize("host,code", [("127.0.0.1", 0), ("0.0.0.0", 1)])
def test_compose_checker_uses_exact_offline_command_without_printing_env(host, code, tmp_path, monkeypatch, capsys):
    checker = load_checker()
    example = tmp_path / "docker/sso/.env.example"
    example.parent.mkdir(parents=True)
    example.write_text("# Synthetic presence guard only\n", encoding="utf-8")
    monkeypatch.setattr(checker, "ROOT", tmp_path)
    commands = []

    def capture(command):
        commands.append(command)
        if command == ["docker", "compose", "version", "--short"]:
            return "2.24.4"
        assert command == [
            "docker",
            "compose",
            "--project-directory",
            ".",
            "--env-file",
            "docker/sso/.env.example",
            "-f",
            "docker/docker-compose.minio.yml",
            "-f",
            "docker/docker-compose.sso.yml",
            "--profile",
            "sso-smoke",
            "config",
            "--format",
            "json",
        ]
        return json.dumps(
            {
                "services": {
                    "minio": {
                        "environment": {"SECRET": "do-not-print-canary"},
                        "ports": [{"host_ip": host, "published": "9000", "target": 9000}],
                    }
                }
            }
        )

    monkeypatch.setattr(checker, "captured", capture)
    assert checker.check_compose_bindings() == code
    assert len(commands) == 2
    output = capsys.readouterr()
    assert "do-not-print-canary" not in output.out + output.err
    assert output.out == ("PASS compose-bindings\n" if code == 0 else "FAIL binding minio:9000\n")


def test_unsupported_compose_fails_before_loading_model(tmp_path, monkeypatch, capsys):
    checker = load_checker()
    example = tmp_path / "docker/sso/.env.example"
    example.parent.mkdir(parents=True)
    example.write_text("# Synthetic presence guard only\n", encoding="utf-8")
    monkeypatch.setattr(checker, "ROOT", tmp_path)

    def old_version(command):
        assert command == ["docker", "compose", "version", "--short"]
        return "2.24.3"

    monkeypatch.setattr(checker, "captured", old_version)
    assert checker.check_compose_bindings() == 1
    assert capsys.readouterr().out == "FAIL compose-version: require >=2.24.4\n"


def test_guide_published_with_oidc_feature_and_recovery_contract():
    guide = (ROOT / "docs/sso.md").read_text(encoding="utf-8")
    assert guide.index("## Keycloak") < guide.index("## Authentik") < guide.index("## Google")
    for text in (
        "client_secret_basic",
        "S256",
        "UserInfo-only",
        "--enable USER",
        "--local USER",
        "exactly seven days",
        "Initial denial preserves",
        "c131a001",
        "forward-fix",
        "pre-release backup including config",
        "copied ASM cookie",
        "1–10080",
        "SSO_PROVIDER=authentik",
    ):
        assert text in guide
    assert "[SSO setup and smoke stand](docs/sso.md)" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert (ROOT / "docs/testing-backends.md").exists()
