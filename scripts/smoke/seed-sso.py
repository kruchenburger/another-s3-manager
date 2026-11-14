#!/usr/bin/env python3
"""LOCAL ONLY: initialize runtime secrets and import the native IdP fixture.

No ASM authorization code is imported. Native imports create provider objects;
existing fixture state is verified, never reset, on subsequent runs.
"""

import argparse
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
MARKER = "asm-local-smoke-v1"
ISSUERS = {
    "keycloak": "http://keycloak.sso.test:8180/realms/asm-smoke",
    "authentik": "http://authentik.sso.test:9002/application/o/asm/",
}
CALLBACKS = [
    "http://localhost:8080/api/auth/oidc/callback",
    "http://localhost:5173/api/auth/oidc/callback",
]
RUNTIME = ROOT / "data/sso/.env.local"
AK = "http://authentik.sso.test:9002/api/v3/"
KC = "http://keycloak.sso.test:8180"


class SmokeFailure(Exception):
    """Only fixed component identifiers cross the CLI error boundary."""


def read_env(path):
    """Read our plain KEY=value format, without shell evaluation/interpolation."""
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\x00" in value:
            raise SmokeFailure("fixture-env-format")
        result[key] = value
    return result


def selection(provider):
    if provider not in ISSUERS:
        raise SmokeFailure("provider-selection")
    return {"SSO_PROVIDER": provider, "OIDC_ISSUER": ISSUERS[provider]}


def write_runtime(path, env, *, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never display secrets. POSIX mode is owner-only; Windows operators must use
    # a private user directory/ACL (chmod alone cannot guarantee Windows ACLs).
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("# LOCAL ONLY. Generated secrets; never commit or print this file.\n")
        for key, value in env.items():
            stream.write(f"{key}={value}\n")


def init_runtime(path, image, provider, *, source=False):
    if not source and (
        not image
        or not re.fullmatch(r"[A-Za-z0-9:/@._-]+", image)
        or any(word in image.lower() for word in ("required", "unset"))
        or image.endswith(":latest")
    ):
        raise SmokeFailure("tested-ASM_SMOKE_IMAGE-required")
    env = {
        "ASM_SMOKE_IMAGE": "invalid.example/asm-smoke-image-required:unset" if source else image,
        "SSO_FIXTURE_MARKER": MARKER,
        "SSO_RUNTIME_CONFIRMED": "yes",
        **selection(provider),
        "PUBLIC_URL": "http://localhost:5173" if source else "http://localhost:8080",
        "LOCAL_LOGIN": "all",
        "SSO_DEMO_PASSWORD": "LocalSsoDemo1!",
        "SSO_CLIENT_SECRET": secrets.token_urlsafe(48),
        "SSO_DB_PASSWORD": secrets.token_urlsafe(48),
        "SSO_AUTHENTIK_SECRET": secrets.token_urlsafe(64),
        "SSO_AUTHENTIK_TOKEN": secrets.token_urlsafe(48),
        "SSO_KEYCLOAK_ADMIN_PASSWORD": secrets.token_urlsafe(48),
        "SSO_JWT_SECRET": secrets.token_urlsafe(64),
    }
    write_runtime(path, env, exclusive=True)


def require_local(env, confirmed):
    provider = env.get("SSO_PROVIDER", "keycloak")
    if (
        not confirmed
        or env.get("SSO_FIXTURE_MARKER") != MARKER
        or env.get("SSO_RUNTIME_CONFIRMED") != "yes"
        or env.get("OIDC_ISSUER") != ISSUERS.get(provider)
        or env.get("PUBLIC_URL") not in ("http://localhost:8080", "http://localhost:5173")
    ):
        raise SmokeFailure("local-fixture-confirmation")
    for key in ("SSO_CLIENT_SECRET", "SSO_DEMO_PASSWORD", "SSO_KEYCLOAK_ADMIN_PASSWORD", "SSO_AUTHENTIK_TOKEN"):
        if not env.get(key) or "offline-only" in env[key]:
            raise SmokeFailure("runtime-secrets-required")


def request(client, component, method, url, *, as_json=True, **kwargs):
    """Bound responses and sanitize every failure, including HTTP error bodies."""
    try:
        deadline = time.monotonic() + 5
        with client.stream(method, url, **kwargs) as response:
            if not 200 <= response.status_code < 300:
                raise SmokeFailure(component)
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 1024 * 1024 or time.monotonic() > deadline:
                    raise SmokeFailure(component)
            return json.loads(data) if as_json else bytes(data)
    except (httpx.HTTPError, ValueError, UnicodeError):
        raise SmokeFailure(component) from None


def wait_for(fn, component, seconds=180):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return fn()
        except SmokeFailure:
            if time.monotonic() >= deadline:
                raise SmokeFailure(component) from None
            time.sleep(2)


def ak_headers(env):
    return {"Authorization": "Bearer " + env["SSO_AUTHENTIK_TOKEN"]}


def ak_list(client, env, path, **params):
    data = request(
        client,
        "authentik-configuration",
        "GET",
        AK + path,
        headers=ak_headers(env),
        params={"page_size": 100, **params},
    )
    # Never silently accept partial inventories or follow a provider-controlled URL.
    if data.get("pagination", {}).get("next") or data.get("pagination", {}).get("total_pages", 1) > 1:
        raise SmokeFailure("authentik-inventory-pagination")
    return data["results"]


def seed_authentik(client, env):
    wait_for(lambda: ak_list(client, env, "core/applications/", slug="asm"), "authentik-bootstrap")
    applications = ak_list(client, env, "core/applications/", slug="asm")
    if applications:
        if len(applications) != 1 or applications[0].get("meta_description") != MARKER:
            raise SmokeFailure("authentik-foreign-application")
        # Do not re-apply after operator group/claim/password changes.
        return
    if ak_list(client, env, "providers/oauth2/", client_id="asm"):
        raise SmokeFailure("authentik-foreign-client")
    for username in ("sso-admin", "sso-reader"):
        existing = ak_list(client, env, "core/users/", username=username)
        if any(u.get("attributes", {}).get("asm_smoke_fixture") != MARKER for u in existing):
            raise SmokeFailure("authentik-foreign-user")
    for name in ("s3-admins", "data-team", "team", "sub"):
        groups = ak_list(client, env, "core/groups/", name=name)
        if any(g.get("attributes", {}).get("asm_smoke_fixture") != MARKER for g in groups):
            raise SmokeFailure("authentik-foreign-group")
    certificates = ak_list(client, env, "crypto/certificatekeypairs/", name="authentik Self-signed Certificate")
    certificates = [c for c in certificates if c.get("private_key_available")]
    if len(certificates) != 1:
        raise SmokeFailure("authentik-signing-certificate")
    blueprint = json.loads((ROOT / "docker/sso/authentik/blueprint.yaml").read_text(encoding="utf-8"))
    if blueprint.get("metadata", {}).get("labels", {}).get("asm_smoke_fixture") != MARKER:
        raise SmokeFailure("authentik-blueprint-marker")
    replacements = {
        "__SSO_DEMO_PASSWORD__": env["SSO_DEMO_PASSWORD"],
        "__SSO_CLIENT_SECRET__": env["SSO_CLIENT_SECRET"],
        "__SIGNING_KEY__": certificates[0]["pk"],
    }

    def render(value):
        if isinstance(value, dict):
            return {k: render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [render(v) for v in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    # JSON is a YAML subset. Native blueprint import handles dependencies and
    # password hashing; no alternate provider object writer or ASM mapper exists.
    result = request(
        client,
        "authentik-blueprint-import",
        "POST",
        AK + "managed/blueprints/import/",
        headers=ak_headers(env),
        files={"file": ("asm-smoke.yaml", json.dumps(render(blueprint)), "application/yaml")},
    )
    if not result.get("success"):
        raise SmokeFailure("authentik-blueprint-import")


def verify_authentik(client, env):
    apps = ak_list(client, env, "core/applications/", slug="asm")
    providers = ak_list(client, env, "providers/oauth2/", client_id="asm")
    if len(apps) != 1 or apps[0].get("meta_description") != MARKER or len(providers) != 1:
        raise SmokeFailure("authentik-seed")
    provider = providers[0]
    if (
        apps[0].get("provider") != provider["pk"]
        or provider.get("client_type") != "confidential"
        or not provider.get("signing_key")
        or provider.get("include_claims_in_id_token") is not True
        or provider.get("redirect_uris")
        != [{"matching_mode": "strict", "url": url, "redirect_uri_type": "authorization"} for url in CALLBACKS]
    ):
        raise SmokeFailure("authentik-client")
    scopes = ak_list(client, env, "propertymappings/provider/scope/")
    attached = [scope for scope in scopes if scope["pk"] in provider["property_mappings"]]
    if not {"openid", "profile", "groups"}.issubset({scope["scope_name"] for scope in attached}):
        raise SmokeFailure("authentik-client-scopes")
    if not any(
        s in attached
        and s["expression"] == 'return {"groups": list(request.user.ak_groups.values_list("name", flat=True))}'
        for s in scopes
    ):
        raise SmokeFailure("authentik-id-token-groups")
    for username in ("sso-admin", "sso-reader"):
        users = ak_list(client, env, "core/users/", username=username)
        if (
            len(users) != 1
            or not users[0].get("is_active")
            or users[0].get("attributes", {}).get("asm_smoke_fixture") != MARKER
        ):
            raise SmokeFailure("authentik-demo-users")


def verify_keycloak(client, env):
    token = request(
        client,
        "keycloak-bootstrap",
        "POST",
        KC + "/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "smoke-bootstrap",
            "password": env["SSO_KEYCLOAK_ADMIN_PASSWORD"],
        },
    )["access_token"]
    headers = {"Authorization": "Bearer " + token}
    base = KC + "/admin/realms/asm-smoke"
    realm = request(client, "keycloak-realm", "GET", base, headers=headers)
    if realm.get("attributes", {}).get("asm_smoke_fixture") != MARKER:
        raise SmokeFailure("keycloak-realm-marker")
    clients = request(client, "keycloak-client", "GET", base + "/clients", headers=headers, params={"clientId": "asm"})
    if len(clients) != 1:
        raise SmokeFailure("keycloak-client")
    conf = clients[0]
    if (
        conf.get("publicClient")
        or conf.get("redirectUris") != CALLBACKS
        or conf.get("attributes", {}).get("pkce.code.challenge.method") != "S256"
    ):
        raise SmokeFailure("keycloak-client")
    mappers = request(
        client,
        "keycloak-id-token-groups",
        "GET",
        base + "/clients/" + conf["id"] + "/protocol-mappers/models",
        headers=headers,
    )
    for claim, full in (("groups", "true"), ("groups_flat", "false")):
        if not any(
            m.get("protocolMapper") == "oidc-group-membership-mapper"
            and m.get("config", {}).get("claim.name") == claim
            and m["config"].get("full.path") == full
            and m["config"].get("id.token.claim") == "true"
            for m in mappers
        ):
            raise SmokeFailure("keycloak-id-token-groups")
    for username in ("sso-admin", "sso-reader"):
        users = request(
            client,
            "keycloak-demo-users",
            "GET",
            base + "/users",
            headers=headers,
            params={"username": username, "exact": "true"},
        )
        if len(users) != 1 or not users[0].get("enabled"):
            raise SmokeFailure("keycloak-demo-users")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--init-runtime", action="store_true")
    modes.add_argument("--select", choices=ISSUERS)
    modes.add_argument("--verify-only", action="store_true")
    parser.add_argument("--image", default=os.environ.get("ASM_SMOKE_IMAGE", ""))
    parser.add_argument("--provider", choices=ISSUERS, default="keycloak")
    parser.add_argument("--confirm-local-smoke", action="store_true")
    parser.add_argument("--source", action="store_true", help="initialize source-only mode without an ASM image")
    args = parser.parse_args()
    path = args.env_file or RUNTIME
    try:
        if args.init_runtime:
            init_runtime(path, args.image, args.provider, source=args.source)
            print("PASS runtime-env-created; protect its Windows ACL; demo password: LocalSsoDemo1!")
            return 0
        env = {**(read_env(path) if path.exists() else {}), **os.environ}
        require_local(env, args.confirm_local_smoke)
        if args.select:
            # Only selection changes; secrets, subjects, clients and IdPs persist.
            stored = read_env(path)
            stored.update(selection(args.select))
            write_runtime(path, stored)
            print("PASS provider-selection; recreate app with the updated env file")
            return 0
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            wait_for(lambda: verify_keycloak(client, env), "keycloak-seed")
            if not args.verify_only:
                seed_authentik(client, env)
            wait_for(lambda: verify_authentik(client, env), "authentik-seed")
        print("PASS keycloak-seed authentik-seed; login flows still require owner smoke")
        return 0
    except SmokeFailure as exc:
        print("FAIL " + str(exc), file=sys.stderr)
        return 1
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        # Provider errors/filenames may contain sensitive data. Never dump them.
        print("FAIL local-sso-seed (configuration/readiness); no credentials logged", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
