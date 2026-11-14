#!/usr/bin/env python3
"""Offline merged-port validation, or explicit full-stand readiness. Never starts services."""

import argparse
import ipaddress
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISSUERS = {
    "keycloak": "http://keycloak.sso.test:8180/realms/asm-smoke",
    "authentik": "http://authentik.sso.test:9002/application/o/asm/",
}
EXAMPLE = "docker/sso/.env.example"
COMPOSE = [
    "docker",
    "compose",
    "--project-directory",
    ".",
    "--env-file",
    EXAMPLE,
    "-f",
    "docker/docker-compose.minio.yml",
    "-f",
    "docker/docker-compose.sso.yml",
    "--profile",
    "sso-smoke",
]


def validate_compose_bindings(model):
    """Validate effective CLI JSON, including inherited/appended publications."""
    failures = []
    for name, service in model.get("services", {}).items():
        for port in service.get("ports", []):
            if not isinstance(port, dict):
                failures.append(f"{name}:unknown-port")
                continue
            try:
                valid = ipaddress.ip_address(port.get("host_ip", "")).is_loopback
            except ValueError:
                valid = False
            if not valid:
                failures.append(f"{name}:{port.get('target', 'unknown-port')}")
    return failures


def captured(command):
    """Rendered config and subprocess errors remain in memory, never in logs."""
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("compose-command")
    return result.stdout


def check_compose_bindings():
    if not (ROOT / EXAMPLE).is_file():
        print("SKIP compose-bindings: manager must supply docker/sso/.env.example")
        return 0
    version = captured(["docker", "compose", "version", "--short"])
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?\s*", version)
    if not match or tuple(map(int, match.groups())) < (2, 24, 4):
        print("FAIL compose-version: require >=2.24.4")
        return 1
    # This exact offline command is the merged-model proof; no docker daemon or
    # service startup is needed. Do not print model, env values or stderr.
    model = json.loads(captured([*COMPOSE, "config", "--format", "json"]))
    failures = validate_compose_bindings(model)
    if failures:
        for identifier in failures:
            print("FAIL binding " + identifier)
        return 1
    print("PASS compose-bindings")
    return 0


def check_services(command, source):
    output = captured([*command, "ps", "--all", "--format", "json"])
    try:
        rows = json.loads(output)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
    # Compose versions have used either a JSON array or JSON Lines for ps.
    if isinstance(rows, dict):
        rows = [rows]
    by_name = {row["Service"]: row for row in rows}
    running = ["minio", "keycloak", "authentik-db", "authentik", "authentik-worker"]
    complete = ["minio-seed"]
    if not source:
        running.append("app")
        complete.extend(["sso-init-data", "sso-seed"])
    for name in running:
        row = by_name.get(name, {})
        if row.get("State") != "running" or row.get("Health") != "healthy":
            raise RuntimeError(name)
    for name in complete:
        row = by_name.get(name, {})
        if row.get("State") != "exited" or row.get("ExitCode") != 0:
            raise RuntimeError(name)


def readiness(args):
    # Reuse provider inventory validation, not any production authentication rule.
    seed = runpy.run_path(str(ROOT / "scripts/smoke/seed-sso.py"))
    env = seed["read_env"](args.env_file)
    seed["require_local"](env, args.confirm_local_smoke)
    command = list(COMPOSE)
    command[5] = str(args.env_file)
    try:
        check_services(command, args.source)
    except json.JSONDecodeError:
        # Older Compose emits one JSON object per line instead of an array.
        raise RuntimeError("compose-ps-format") from None
    import httpx

    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
        request = seed["request"]
        for provider, issuer in ISSUERS.items():
            discovery = request(client, provider + "-discovery", "GET", issuer + "/.well-known/openid-configuration")
            if discovery.get("issuer") != issuer or not all(
                discovery.get(k) for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")
            ):
                raise RuntimeError(provider + "-discovery")
        seed["verify_keycloak"](client, env)
        seed["verify_authentik"](client, env)
        public = "http://localhost:5173" if args.source else "http://localhost:8080"
        if env["PUBLIC_URL"] != public:
            raise RuntimeError("app-canonical-origin")
        health = request(client, "app-api", "GET", public + "/health")
        info = request(client, "app-info", "GET", public + "/api/app-info")
        if health.get("status") != "ok" or not health.get("version") or info.get("app_version") != health["version"]:
            raise RuntimeError("app-version")
        if not args.source and health["version"] in ("dev", "unset"):
            raise RuntimeError("tested-image-version")
        if info.get("auth", {}).get("oidc_available") is not True:
            raise RuntimeError("app-oidc-discovery")
        html = request(client, "app-frontend", "GET", public + "/", as_json=False)
        if b'id="root"' not in html or b"<script" not in html:
            raise RuntimeError("app-frontend")
        scripts = re.findall(rb'<script[^>]+src="([^"]+)"', html)
        if not scripts:
            raise RuntimeError("app-frontend-assets")
        for path in scripts:
            path = path.decode("utf-8")
            if not path.startswith("/") or path.startswith("//"):
                raise RuntimeError("app-frontend-asset-origin")
            asset = request(client, "app-frontend-assets", "GET", public + path, as_json=False)
            if not asset or b"<html" in asset[:200].lower():
                raise RuntimeError("app-frontend-assets")
        # Login + current-account + storage adapter prove initialized SQLite and
        # seeded bucket access through the app, rather than only checking TCP.
        request(
            client,
            "app-sqlite-login",
            "POST",
            public + "/api/login",
            data={"username": "admin", "password": env["SSO_DEMO_PASSWORD"]},
        )
        me = request(client, "app-sqlite-current-account", "GET", public + "/api/me")
        if me.get("username") != "admin":
            raise RuntimeError("app-sqlite-current-account")
        config = request(client, "app-selected-issuer", "GET", public + "/api/config")
        runtime = config.get("auth_runtime", {})
        if runtime.get("issuer") != env["OIDC_ISSUER"] or runtime.get("client_id") != "asm":
            raise RuntimeError("app-selected-issuer")
        buckets = request(client, "minio-seeded-bucket", "GET", public + "/api/buckets?role=admin")
        names = [b if isinstance(b, str) else b.get("name", b.get("Name")) for b in buckets]
        if "e2e-test" not in names:
            raise RuntimeError("minio-seeded-bucket")
        request(client, "minio-seeded-objects", "GET", public + "/api/buckets/e2e-test/files?role=admin&client_load=1")
    print("PASS full-stand-readiness; owner login/mapping/logout smoke remains pending")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-compose-bindings", action="store_true")
    parser.add_argument("--env-file", type=Path, default=ROOT / "data/sso/.env.local")
    parser.add_argument("--source", action="store_true")
    parser.add_argument("--confirm-local-smoke", action="store_true")
    args = parser.parse_args()
    try:
        return check_compose_bindings() if args.check_compose_bindings else readiness(args)
    except RuntimeError as exc:
        print("FAIL " + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print("FAIL smoke-configuration-or-compose; no rendered env logged", file=sys.stderr)
        return 1
    except Exception as exc:
        # SmokeFailure comes from the loaded seed module; it carries only a
        # fixed component label. Never print an arbitrary exception or traceback.
        if type(exc).__name__ == "SmokeFailure":
            print("FAIL " + str(exc), file=sys.stderr)
            return 1
        print("FAIL unexpected-smoke-response; no upstream body logged", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
