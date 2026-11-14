# Single sign-on (ASM 1.3.2)

## Keycloak — configure this first

Use a dedicated OpenID Connect client. These examples use generic domains;
they do not change an existing deployment's infrastructure.

1. Set ASM's canonical `PUBLIC_URL=https://s3.example.com` (origin only, no
   path or trailing slash). ASM derives the callback as
   `https://s3.example.com/api/auth/oidc/callback`, never from Host or
   X-Forwarded headers. Subpath deployment is unsupported.
2. In the Keycloak realm, open its OpenID Endpoint Configuration. Copy the
   discovery document's `issuer` **exactly**, including the realm path and any
   trailing slash, into `OIDC_ISSUER`. For example,
   `https://identity.example.com/realms/storage`. ASM does not normalize it.
3. Create an OpenID Connect client `asm`: Client authentication **On**
   (confidential), Standard flow **On**, Implicit flow **Off**, Direct access
   grants **Off**. Set the exact callback above as the only Valid redirect URI;
   do not use a wildcard. Configure PKCE code challenge method **S256**.
   ASM uses authorization code flow and `client_secret_basic` at the token endpoint.
4. Create an assigned client scope `groups` with a Group Membership mapper:
   Token claim name `groups`, Add to ID token **On**, Full group path **On**.
   Request `openid profile groups`; add `email` only if an email claim is needed.
   A user in nested group `team/sub` then carries literal `/team/sub`.
   A flat mapper (Full group path **Off**) instead emits `data-team`.
   These are distinct values: configure separate ASM rules, never strip slashes.
   For the fixture, a second flat mapper emits `groups_flat`; its rule explicitly
   names that claim. **UserInfo-only groups do not work:** ASM 1.3.2 reads the
   ID token and has no UserInfo fallback.
5. Supply `OIDC_CLIENT_ID=asm` and the client secret through runtime
   `OIDC_CLIENT_SECRET` or `OIDC_CLIENT_SECRET_FILE`. The file wins, including
   when unreadable or empty (startup fails rather than falling back to env).
   Never store a client secret in `config.json`, exports, logs or public examples.

Merge this policy with your existing S3 roles; `reader` must name an actual role
with an appropriate bucket allow-list. The configuration does not create S3
read-only credentials: enforce object-write restrictions in the storage policy.

```json
{
  "auth": {
    "local_login": "all",
    "oidc": {
      "display_name": "Company SSO",
      "scopes": ["openid", "profile", "groups"],
      "username_claim": "preferred_username",
      "groups_claim": "groups",
      "session_max_minutes": 180,
      "role_mapping": {
        "mode": "sync",
        "require_match": true,
        "rules": [
          { "claim": "groups", "value": "/s3-admins", "admin": true },
          { "claim": "groups", "value": "/team/sub", "roles": ["reader"] },
          { "claim": "groups", "value": "data-team", "roles": ["reader"] },
          { "claim": "groups_flat", "value": "data-team", "roles": ["reader"] }
        ]
      }
    }
  }
}
```

Choose the rules for your actual ID-token claim shape; a flat `groups` mapper
needs `s3-admins` instead of `/s3-admins` for its explicit admin rule. Matching
is exact and case-sensitive. Rules union their existing roles, and only an
explicit `admin: true` grants administrator status. A rule granting only missing
roles does not qualify. `groups_claim` is descriptive configuration, not a
provider-specific rewrite of rule claim paths.

### Mapping, freshness and sessions

`sync` is the default: accepted logins replace roles/admin from current rules.
`initial` grants only at account creation and permits later manual grants.
Both modes re-evaluate eligibility on every login; `require_match` must be
`true`. There is no background synchronization or IdP admin credential in ASM.

Applied-sync authorization expires **exactly seven days** after the last
accepted SSO login, including PATs, downloads and destructive retries. The
boundary itself is denied; a NULL deadline fails closed. There is no
`authz_max_days` override. PAT use, failed login, config save and Enable never
renew freshness. Initial accounts' PATs remain locally controlled by grants,
disable and revocation. Initial denial preserves manual grants/admin/default
role, bumps the session epoch and refuses login without freshness renewal.

The owner confirmed this transition policy on 2026-11-13. Changing global
configuration alone changes no account's applied mode, epoch, grants or deadline;
existing sessions are untouched until a login outcome changes account state.

| Event                                                    | sync → initial                                                                                                                       | initial → sync                                                                                                                                                    |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Existing session before another callback                 | Remains applied-sync; prior seven-day deadline enforced, expired/NULL denied.                                                        | Remains applied-initial; ordinary expiry/epoch/status checks.                                                                                                     |
| Existing PAT before another callback                     | Prior sync deadline remains; config cannot revive an expired PAT.                                                                    | Local disable/revoke/grant controls; no new freshness denial.                                                                                                     |
| Accepted callback                                        | Preserve current grants/admin; apply initial and clear deadline. Other epoch-valid credentials now follow initial.                   | Replace grants/admin, reconcile default role; apply sync with now + exactly seven days. Other epoch-valid credentials use that deadline.                          |
| Mapping-denied callback                                  | Preserve grants/admin/default role; epoch +1, no login/renewal; applied-sync and old deadline remain. PAT still obeys that deadline. | Clear grants/admin/default role, expire stored deadline; epoch +1, no login; applied-initial remains. PAT stays locally controlled but has no cleared privileges. |
| Disabled callback, including Disable before final commit | No callback mutation or new session; Disable's own epoch change stands. Enable does not renew or apply a mode.                       | Same; unrevoked PATs restored by Enable still use the unchanged applied mode.                                                                                     |

In unchanged modes, sync denial clears managed privileges and expires the
deadline; initial denial preserves manual privileges. Both bump epoch, refuse
login and leave applied mode unchanged. A successful login is the only event
that changes applied mode.

Session lifetime is a strict integer **1–10080 minutes**, effective default
**180**. `session_max_minutes: null` inherits `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`,
validated against the same range; invalid inheritance fails validation. Settings
are validated at startup and on reload/save. Invalid runtime reload retains
last-good config and refuses its triggering operation. Admin settings are
read-only; derived runtime fields and secrets are not stored policy.

Production requires HTTPS and Secure cookies. `COOKIE_SECURE=false` with HTTPS
`PUBLIC_URL` is invalid. Development HTTP requires `OIDC_ALLOW_INSECURE_HTTP=true`
and `COOKIE_SECURE=false`. HTTP permission grants **no** private-network access.
Private IdPs additionally require every used private endpoint origin, including
initial discovery, in `OIDC_ALLOWED_PRIVATE_ORIGINS` (comma-separated exact
scheme/host/effective-port origins, empty by default). No paths or wildcards.
All DNS answers and the connected peer are checked; TLS/SNI verification,
no redirects/proxy environment, 5-second timeout and streamed 1 MiB limit apply
to discovery, refresh, JWKS and token exchange. Adjacent origins gain nothing.

Discovery outages make SSO unavailable without changing local-login policy.
Reverse proxies must redact `code`, `state`, `token`, `id_token_hint`,
`client_secret`, `code_verifier`, `refresh_token` and cookies. Application
redaction does not sanitize browser traces; do not collect authentication traces,
videos, screenshots, raw network logs or HTML reports for OIDC smoke.

### Local recovery and account lifecycle

`LOCAL_LOGIN` overrides `auth.local_login`: `all` (default), `admins` (local
administrators only) or `off`. Off hides local login and never automatically
falls back; off without configured OIDC is a startup error. For recovery,
explicitly set `LOCAL_LOGIN=admins` and restart ASM, then use its console CLI:

```bash
# Run inside the ASM container, or use uv run python -m ... in source mode.
python -m another_s3_manager.reset_admin_password --enable USER --yes
python -m another_s3_manager.reset_admin_password --local USER --yes
```

`--enable USER` is standalone: no password, reset, source change, epoch bump or
freshness renewal. `--local USER [PASSWORD]` validates a usable password, then
atomically writes local source/hash/CLI provenance, clears applied mode/deadline
and increments epoch, preserving disabled and grants. Enabling is separate.
Prefer the interactive password prompt; positional passwords are visible in
process arguments. `--enable` and `--local` are mutually exclusive; repeated
target flags are usage errors. Named users must exist and are never created.

Legacy `[PASSWORD] [--yes]` resets/recreates built-in local `admin`; an OIDC admin
requires explicit `--local`. Interactive execution asks for confirmation unless
`--yes`, then prompts for and confirms a missing password. Non-TTY requires
`--yes` and an explicit password for reset/local (otherwise exit 2); Enable needs
no password. Missing target, abort, mismatch or validation failure exits 1 and
mutates nothing. Invalid/repeated flag grammar exits 2. With unreadable recovery
config, the fallback policy is minimum 8 characters, one uppercase, lowercase and
digit, and zero required special characters. A callback after console local
recovery cannot restore OIDC source or grants.

Disable prevents SSO login/JIT recreation and invalidates sessions; Enable does
not revive old web sessions or renew freshness. Delete allows JIT recreation
when the IdP still qualifies. Identities are `(issuer, subject)`: no email/name
auto-link and no self-link/unlink/convert UI. Changing issuer requires isolated
new identities, reviewed re-grants and disabling old accounts, or postponing a
migration requiring linkage until a supported tool exists. Do not edit identity
rows with raw SQL.

One browser cookie jar has one active ASM account; the last callback Set-Cookie
wins. Cross-tab invalidation replaces account/cache state and refreshes
authoritative me/CSRF before actions. Use separate browser profiles/private
sessions to compare users. **Logout clears ASM's cookie only**: it does not end
the IdP session or revoke a copied ASM cookie. Visiting SSO again may silently
sign the same IdP user in. To smoke the second user, use an isolated browser
session or explicitly sign out at the IdP first.

### Upgrade and recovery

Before upgrade, take a consistent SQLite online backup or stop ASM before
backing up its data, and include config. Copying only a live database without
its WAL handling is unsafe. Previous-image startup can fail on unknown Alembic
revision `c131a001`; N-1-shaped SQL inserts do not prove startup compatibility.
The manager must obtain remote actual N-1 image startup evidence on an isolated
upgraded database copy. Do not promise image-only rollback or use manual stamp
or production schema downgrade. Recovery is a **forward-fix**, or restoration
of a consistent **pre-release backup including config**, explicitly losing
subsequent changes. Older code cannot enforce new controls even if it starts.

## Authentik

1. Use an isolated instance/tenant (brand). Create an OAuth2/OpenID Provider and
   an Application with slug `asm` assigned to that provider. Use the normal
   authentication flow and an authenticated authorization flow; the fixture uses
   implicit consent. This does not bypass authentication.
2. Select a confidential client, authorization code grant, exact ASM callback and
   an **RSA signing certificate (RS256)**. Without Signing Key, Authentik issues
   symmetric tokens that ASM rejects. ASM sends PKCE S256 and client_secret_basic;
   do not enable password or implicit grants for ASM.
3. Attach an OAuth2 Scope Mapping with Scope name `groups` and expression
   `return {"groups": list(request.user.ak_groups.values_list("name", flat=True))}`.
   Attach the `openid` scope mapping and a profile mapping for `preferred_username`
   as well. Enable **Include
   claims in id_token**; request `openid profile groups`. UserInfo alone is
   insufficient.
4. Assign the users to `s3-admins` or `data-team`; use literal `groups` rules for
   `s3-admins` (explicit admin) and `data-team` (`reader`). These are flat names.
   The fixture also creates parent `team`/child `sub`; it does not rewrite those
   names into Keycloak's `/team/sub`.
5. Copy the application's exact discovery issuer into `OIDC_ISSUER`. The
   fixture uses per-provider issuer
   `http://authentik.sso.test:9002/application/o/asm/`, including its trailing
   slash. Supply client secret through runtime env/file, as for Keycloak.

The blueprint is JSON (a YAML subset), using `state: created` so manual edits
survive reruns. The seeder substitutes runtime passwords/client secret and the
generated signing certificate identifier before native blueprint import. No
private key is tracked. Built-in `akadmin` and system users are separate from
the two demo users.

## Google (recipe only)

Create a Web application OAuth client, configure consent/test-user access and
register the exact ASM callback. Use the published issuer and confidential
client secret; request `openid profile email`. Google does not supply fixture
group claims. A literal `hd` rule can grant an existing ASM role, but additionally
requires boolean `email_verified: true`; absent/false/string verification does
not qualify. There is no `allowed_email_domains` setting. A login hint is not
authorization. Review actual ID-token claims and explicit admin rules.

## Microsoft Entra ID (recipe only)

Register a single-tenant Web application with exact callback and secret. Copy
the tenant-specific v2 discovery issuer exactly; request `openid profile email`.
Configure ID-token groups and use literal group object IDs in ASM rules. Groups
overage is treated as no groups; ASM does not call Graph. Use group filtering or
application roles emitted in `roles` with rules naming that claim. An independent
effective app-role rule may qualify during overage. Never grant admin merely by
matching a display name/email.

Release real-provider smoke covers **Keycloak and Authentik only**. Google/Entra
recipes are not runtime verification claims. There is no UserInfo merge, linking
UI, RP logout or MCP OAuth in 1.3.2.

## Isolated, no-build release smoke

This is **local-only development tooling**, never a production deployment.
Reserve several GiB of Docker RAM (start with at least 4 GiB available), image/DB
disk space and time for two IdPs to initialize. These are planning allowances,
not measured limits; observe actual usage. Existing MinIO seeding uploads over
10,000 tiny pagination/virtualization objects. Avoid heavy concurrent local work.
Only the owner starts services for final release smoke. Offline tests do not
prove that the stand has booted or login works.

### Pins and provider formats

Selected against official sources on 2026-11-14; no image pulls/startup are implied:

| Component                   | Pin and official reference                                                                                                                                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keycloak                    | `quay.io/keycloak/keycloak:26.8.2` — [release](https://github.com/keycloak/keycloak/releases/tag/26.8.2); dev H2 persists in its own volume.                                                                                                      |
| Authentik server and worker | `ghcr.io/goauthentik/server:2026.8.5` — [release](https://github.com/goauthentik/authentik/releases/tag/version%2F2026.8.5), [versioned Compose](https://github.com/goauthentik/authentik/blob/version/2026.8.5/lifecycle/container/compose.yml). |
| PostgreSQL                  | `postgres:16.16-alpine3.23` — same major as the versioned Authentik Compose, exact tag from the [official image manifest](https://github.com/docker-library/official-images/blob/master/library/postgres).                                        |
| ASM, seed, volume init      | Required `ASM_SMOKE_IMAGE`, the manager's tested remote-built OIDC image. No latest default or invented APP_VERSION.                                                                                                                              |
| MinIO and client            | Unchanged digest pins from the [existing overlay](../docker/docker-compose.minio.yml) and [seeder](../scripts/ci/seed-minio.sh).                                                                                                                  |

Authentik's versioned Compose requires PostgreSQL, server and worker, without
Redis. This OIDC stand needs no Docker socket/outpost. Source contracts:
[bootstrap env](https://docs.goauthentik.io/install-config/automated-install/),
[create-only blueprint entries](https://docs.goauthentik.io/customize/blueprints/v1/structure/),
[Keycloak native import](https://www.keycloak.org/server/importExport).
Pins/native formats are source-checked; runtime compatibility, seed convergence
and login are still unobserved until the owner runs them.

### Canonical names, ports and data

Add these local DNS/hosts entries on the browser/source-ASM host, through your
OS's hosts editor. Docker aliases supply the same names internally:

```text
127.0.0.1 keycloak.sso.test authentik.sso.test minio
```

| Component               | Canonical URL                                        |
| ----------------------- | ---------------------------------------------------- |
| Keycloak                | `http://keycloak.sso.test:8180/realms/asm-smoke`     |
| Authentik               | `http://authentik.sso.test:9002/application/o/asm/`  |
| Image ASM               | `http://localhost:8080`                              |
| Source ASM through Vite | `http://localhost:5173`                              |
| MinIO                   | `http://minio:9000`; console `http://localhost:9001` |

Each IdP listens on the same port inside its container as on the host. Container
localhost is not host localhost. There is no issuer/response rewriting or token
endpoint override. Clients permit exactly the two development callbacks at ASM
8080/5173; production should register only its needed callback. Dev HTTP and
private-origin admission are separate: the overlay explicitly allows only
`http://keycloak.sso.test:8180,http://authentik.sso.test:9002`.

All published ports are loopback-only; unused dependency ports stay unexposed.
Require Compose **>=2.24.4** for `ports: !override`, which replaces inherited
MinIO wildcard bindings. Appending loopback ports would leave those originals.
See the [official merge contract](https://docs.docker.com/reference/compose-file/merge/#replace-value).

Compose only the MinIO overlay and new SSO overlay with `--project-directory .`.
Never include ordinary `docker-compose.yml` (it inherits build, ordinary `.env`,
container name and `./data`). The new overlay defines a complete image-based ASM,
overrides the MinIO container name and uses the dedicated `asm-sso-smoke` project.
Stop conflicting stands on these reserved ports first.

ASM data volumes are `asm-sso-smoke-keycloak-data` and
`asm-sso-smoke-authentik-data`, selected by `SSO_PROVIDER`. IdP and MinIO data
are independently persisted. Selecting an issuer is not identity migration.
The read-only fixture config supplies `reader`/`admin` MinIO roles for
`e2e-test`, using public MinIO demo credentials; reader disables deletion, not
S3 writes generally. For real read-only storage use restricted S3 credentials.
Normal config validation/reload applies to external edits; recreate app after
atomic replacement of a bind-mounted config file (otherwise an old inode may
remain mounted). Never overwrite owner config or mount ordinary `./data`.

### Offline checks

The manager supplies `docker/sso/.env.example` with unusable, public offline
placeholders. If absent, tests/checker explicitly skip dependent checks and those
gates remain pending. Never start/pull with that example. No ordinary `.env` is
required:

```bash
uv run pytest -o addopts= tests/test_sso_smoke_fixtures.py
docker compose --project-directory . --env-file docker/sso/.env.example -f docker/docker-compose.minio.yml -f docker/docker-compose.sso.yml --profile sso-smoke config --quiet
uv run python scripts/smoke/check-sso.py --check-compose-bindings
```

The checker verifies Compose version and captures that exact merged
`config --format json` invocation in memory. Missing/empty/wildcard published
host_ip is rejected for every service, including inherited MinIO ports. Output
is pass/fail and component/port identifiers only, never rendered env/secrets.
Syntax, safe bindings, full readiness and accepted flows are separate evidence.

### Image mode — owner commands

First export the manager-supplied tested `ASM_SMOKE_IMAGE` reference. It must
contain the OIDC code; do not substitute an unrelated image. Health/app-info must
show the actual version under test; the fixture does not override APP_VERSION.

```bash
# Once: refuses existing runtime file, generates secrets without printing them.
uv run python scripts/smoke/seed-sso.py --init-runtime --image "$ASM_SMOKE_IMAGE"
sso() {
  docker compose --project-directory . --env-file data/sso/.env.local \
    -f docker/docker-compose.minio.yml -f docker/docker-compose.sso.yml \
    --profile sso-smoke "$@"
}
sso pull
sso up -d --no-build
uv run python scripts/smoke/check-sso.py --confirm-local-smoke

# SSO_PROVIDER=authentik: the selector updates provider AND canonical issuer.
uv run python scripts/smoke/seed-sso.py --select authentik --confirm-local-smoke
sso run --rm --no-deps sso-init-data
sso up -d --no-build --no-deps --force-recreate app
uv run python scripts/smoke/check-sso.py --confirm-local-smoke

# Restore the previous Keycloak-backed ASM database.
uv run python scripts/smoke/seed-sso.py --select keycloak --confirm-local-smoke
sso run --rm --no-deps sso-init-data
sso up -d --no-build --no-deps --force-recreate app

# Stop non-destructively; do not automate volume deletion.
sso stop
```

Fresh Authentik-first initialization accepts `--provider authentik`. Both IdPs
stay running while only app is recreated with its selected data. Avoid stale
exported SSO_PROVIDER/OIDC_ISSUER: shell variables override Compose env-file
values. Keep secrets in ignored `data/sso/.env.local`, owner-only POSIX mode;
on Windows explicitly restrict its ACL to your user. Keep the same secrets with
persistent volumes: bootstrap env does not reset an initialized provider.

Both demo users use env-supplied public, local-only password `LocalSsoDemo1!`.
Never reuse it. Keycloak `smoke-bootstrap` password and Authentik bootstrap token
are generated and never printed. Authentik built-in `akadmin` uses the demo
password. No production credentials/private keys are tracked.

Keycloak imports the marked realm natively and skips an existing realm.
Authentik's supplemental seeder waits for bootstrap, supplies runtime values and
the generated certificate identifier to native blueprint import in memory.
Create-only entries preserve manual state. Reruns do not rotate subjects/clients,
reset passwords or restore manually removed group membership. Foreign/colliding
objects fail instead of being overwritten. Targets are fixed local fixture URLs;
runtime marker and `--confirm-local-smoke` are mandatory. This is development
provisioning, not ASM-72 background IdP synchronization.

### Source mode — no published OIDC image needed

Use preinstalled Python/Node dependencies; no image/frontend build. For a fresh
stand initialize below. Reusing provider volumes requires their **original**
runtime secrets; never regenerate over retained data. Source initialization sets
an intentionally unpullable image placeholder only to parse Compose. Selected
services never pull/use it.

```bash
uv run python scripts/smoke/seed-sso.py --init-runtime --source
# Define sso() as above; start ONLY these services, excluding app/init/seed.
sso pull keycloak authentik-db authentik authentik-worker minio minio-seed
sso up -d --no-build keycloak authentik-db authentik authentik-worker minio minio-seed
uv run python scripts/smoke/seed-sso.py --confirm-local-smoke

# Backend terminal (Bash), from repository root. Source only this generated
# plain KEY=value file, never a downloaded/provider-supplied shell file.
set -a
. data/sso/.env.local
set +a
export DATA_DIR="data/sso/native-$SSO_PROVIDER"
mkdir -p "$DATA_DIR"
if [ ! -f "$DATA_DIR/config.json" ]; then
  cp docker/sso/asm/config.json "$DATA_DIR/config.json"
fi
export S3_FILE_MANAGER_CONFIG="$DATA_DIR/config.json"
export JWT_SECRET_KEY="$SSO_JWT_SECRET" ADMIN_PASSWORD="$SSO_DEMO_PASSWORD"
export OIDC_CLIENT_ID=asm OIDC_CLIENT_SECRET="$SSO_CLIENT_SECRET"
export OIDC_ALLOW_INSECURE_HTTP=true COOKIE_SECURE=false UVICORN_HOST=127.0.0.1
export OIDC_ALLOWED_PRIVATE_ORIGINS=http://keycloak.sso.test:8180,http://authentik.sso.test:9002
unset OIDC_CLIENT_SECRET_FILE
uv run python -m another_s3_manager.main

# Separate frontend terminal, from repository root:
cd frontend
npm run dev -- --host localhost

# Separate checking terminal, from repository root:
uv run python scripts/smoke/check-sso.py --source --confirm-local-smoke
```

Open canonical `http://localhost:5173`; Vite proxies API/callback and health to 8080. Native SQLite directories `data/sso/native-keycloak` and
`data/sso/native-authentik` are separate from ordinary app data and image-mode
volumes. The host `minio` alias makes the same fixture role endpoint work.
Source mode copies the fixture once into its isolated runtime directory, keeping
startup config migration and manual policy edits away from the tracked fixture.
The copy is never automatically overwritten; review explicit fixture updates.

For Authentik, stop only native backend, select provider in an unexported command
terminal, then re-source runtime env and repeat backend exports with the new
DATA_DIR. Leave Vite and IdPs running. To reuse image-mode runtime for source
mode, change only PUBLIC_URL to `http://localhost:5173`, keeping original secrets.
Stop native servers with Ctrl-C and Compose services with `sso stop`.

### Readiness and owner acceptance

Runtime checker never starts containers. It checks healthy MinIO, both IdPs,
PostgreSQL and worker; completed seed/init; exact discovery issuer, client and
ID-token mapper setup; ASM API, frontend entry assets, matching health/app-info
versions, local-admin login/current-account and MinIO bucket/object access
through ASM (usable SQLite/storage). Source mode substitutes native ASM/Vite for
app/init/seed containers and checks IdP setup via admin APIs. HTTP is bounded;
failures name a component without logging tokens or bodies. Baseline readiness
expects local-login all and the original local admin password; intentional
owner policy/password changes may fail it during acceptance. Never reset those
changes just to make readiness green.

Owner smoke after all 1.3.2 PRs, on **each** provider:

- Log in as both users in isolated sessions. Check explicit admin vs reader
  visibility and current MinIO `e2e-test` access.
- Change group membership, log in again and observe sync replacement. In initial
  mode preserve a manually added grant but refuse a subsequently unmatched login.
- Check local-login all/admins/off rendering/recovery, Disable/Enable, no freshness
  renewal and Delete's JIT warning.
- Log out of ASM; retained IdP session is expected. Use an isolated session or IdP
  sign-out to test the other user.
- PAT's seven-day boundary is covered by existing controlled-clock Access tests;
  the owner need not wait a week or edit real timestamps.

Record only observations. Missing component means **incomplete stand**, with
affected flows blocked; fixture tests are not IdP startup evidence. No
Google/Entra tenants or MCP OAuth clients are required. Full suites/builds and
fake-OP browser validation stay in remote CI. Release review, CI and accepted
smoke precede the owner's `v1.3.2` tag; ASM has no `-rc`.
