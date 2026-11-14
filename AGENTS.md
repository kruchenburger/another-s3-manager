# Project instructions

This file is the canonical project guide shared by Claude Code and Codex.
When this repository is checked out inside the workspace, a session started
directly here must, before planning or editing, read the [workspace root
guide](../../AGENTS.md) and every applicable document in the [neutral contract
directory](../../.harness/contracts/engineering/) completely. Those shared
project obligations remain applicable, but the full workspace harness (MCP,
hooks, roles, and skills) is guaranteed only for sessions started from the
workspace root. In a standalone clone where that parent workspace is absent,
this guide remains self-contained and workspace extras are unavailable. Start
from the workspace root when shared tooling is required.

# Another S3 Manager

## OIDC login (1.3.2)

- Access owns OIDC settings, networking, strict ID-token validation, transactions,
  identity provisioning and literal claim mapping. Web/MCP/CLI/Storage use only
  the Access package root. No migration is added by this feature; PR 2 supplies
  identities, the transaction ledger and applied-mode storage.
- Enable only with `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `PUBLIC_URL` (canonical origin).
  `OIDC_CLIENT_SECRET_FILE` wins over `OIDC_CLIENT_SECRET`; unreadable files fail.
  No secret enters config, export or logs. HTTPS requires Secure cookies.
  `OIDC_ALLOW_INSECURE_HTTP=true` is development-only and does not permit private IPs.
- `OIDC_ALLOWED_PRIVATE_ORIGINS` grants exact scheme/host/effective-port origins.
  All DNS answers and the pinned connected peer are checked before request bytes;
  verified TLS/SNI, no redirects/proxy environment, 5s timeout and 1 MiB streamed
  cap apply to initial discovery, refresh, JWKS and token exchange.
- `LOCAL_LOGIN` overrides `auth.local_login` (`all`, `admins`, `off`; default all).
  Discovery outages never change that policy. Off without OIDC is a startup error.
  Stored `auth.oidc` supports display_name, scopes, username_claim, groups_claim,
  session_max_minutes and role_mapping (`mode`, `require_match`, `rules`).
  Lifetime is integer 1–10080, effective default 180; null inherits validated
  JWT_ACCESS_TOKEN_EXPIRE_MINUTES. require_match=false and authz_max_days are rejected.
- Sync and initial both check eligibility on each login; only accepted SSO login
  changes mapping_mode_applied. Applied-sync sessions/PATs/download/destructive
  retries deny at the stored deadline (exactly seven days); NULL fails closed.
  Initial denial preserves manual grants, bumps epoch and does not renew freshness.
  Disabled callbacks and callbacks after console local recovery mutate nothing.
- All config publishers and callback commits use lock order role_grants_lock →
  config lock → BEGIN IMMEDIATE. No network/hash work under publication locks.
  Invalid runtime reload refuses its triggering operation and retains last-good
  config. Returned snapshots cannot mutate the shared cache. Partial nested saves
  preserve security settings; runtime auth fields never belong in save payloads.
- Console recovery grammar: legacy `[PASSWORD] [--yes]` resets/recreates built-in
  local admin; an OIDC admin requires explicit `--local`. `--enable USER [--yes]`
  only clears disabled, accepts no password and never renews freshness/epoch.
  `--local USER [PASSWORD] [--yes]` atomically writes a usable policy-validated
  local password/source/provenance, clears applied mode/deadline and increments
  epoch, preserving disabled and grants. Both target flags together or repeated
  target flags are usage errors. Named targets must exist; no implicit creation.
  Missing confirmation/password in non-TTY exits 2; missing target, abort, mismatch
  or failed validation exits 1. Unreadable recovery config uses minimum 8, one
  uppercase/lowercase/digit, zero required special characters. Enable is separate.
- Browser cookie jars have one active account; last callback Set-Cookie wins.
  session_identity is opaque, never a JWT; cross-tab signals contain no identity
  or credential. Account actions wait for authoritative me/CSRF after invalidation.
- Logout clears ASM's cookie only: it neither ends the IdP session nor revokes a
  copied cookie. Disable prevents JIT recreation; Delete does not. No linking,
  UserInfo, RP logout, MCP OAuth or background IdP sync is implemented here.
- Reverse proxies must redact code/state/token/id_token_hint/client_secret/
  code_verifier/refresh_token and cookies. Application redaction does not sanitize
  browser traces. OIDC browser CI is remote-only with distinct sites, no traces,
  videos/screenshots/HTML reports/raw logs uploaded, including failure/retry.
  Full suites/builds and image-size measurement remain remote CI obligations.

Lightweight web UI for managing files in S3 and S3-compatible storage.

> **This is a public repository.** Never commit, push, or include in PR descriptions / commit messages / issue bodies any absolute paths from a developer's local filesystem (e.g. `D:\...`, `/Users/...`, `C:\...`, `/home/...`). Specs and plans for this project live out-of-repo per the shared workspace specs-and-plans contract — when referencing them in a PR description, use only the **relative tail** (e.g. `specs/2026-05-02-foo-design.md (out-of-repo)`), never the full absolute path. Personal directory structure leaking into a public repo is a privacy issue and looks unprofessional.

## Stack

- **Backend**: Python 3.13+, FastAPI, Boto3, JWT auth (cookie-based), per-username ban for brute-force defense
- **Frontend**: React + Mantine (Vite); FastAPI serves the built SPA at `/`
- **Deployment**: Docker, Docker Compose, Kubernetes (chart hosted at [github.com/kruchenburger/helm](https://github.com/kruchenburger/helm) — in progress)
- **Package manager**: uv

## Structure

```
another-s3-manager/
├── src/
│   └── another_s3_manager/
│       ├── __init__.py
│       ├── access/          # Access context: authentication, repositories and access policies
│       ├── main.py          # FastAPI app, API endpoints
│       ├── auth.py           # Web auth dependencies and compatibility exports
│       ├── config.py         # Config management (config.json)
│       ├── constants.py      # App constants, paths
│       ├── database.py       # SQLAlchemy engine + session_scope()
│       ├── models.py         # ORM models (User, Role, Ban)
│       ├── s3_client.py      # S3 client, role management
│       ├── users.py          # Import-only compatibility shim for access/users.py
│       ├── utils.py          # Validation, sanitization
│       └── static/app/       # React SPA build output (generated, not tracked)
├── migrations/               # Alembic migrations (env.py + versions/)
├── alembic.ini
├── tests/                    # pytest tests
├── frontend/                 # React + Mantine source
├── data/                     # Runtime data (not tracked)
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── uv.lock
```

## Contexts

The code moves to bounded contexts one release at a time. Rule: every access policy has
exactly one home, and the web routes, MCP tools, move jobs and CLI are thin adapters that
call it and translate its error.

- `access/` — authentication and access policies. `principal.py` owns raw-grant
  principals and account identity normalization; `passwords.py` owns hashing and
  fallback; `sessions.py` owns HS256 JWT and CSRF generation; `users.py` and
  `tokens.py` own persistence and the single role-grants lock. Top-level `users.py`
  and `api_tokens.py` are import-only compatibility shims. Session, local-password
  and bearer authentication use the public service facade; web/MCP adapters keep
  their existing error mapping and dictionary projections. Authorization includes role grants, admin role expansion, bucket allow-lists, the MCP write gate and
  the deletion gate (instance-wide and per role: `deletion_allowed` / `require_delete`), composed by `require_destructive` (role grant, bucket allow-list, then deletion gate). `policies.py` holds pure rules over a passed-in config, `service.py`
  raises `AccessDenied(code, message)` (a `PermissionError` subclass), `__init__.py` is the
  public API. Adapters map `AccessDenied.code` to their own answer in one table each.
- Boundaries are enforced by import-linter (`[tool.importlinter]` in `pyproject.toml`,
  `uv run lint-imports`, also in CI): adapters (`main`, `mcp_server`,
  `reset_admin_password`) do not import each other, `access` imports no adapter, no
  storage module and no web/MCP framework, and code outside `access` imports only its
  package root (`from another_s3_manager import access`), never `access.service` /
  `access.policies` / `access.errors`.
- Access also owns current-account validation, account lifecycle and atomic password/session-epoch
  mutations. `principal_for` is the shared status entry point; its private snapshot seam accepts only
  trusted transaction or freshly loaded per-attempt state. `account_identity` is the single
  `(id, auth_generation)` rule used by sessions, PAT authentication, Storage and move jobs.
  `access/oidc/` owns strict settings, bounded discovery/JWKS/token transport,
  PKCE transactions, literal mapping and atomic identity/JIT persistence.
- Test layout: each policy once at the service level in `tests/access/`, plus a thin
  mapping test per adapter.

## Database

- SQLAlchemy 2.0 (sync) + Alembic for migrations
- SQLite at `<DATA_DIR>/another_s3_manager.db`
- Tables: `users`, `user_roles` (junction), `bans` (FK → users with CASCADE), `api_tokens` (FK CASCADE → users; stores SHA-256 hash of plaintext token, `is_read_only`, `max_read_bytes`, `revoked_at`), `user_identities`, `oidc_login_transactions`
- Users additionally store `auth_source`, `is_disabled`, `auth_generation`, `session_epoch`, nullable `sso_authz_valid_until` and nullable `mapping_mode_applied` (`sync`/`initial`). Applied-sync freshness and login-applied mode transitions are enforced by Access.
- Generation storage stays nullable for N-1-shaped inserts. New users get a random generation; a legacy NULL is materialized atomically before a Principal is returned.
- Identity links have unique issuer/subject and user/issuer constraints with user-delete cascade. The login ledger stores only SHA-256 state hashes and timestamps, is consumed atomically once, and purges at most 100 expired rows per operation.
- Migration `c131a001` follows `35173f08b83b`. Downgrade is test/dev-only and loses the new security fields, identities and ledger. A previous image cannot start on this revision; production recovery is a forward fix or restoring a consistent pre-release backup, losing later changes.
- Module: `database.py` (engine + `session_scope()`), `models.py` (ORM)
- Auto-migration from `users.json` / `bans.json` on first startup (legacy files renamed to `*.migrated.bak`)
- WAL journal mode + `busy_timeout=5000` set on every connection (readers no longer block on writers — matters with the ~40 concurrent boto3 worker threads); escape hatch `SQLITE_JOURNAL_MODE=delete` for network-mounted `DATA_DIR`. Backing up the DB file requires either `sqlite3 .backup` / the online backup API, or stopping the app first — copying `another_s3_manager.db` alone while the app is running can produce a torn snapshot (the `-wal` file holds uncommitted-to-main-file pages). No such backup tooling exists in this repo yet.

## Migration commands

```bash
# Generate a new migration from model changes
uv run alembic revision --autogenerate -m "describe change"

# Apply migrations
uv run alembic upgrade head

# Rollback one step
uv run alembic downgrade -1
```

FK enforcement is explicitly forced OFF for the duration of any migration run
(`migrations/env.py`), then verified clean afterwards via `PRAGMA foreign_key_check`
before the transaction commits. This is a migration-context-only setting: SQLite's
`render_as_batch` (needed for `drop_column`/`alter_column` on SQLite) implements those
ops by recreating the whole table — create new → copy rows → `DROP TABLE` old → rename
— and with FK enforcement on, that `DROP TABLE` fired every `ON DELETE CASCADE`
pointing at the recreated table, silently wiping unrelated child rows (e.g. a `users`
column drop/add used to wipe `user_roles`/`bans`/`api_tokens`). Runtime FK enforcement
(`database.py`'s connect-listener) is untouched — `upgrade head` / `downgrade -1` are
safe to run against a populated database.

## Development Commands

### Isolated real-IdP smoke (1.3.2)

See `docs/sso.md` (Keycloak first, then Authentik). The SSO overlay defines its
own image-based ASM; combine only `docker/docker-compose.minio.yml` and
`docker/docker-compose.sso.yml`, with `--project-directory .` and profile
`sso-smoke`. Never include ordinary `docker-compose.yml` or mount ordinary
`./data`. `ASM_SMOKE_IMAGE` must identify a tested remote-built OIDC image;
source mode uses native ASM + Vite without image/frontend builds. Both IdPs
remain running; provider selection recreates app only, with distinct ASM data.

Selected local offline checks, sequentially (never start the stack as a check):

```bash
uv run pytest -o addopts= tests/test_sso_smoke_fixtures.py
docker compose --project-directory . --env-file docker/sso/.env.example -f docker/docker-compose.minio.yml -f docker/docker-compose.sso.yml --profile sso-smoke config --quiet
uv run python scripts/smoke/check-sso.py --check-compose-bindings
```

Require Compose >=2.24.4 for MinIO `ports: !override`; the checker validates
fully merged JSON in memory without printing env/secrets. If manager-supplied
`docker/sso/.env.example` is absent, skip env-dependent checks explicitly and
report them pending. Fixture pytest does not prove running IdPs. Only the owner
starts the complete stand and accepts both-provider release flows; full suites,
builds and fake-OP browser validation remain remote CI obligations.

### Native development

```bash
# Install dependencies
uv sync

# Linter and formatting
uv run ruff check .
uv run ruff format .

# Context boundaries
uv run lint-imports

# Tests
uv run pytest --cov

# Run locally
JWT_SECRET_KEY=dev-secret uv run python -m another_s3_manager.main

# Docker
docker compose up --build
```

### Frontend Development

```bash
# Install JS deps (one-time, after each pull that touches frontend/package.json)
cd frontend && npm install

# Dev server with hot reload (proxies /api → http://localhost:8080)
cd frontend && npm run dev   # opens on http://localhost:5173

# Production build → bundles into ../src/another_s3_manager/static/app/
# Vendor libs are split into separate chunks (react / mantine / tanstack / icons / gsap)
# via `manualChunks` in `vite.config.ts` so browsers can cache them independently of
# our app code — main entrypoint stays under the 500 KB warning threshold.
cd frontend && npm run build

# Unit tests (Vitest)
cd frontend && npm test

# Type check
cd frontend && npm run lint

# E2E tests (Playwright) — requires `docker compose up` running on port 8080
cd frontend && npx playwright test
```

**Playwright E2E does NOT auto-start the backend** (no `webServer` in
`playwright.config.ts`). Run `docker compose up --build -d` first, otherwise
all E2E tests fail with connection refused. Override target via
`E2E_BASE_URL=http://otherhost:port npx playwright test`.

**Accessibility baseline:** `frontend/tests/e2e/a11y.spec.ts` runs axe-core
(via `@axe-core/playwright`) against every covered route and fails
the build on any `critical`/`serious` violation. WCAG 2.1 AA + best-practice
tags. `moderate`/`minor` are logged but non-blocking. See
[`docs/accessibility.md`](docs/accessibility.md) for the full route list, how
to fix common violations, and the rationale for our theme-level contrast
adjustments (`autoContrast: true` scoped to Button + Badge, plus the
`cssVariablesResolver` pins for dimmed / error / primary-hover, all in
`src/app/theme.ts` and locked by `frontend/tests/unit/themeContrast.test.ts`).

#### E2E specs that need a real S3 backend (MinIO)

`upload-delete.spec.ts` and `special-chars.spec.ts` exercise file
upload/download/delete against a live S3-compatible endpoint. To run them
locally, start an extra MinIO sidecar alongside the app:

```bash
# Bring up app + MinIO + auto-seeded e2e-test bucket
docker compose -f docker-compose.yml -f docker/docker-compose.minio.yml up --build -d

# One-time: register the MinIO-e2e role in data/config.json (or via the admin UI)
docker compose exec -T app python -c "
import json
from another_s3_manager.config import load_config, save_config
cfg = load_config(force_reload=True)
if not any(r['name'] == 'MinIO-e2e' for r in cfg.get('roles', [])):
    cfg.setdefault('roles', []).append({
        'name': 'MinIO-e2e',
        'type': 's3_compatible',
        'access_key_id': 'minioadmin',
        'secret_access_key': 'minioadmin',
        'endpoint_url': 'http://minio:9000',
        'addressing_style': 'path',
        'allowed_buckets': ['e2e-test'],
    })
    save_config(cfg)
"

# Run the two specs
cd frontend && npx playwright test upload-delete.spec.ts special-chars.spec.ts
```

CI runs the same setup via `.github/workflows/ci.yml` `e2e` job — MinIO
booted with `docker run` (so we control the `server /data` CMD that GHA
`services:` can't override), seeded by the same `scripts/ci/seed-minio.sh`.

See [`docs/testing-backends.md`](docs/testing-backends.md) for the MinIO vs ministack (AWS-native assume_role / credentials) test backends.

Local dev requires both servers: backend on `8080` (FastAPI) + Vite on `5173`.
Vite proxies `/api` → backend, so the React app talks to the real backend during
dev. For production-like testing, run `npm run build` then visit
`http://localhost:8080/` (the FastAPI app serves the bundle directly).

**`COOKIE_SECURE=false` is required when running locally over HTTP** — without it
the browser drops the auth cookie.

### SPA serving (Phase 7)

The React SPA owns every path from `/` (the vanilla UI was removed in Phase 7;
old `/v2/*` URLs intentionally have no redirects and render the SPA's 404 page).
It is served by a single catch-all FastAPI route in `main.py` (not a
`StaticFiles` mount) registered at the very end of the file. **Route ordering
invariant: API routes → `/mcp` mount → SPA catch-all LAST** — the catch-all is
greedy, anything registered after it is unreachable. Unknown `api/`/`mcp/`
paths (plus bare `api`/`mcp`/`metrics`/`health`) get a JSON 404 from the
catch-all instead of index.html; bare `/mcp` 307-redirects to `/mcp/`. The
route serves real files when they exist and falls back to `index.html` so
React Router handles client-side navigation. Files are loaded into memory and
returned via `Response` (not `FileResponse`) — kept as a small defensive
choice; SPA bundles are <1MB so the cost is negligible.

## Versioning

Version is derived from git tag via `APP_VERSION` env var. In local development — `dev`.

## Environment Variables

| Variable                          | Required | Default                                 | Description                                                                                                                                                                                             |
| --------------------------------- | -------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `JWT_SECRET_KEY`                  | Yes      | —                                       | JWT signing secret                                                                                                                                                                                      |
| `PORT`                            | No       | `8080`                                  | Server port                                                                                                                                                                                             |
| `UVICORN_HOST`                    | No       | `0.0.0.0`                               | Server bind address                                                                                                                                                                                     |
| `LOG_LEVEL`                       | No       | `info`                                  | Logging level                                                                                                                                                                                           |
| `ADMIN_PASSWORD`                  | No       | `change_me_pls`                         | Admin password — seeds `admin` on first boot, re-applied on every restart while the env still governs it (see README "Admin password lifecycle")                                                        |
| `ADMIN_PASSWORD_FORCE`            | No       | unset                                   | One-shot override: `1`/`true`/`yes` forces `ADMIN_PASSWORD` to overwrite the admin password (even if set via UI/CLI) and hands governance back to the env. Remove after use                             |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | No       | `180`                                   | JWT expiration (minutes)                                                                                                                                                                                |
| `DISABLE_DELETION`                | No       | `false`                                 | Disable file deletion                                                                                                                                                                                   |
| `MAX_FILE_SIZE`                   | No       | `104857600`                             | Max upload file size (bytes, 100MB)                                                                                                                                                                     |
| `MOVE_MAX_OBJECTS`                | No       | `50000`                                 | Maximum unique objects per move; config `move_max_objects` overrides the environment. Enumeration stops immediately above this limit.                                                                   |
| `PRESIGNED_URL_DEFAULT_TTL`       | No       | `3600`                                  | Default presigned-URL lifetime (seconds). Overridable per link up to the max.                                                                                                                           |
| `PRESIGNED_URL_MAX_TTL`           | No       | `604800`                                | Max presigned-URL lifetime (seconds; 7-day SigV4 ceiling). Requests above this are rejected (400).                                                                                                      |
| `ENABLE_LAZY_LOADING`             | No       | `true`                                  | Enable lazy loading for file lists                                                                                                                                                                      |
| `AWS_REGION`                      | No       | from env                                | Default AWS region                                                                                                                                                                                      |
| `S3_FILE_MANAGER_CONFIG`          | No       | `./data/config.json`                    | Path to config file (under DATA_DIR by convention)                                                                                                                                                      |
| `DATA_DIR`                        | No       | `./data` (native), `/app/data` (Docker) | Data dir (SQLite DB + runtime data)                                                                                                                                                                     |
| `SQLITE_JOURNAL_MODE`             | No       | `wal`                                   | SQLite journal mode (`wal`/`delete`). WAL removes reader/writer blocking but needs real POSIX locking + mmap; set `delete` if `DATA_DIR` is on NFS/SMB or a Docker Desktop bind mount on Windows/macOS  |
| `COOKIE_SECURE`                   | No       | `true`                                  | `Secure` flag on auth cookie. MUST be `false` on local HTTP, else browser drops the cookie                                                                                                              |
| `LOG_FORMAT`                      | No       | `text`                                  | Log output format: `text` or `json` (structured, for log aggregators)                                                                                                                                   |
| `ACCESS_LOG_EXCLUDE_PATHS`        | No       | `/,/health,/metrics`                    | Comma-separated paths whose successful (status < 400) `uvicorn.access` lines are dropped — silences health-check / uptime-monitor / Prometheus-scrape noise. Errors always logged; empty value logs all |
| `METRICS_PASSWORD`                | No       | —                                       | Optional basic-auth password for `/metrics` (username `metrics`). If unset, endpoint is open                                                                                                            |

## Features

- Multiple AWS account support (assume_role, profiles, direct credentials)
- S3-compatible services (MinIO, R2, Wasabi)
- JWT authentication via `httpOnly + Secure + SameSite=Strict` cookie + CSRF protection (`X-CSRF-Token` from `/api/me`)
- Web sessions are HS256-only JWTs with required account-generation and session-epoch claims; pre-1.3.1 cookies need one re-login. The cookie and every download-token source use the same Access validator.
- Admins can disable/enable accounts. Access serializes actor revalidation, self-protection, the last-enabled-local-admin guard and the mutation. Disable bumps the session epoch; Enable restores unrevoked MCP tokens but never old web sessions.
- Every real password-hash change (UI, admin reset, CLI, env sync, repository compatibility writers) atomically bumps the session epoch; no-op and provenance-only writes do not. A successful own-password change clears browser auth state and returns to sign-in.
- Logout always clears the ASM cookie. It does not revoke copied cookies, bump the epoch or sign out of the IdP.
- Automatic refresh of expired credentials
- Granular per-role, per-bucket access control
- Role-level delete permission: a role with `"allow_delete": false` in `config.json` blocks deleting (file, folder, move, move cleanup, MCP `delete_file` / `copy_object(delete_source)`) for everyone using it, admins included; before every destructive S3 HTTP attempt (including SDK retries), Storage reloads config and the current user by id and rechecks role grants, bucket access and the deletion gate through Access. Absent = allowed; any non-boolean value = denied. Overwriting a key by upload/copy is not covered. `POST /api/config` keeps the flag when the body omits it
- Brute-force defense: per-username ban (3 failed attempts → 1h ban). **Admins exempt** to avoid DoS on the predictable `admin` username — admin protection must come from deployment layer (see "Production deployment" in README).
- No application-level IP rate limit. Production exposure expects an authenticated reverse proxy (Cloudflare Access, Tunnel, WAF) — that's the right layer for IP-based throttling.
- React SPA at `/`: collapsible sidebar with role/bucket tree, file browser (table+grid toggle, sortable columns — name/size/modified, both views — hover actions, bulk delete, drag-drop upload, preview modal, New folder, Move to… with an optional new name, multi-select and drag-and-drop moves reported in one move tray — there is no separate Rename action by design, since a move is copy + delete); sorting by size/date on a large (truncated) folder loads the whole level first so the order is exact.
- React admin pages on `/admin/*`: separate AdminLayout with grouped sidebar (ACCOUNTS: Users / Bans, INFRASTRUCTURE: Roles / Settings) reachable from "Admin Console" in UserMenu. Users page (CRUD + reset password + self-protect for delete/demote/reset). Bans page (view + unban). Roles page (table + create wizard with type-conditional credential fields + edit form, secret_access_key preserve-on-blank). Settings page (typed global settings with read-only k8s ConfigMap mode, MB↔bytes conversion preserves byte-precision when MB field unchanged). Backend endpoints unchanged from Phase 1; React pages reuse them via TanStack Query plus a small `update_user` self-demote guard.
- Self-service password change at `/change-password`: any authenticated user changes their own password via UserMenu → "Change password". Requires the current password (defence against stolen-cookie attacks) and rejects identical new password. Client-side validation: 8+ chars, confirm matches, current required.
- **Admin password provenance**: `users.password_set_via` (`env`/`ui`/`cli`/`unknown`) tracks who last set the `admin` password. A startup hook (`sync_admin_password_from_env` in `users.py`) re-applies `ADMIN_PASSWORD` on every restart while the environment still governs it, but never overwrites a password set via the UI or the CLI. `ADMIN_PASSWORD_FORCE=1` is the one-shot override back to environment management. Break-glass reset: `docker compose exec app python -m another_s3_manager.reset_admin_password` (interactive prompt, or `--yes` + positional password for non-TTY use). See README "Admin password lifecycle".
- **MCP server at `/mcp`** for AI agents (Claude Desktop, Cursor, Codex). Bearer auth via per-user MCP tokens; same role/permission model as web UI. `bucket_summary` tool gives agents a one-call bounded digest of any bucket (honest partial coverage on huge buckets); `list_files` page sizes are operator-bounded via `mcp_list_page_size`/`mcp_list_max_page_size`, the summary walk via `mcp_summary_max_keys`/`mcp_summary_prefix_scan_pages`; server-level instructions orient agents on connect (REST API is cookie-auth only — not usable with MCP tokens). Self-serve token management at `/api-tokens` (UI labels them "MCP tokens"; URL kept for backwards compatibility). User can edit token metadata (name, read-only flag, max read bytes) without revoke + recreate. Admin can issue tokens on behalf of users. See `docs/mcp-setup.md`.
- **Prometheus metrics** at `/metrics` (optional basic auth via `METRICS_PASSWORD`). All application metrics are namespaced `as3m_`; runtime metrics (`process_*`, `python_info`) keep their standard names. Covers HTTP, auth, S3 ops/objects/bytes/errors, STS + credential refresh, MCP tool calls and guard denials, DB timings. Metric inventory + scrape config: `docs/observability.md`. Ships a ready-made Grafana dashboard (`docs/grafana-dashboard.json`) + a one-command local Prometheus/Grafana stack (`docker compose -f docker-compose.yml -f docker/docker-compose.observability.yml up`); dashboard invariants are guarded by `tests/test_grafana_dashboard.py`.

### React API surface

Folder moves use an in-memory registry in a single application process: at most 2 running jobs per user and 4 globally, with 8 copy workers per job. Preflights are limited to 10 per user per minute; requests contain at most 1,000 items and 256 KiB of JSON. Completed jobs expire after one hour; at most 200 are retained, with up to 1,000 failures each, served in pages of 100. Restarting loses the registry and no job auto-resumes. Until deletion starts the source remains complete; after deletion starts a complete copy exists at the destination. Internal reservations coordinate web/MCP writes, conservatively including source parents for marker writes and matching bucket names across roles/endpoints; external clients and separate processes/replicas are not coordinated. Job polling and cleanup use the stored role/bucket and re-check current access. Cleanup is available only before source deletion begins and skips destination objects with changed ETags. Multipart copies above 5 GiB preserve content metadata but do not copy tags; versioned-bucket deletions leave historical versions.

The React SPA consumes existing backend endpoints plus a small set added for SPA UX:

- `POST /api/buckets/{b}/folders?role=...` — create an empty folder marker; rejects file/folder name collisions. Requires cookie auth and CSRF, independently of the deletion gate.
- `POST /api/buckets/{b}/move/preflight?role=...` — validate and enumerate an immutable same-bucket plan, returning object/byte counts before writes.
- `POST /api/buckets/{b}/move?role=...` — start a background copy-then-delete job; requires a UUID `operation_id`, items and destination; optional `new_name` for a single item. Returns 202 `{job_id}`. Roles are required on all three bucket routes.
- `GET /api/jobs/{job_id}?failures_offset=0` — owner-only job progress and paginated failures; checks current role/bucket access.
- `POST /api/jobs/{job_id}/cleanup` — owner-only, CSRF-protected removal of unchanged partial copies from that job. Move and cleanup obey `DISABLE_DELETION` OR config `disable_deletion`, and the role's `allow_delete`.
- `GET /api/me` — extended to include `allowed_roles: string[]`, `role_permissions: {role: {delete: bool}}` (the role-level delete policy, already combined with the global flag; the SPA reads it through `useRolePermissions`) and `disable_deletion: bool` (env `DISABLE_DELETION` OR `config.disable_deletion`, env wins; surfaces the flag so the React UI can disable Delete controls before the user clicks)
- `GET /api/buckets?role=...` — list buckets (already existed)
- `GET /api/buckets/{b}/files?path=...&role=...` — list files (already existed)
- `GET /api/buckets/{b}/files?...&client_load=1&search=<prefix>` — server-side name-prefix search: lists the current folder's immediate children (folders + files) whose name starts with `<prefix>`, case-sensitive, via S3 `ListObjectsV2(Prefix=…)`. client_load mode only (else 400). Powers the "Search on server" affordance shown when a folder is truncated.
- `POST /api/buckets/{b}/upload` — single-file multipart upload (already existed)
- `DELETE /api/buckets/{b}/files?path=...&role=...` — file or folder delete (already existed)
- `GET /api/buckets/{b}/download?path=...&role=...` — streamed download (already existed; cookie-auth proxy used by Download button)
- `GET /api/buckets/{b}/presigned?path=...&role=...&op=get[&expires_in=<seconds>]` — boto3 presigned GET URL. Lifetime defaults to `presigned_url_default_ttl` (config/env, default 1h); `expires_in` overrides it within `[60, presigned_url_max_ttl]` (else 400 `INVALID_EXPIRES_IN`). Returns `{url, expires_at, expires_in, warning?}` — `expires_in` echoes the granted TTL; `warning` is present for STS-backed roles (assume_role/profile) when the link outlives ~1h (it may expire when the role's session ends). Auto-applies a `; charset=utf-8` Content-Type override for known text extensions. Used by Copy URL (single + bulk, with a per-link "Valid for" override) and grid thumbnails.
- `GET /api/admin/users` — list users with available roles (returns `{users, available_roles}`); each user's `allowed_roles` holds only roles present in config, grants to removed roles are listed in `missing_roles`
- `POST /api/admin/users` — create user (multipart Form); 400 `Unknown role(s): …` for role names not in config
- `PUT /api/admin/users/{u}` — update user (multipart Form, blocks self-demote); same unknown-role 400 when `allowed_roles` is sent
- `DELETE /api/admin/users/{u}` — delete user (blocks self-delete)
- `PUT /api/admin/users/{u}/password` — admin-reset another user's password (JSON `{password}`)
- `PUT /api/me/password` — self-service password change (JSON `{current_password, new_password}`); requires current password, rejects identical new password
- `GET /api/admin/bans` — list active bans (returns `{bans}`)
- `DELETE /api/admin/bans/{u}` — unban user
- `GET /api/config` — read whole config including derived `data_dir` / `current_role` / `is_read_only` (response-only)
- `POST /api/config` — write config; React strips derived fields via `toWritableConfig()` to avoid persisting runtime values. New role names must be unique, without commas or surrounding whitespace. Grants (`user_roles`, `default_role`) for added names are pruned before saving and for removed names after saving, so a re-created name never inherits old grants. Everywhere else a non-admin's grants are filtered by the current config (`users.effective_allowed_roles`); startup only logs dangling grants
- `GET /api/me/tokens` — list authenticated user's active MCP tokens (table `api_tokens` kept for backwards compatibility)
- `POST /api/me/tokens` — create MCP token (returns plaintext token once; stored as SHA-256 hash)
- `PUT /api/me/tokens/{id}` — update editable metadata (`name`, `is_read_only`, `max_read_bytes`); 400 on empty body / out-of-range, 404 on missing/revoked, 409 on name collision
- `DELETE /api/me/tokens/{id}` — revoke own token
- `GET /api/admin/tokens` — admin list of all tokens with owner info
- `POST /api/admin/tokens` — admin create token on behalf of any user
- `PUT /api/admin/tokens/{id}` — admin edit any user's token metadata (returns `owner_username` alongside the standard token shape)
- `DELETE /api/admin/tokens/{id}` — admin revoke any token
- `/mcp/*` — MCP server (Bearer token auth via `Authorization: Bearer as3m_...`; same role/permission model as web UI; see `docs/mcp-setup.md`)
- `/metrics` — Prometheus exposition format (optional basic auth via `METRICS_PASSWORD`)

## Deployment

### Local dev

```bash
# One-time setup
cp .env.example .env
# Edit .env, paste output of: python -c 'import secrets; print(secrets.token_urlsafe(32))'

# Run (every time)
docker compose up --build
```

`docker-compose.yml` bind-mounts `./data` so SQLite DB, config, and uploads stay
visible in your IDE. An `init-data` sidecar fixes ownership for the non-root app
container before startup — no manual `chown` needed.

For native dev (no Docker, fastest iteration):

```bash
JWT_SECRET_KEY=dev-secret uv run python -m another_s3_manager.main
```

To mount your host `~/.aws` for SSO profiles, uncomment one of the optional
volume lines in `docker-compose.yml` (Linux/macOS or Windows variant).

### Self-host

Use `docker-compose.example.yml` — pulls a published image from GHCR, no source clone needed.
Copy to a server, set `JWT_SECRET_KEY`, run.

### Kubernetes

Container is k8s-ready: read-only `config.json` mount via ConfigMap is supported
(`config.py:is_config_writable()` handles RO gracefully), SQLite DB lives under `DATA_DIR`
(mount a PVC), secrets via env. Helm charts for kruchenburger services live in a separate
repo: [github.com/kruchenburger/helm](https://github.com/kruchenburger/helm) (in progress).
