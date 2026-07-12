# Another S3 Manager

Lightweight web UI for managing files in S3 and S3-compatible storage.

> **This is a public repository.** Never commit, push, or include in PR descriptions / commit messages / issue bodies any absolute paths from a developer's local filesystem (e.g. `D:\...`, `/Users/...`, `C:\...`, `/home/...`). Specs and plans for this project live out-of-repo per `.claude/rules/specs-and-plans.md` — when referencing them in a PR description, use only the **relative tail** (e.g. `specs/2026-05-02-foo-design.md (out-of-repo)`), never the full absolute path. Personal directory structure leaking into a public repo is a privacy issue and looks unprofessional.

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
│       ├── main.py          # FastAPI app, API endpoints
│       ├── auth.py           # JWT auth, CSRF, ban logic
│       ├── config.py         # Config management (config.json)
│       ├── constants.py      # App constants, paths
│       ├── database.py       # SQLAlchemy engine + session_scope()
│       ├── models.py         # ORM models (User, Role, Ban)
│       ├── s3_client.py      # S3 client, role management
│       ├── users.py          # User management (SQLite via SQLAlchemy)
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

## Database

- SQLAlchemy 2.0 (sync) + Alembic for migrations
- SQLite at `<DATA_DIR>/another_s3_manager.db`
- Tables: `users`, `user_roles` (junction), `bans` (FK → users with CASCADE), `api_tokens` (FK CASCADE → users; stores SHA-256 hash of plaintext token, `is_read_only`, `max_read_bytes`, `revoked_at`)
- Module: `database.py` (engine + `session_scope()`), `models.py` (ORM)
- Auto-migration from `users.json` / `bans.json` on first startup (legacy files renamed to `*.migrated.bak`)

## Migration commands

```bash
# Generate a new migration from model changes
uv run alembic revision --autogenerate -m "describe change"

# Apply migrations
uv run alembic upgrade head

# Rollback one step
uv run alembic downgrade -1
```

## Development Commands

```bash
# Install dependencies
uv sync

# Linter and formatting
uv run ruff check .
uv run ruff format .

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

| Variable                          | Required | Default                                 | Description                                                                                        |
| --------------------------------- | -------- | --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `JWT_SECRET_KEY`                  | Yes      | —                                       | JWT signing secret                                                                                 |
| `PORT`                            | No       | `8080`                                  | Server port                                                                                        |
| `UVICORN_HOST`                    | No       | `0.0.0.0`                               | Server bind address                                                                                |
| `LOG_LEVEL`                       | No       | `info`                                  | Logging level                                                                                      |
| `ADMIN_PASSWORD`                  | No       | `change_me_pls`                         | Admin user password                                                                                |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | No       | `180`                                   | JWT expiration (minutes)                                                                           |
| `DISABLE_DELETION`                | No       | `false`                                 | Disable file deletion                                                                              |
| `MAX_FILE_SIZE`                   | No       | `104857600`                             | Max upload file size (bytes, 100MB)                                                                |
| `PRESIGNED_URL_DEFAULT_TTL`       | No       | `3600`                                  | Default presigned-URL lifetime (seconds). Overridable per link up to the max.                      |
| `PRESIGNED_URL_MAX_TTL`           | No       | `604800`                                | Max presigned-URL lifetime (seconds; 7-day SigV4 ceiling). Requests above this are rejected (400). |
| `ENABLE_LAZY_LOADING`             | No       | `true`                                  | Enable lazy loading for file lists                                                                 |
| `AWS_REGION`                      | No       | from env                                | Default AWS region                                                                                 |
| `S3_FILE_MANAGER_CONFIG`          | No       | `./data/config.json`                    | Path to config file (under DATA_DIR by convention)                                                 |
| `DATA_DIR`                        | No       | `./data` (native), `/app/data` (Docker) | Data dir (SQLite DB + runtime data)                                                                |
| `COOKIE_SECURE`                   | No       | `true`                                  | `Secure` flag on auth cookie. MUST be `false` on local HTTP, else browser drops the cookie         |
| `LOG_FORMAT`                      | No       | `text`                                  | Log output format: `text` or `json` (structured, for log aggregators)                              |
| `METRICS_PASSWORD`                | No       | —                                       | Optional basic-auth password for `/metrics` (username `metrics`). If unset, endpoint is open       |

## Features

- Multiple AWS account support (assume_role, profiles, direct credentials)
- S3-compatible services (MinIO, R2, Wasabi)
- JWT authentication via `httpOnly + Secure + SameSite=Strict` cookie + CSRF protection (`X-CSRF-Token` from `/api/me`)
- Automatic refresh of expired credentials
- Granular per-role, per-bucket access control
- Brute-force defense: per-username ban (3 failed attempts → 1h ban). **Admins exempt** to avoid DoS on the predictable `admin` username — admin protection must come from deployment layer (see "Production deployment" in README).
- No application-level IP rate limit. Production exposure expects an authenticated reverse proxy (Cloudflare Access, Tunnel, WAF) — that's the right layer for IP-based throttling.
- React SPA at `/`: collapsible sidebar with role/bucket tree, file browser (table+grid toggle, sortable columns — name/size/modified, both views — hover actions, bulk delete, drag-drop upload, preview modal); sorting by size/date on a large (truncated) folder loads the whole level first so the order is exact.
- React admin pages on `/admin/*`: separate AdminLayout with grouped sidebar (ACCOUNTS: Users / Bans, INFRASTRUCTURE: Roles / Settings) reachable from "Admin Console" in UserMenu. Users page (CRUD + reset password + self-protect for delete/demote/reset). Bans page (view + unban). Roles page (table + create wizard with type-conditional credential fields + edit form, secret_access_key preserve-on-blank). Settings page (typed global settings with read-only k8s ConfigMap mode, MB↔bytes conversion preserves byte-precision when MB field unchanged). Backend endpoints unchanged from Phase 1; React pages reuse them via TanStack Query plus a small `update_user` self-demote guard.
- Self-service password change at `/change-password`: any authenticated user changes their own password via UserMenu → "Change password". Requires the current password (defence against stolen-cookie attacks) and rejects identical new password. Client-side validation: 8+ chars, confirm matches, current required.
- **MCP server at `/mcp`** for AI agents (Claude Desktop, Cursor, Codex). Bearer auth via per-user MCP tokens; same role/permission model as web UI. `bucket_summary` tool gives agents a one-call bounded digest of any bucket (honest partial coverage on huge buckets); `list_files` page sizes are operator-bounded via `mcp_list_page_size`/`mcp_list_max_page_size`, the summary walk via `mcp_summary_max_keys`/`mcp_summary_prefix_scan_pages`; server-level instructions orient agents on connect (REST API is cookie-auth only — not usable with MCP tokens). Self-serve token management at `/api-tokens` (UI labels them "MCP tokens"; URL kept for backwards compatibility). User can edit token metadata (name, read-only flag, max read bytes) without revoke + recreate. Admin can issue tokens on behalf of users. See `docs/mcp-setup.md`.
- **Prometheus metrics** at `/metrics` (optional basic auth via `METRICS_PASSWORD`). All application metrics are namespaced `as3m_`; runtime metrics (`process_*`, `python_info`) keep their standard names. Covers HTTP, auth, S3 ops/objects/bytes/errors, STS + credential refresh, MCP tool calls and guard denials, DB timings. Metric inventory + scrape config: `docs/observability.md`. Ships a ready-made Grafana dashboard (`docs/grafana-dashboard.json`) + a one-command local Prometheus/Grafana stack (`docker compose -f docker-compose.yml -f docker/docker-compose.observability.yml up`); dashboard invariants are guarded by `tests/test_grafana_dashboard.py`.

### React API surface

The React SPA consumes existing backend endpoints plus a small set added for SPA UX:

- `GET /api/me` — extended to include `allowed_roles: string[]` and `disable_deletion: bool` (env `DISABLE_DELETION` OR `config.disable_deletion`, env wins; surfaces the flag so the React UI can disable Delete controls before the user clicks)
- `GET /api/buckets?role=...` — list buckets (already existed)
- `GET /api/buckets/{b}/files?path=...&role=...` — list files (already existed)
- `GET /api/buckets/{b}/files?...&client_load=1&search=<prefix>` — server-side name-prefix search: lists the current folder's immediate children (folders + files) whose name starts with `<prefix>`, case-sensitive, via S3 `ListObjectsV2(Prefix=…)`. client_load mode only (else 400). Powers the "Search on server" affordance shown when a folder is truncated.
- `POST /api/buckets/{b}/upload` — single-file multipart upload (already existed)
- `DELETE /api/buckets/{b}/files?path=...&role=...` — file or folder delete (already existed)
- `GET /api/buckets/{b}/download?path=...&role=...` — streamed download (already existed; cookie-auth proxy used by Download button)
- `GET /api/buckets/{b}/presigned?path=...&role=...&op=get[&expires_in=<seconds>]` — boto3 presigned GET URL. Lifetime defaults to `presigned_url_default_ttl` (config/env, default 1h); `expires_in` overrides it within `[60, presigned_url_max_ttl]` (else 400 `INVALID_EXPIRES_IN`). Returns `{url, expires_at, expires_in, warning?}` — `expires_in` echoes the granted TTL; `warning` is present for STS-backed roles (assume_role/profile) when the link outlives ~1h (it may expire when the role's session ends). Auto-applies a `; charset=utf-8` Content-Type override for known text extensions. Used by Copy URL (single + bulk, with a per-link "Valid for" override) and grid thumbnails.
- `GET /api/admin/users` — list users with available roles (returns `{users, available_roles}`)
- `POST /api/admin/users` — create user (multipart Form)
- `PUT /api/admin/users/{u}` — update user (multipart Form, blocks self-demote)
- `DELETE /api/admin/users/{u}` — delete user (blocks self-delete)
- `PUT /api/admin/users/{u}/password` — admin-reset another user's password (JSON `{password}`)
- `PUT /api/me/password` — self-service password change (JSON `{current_password, new_password}`); requires current password, rejects identical new password
- `GET /api/admin/bans` — list active bans (returns `{bans}`)
- `DELETE /api/admin/bans/{u}` — unban user
- `GET /api/config` — read whole config including derived `data_dir` / `current_role` / `is_read_only` (response-only)
- `POST /api/config` — write config; React strips derived fields via `toWritableConfig()` to avoid persisting runtime values
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
