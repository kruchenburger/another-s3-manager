# Another S3 Manager

Lightweight web UI for managing files in S3 and S3-compatible storage.

## Stack

- **Backend**: Python 3.13+, FastAPI, Boto3, JWT auth (cookie-based), per-username ban for brute-force defense
- **Frontend**: Vanilla HTML/JS/CSS (migration to React + Mantine in progress)
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
│       └── static/           # Frontend assets (HTML/JS/CSS)
├── migrations/               # Alembic migrations (env.py + versions/)
├── alembic.ini
├── tests/                    # pytest tests
├── frontend/                 # React + Mantine scaffold (WIP)
├── data/                     # Runtime data (not tracked)
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── uv.lock
```

## Database

- SQLAlchemy 2.0 (sync) + Alembic for migrations
- SQLite at `<DATA_DIR>/another_s3_manager.db`
- Tables: `users` (incl. `tour_seen_v1` flag for one-time onboarding), `user_roles` (junction), `bans` (FK → users with CASCADE)
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

# Production build → bundles into ../src/another_s3_manager/static/v2/
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

Local dev requires both servers: backend on `8080` (FastAPI) + Vite on `5173`.
Vite proxies `/api` → backend, so the React app talks to the real backend during
dev. For production-like testing, run `npm run build` then visit
`http://localhost:8080/v2/` (the FastAPI app serves the bundle directly).

**`COOKIE_SECURE=false` is required when running locally over HTTP** — without it
the browser drops the auth cookie.

### Strangler-fig migration

The vanilla UI (`/`, `/login`, `/admin`) and the React SPA (`/v2/*`) coexist
during the migration. Each release adds more pages to `/v2/`; the vanilla UI is
removed only after `/v2/` has full feature parity (Phase 7).

`/v2/*` is served by a single catch-all FastAPI route in `main.py` (not a
`StaticFiles` mount). The route serves real files when they exist and falls back
to `index.html` so React Router handles client-side navigation. Files are loaded
into memory and returned via `Response` (not `FileResponse`) — kept as a small
defensive choice; SPA bundles are <1MB so the cost is negligible.

## Versioning

Version is derived from git tag via `APP_VERSION` env var. In local development — `dev`.

## Environment Variables

| Variable                          | Required | Default         | Description                         |
| --------------------------------- | -------- | --------------- | ----------------------------------- |
| `JWT_SECRET_KEY`                  | Yes      | —               | JWT signing secret                  |
| `PORT`                            | No       | `8080`          | Server port                         |
| `UVICORN_HOST`                    | No       | `0.0.0.0`       | Server bind address                 |
| `LOG_LEVEL`                       | No       | `info`          | Logging level                       |
| `ADMIN_PASSWORD`                  | No       | `change_me_pls` | Admin user password                 |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | No       | `180`           | JWT expiration (minutes)            |
| `ITEMS_PER_PAGE`                  | No       | `200`           | Items per page in file listing      |
| `DISABLE_DELETION`                | No       | `false`         | Disable file deletion               |
| `MAX_FILE_SIZE`                   | No       | `104857600`     | Max upload file size (bytes, 100MB) |
| `ENABLE_LAZY_LOADING`             | No       | `true`          | Enable lazy loading for file lists  |
| `AWS_REGION`                      | No       | from env        | Default AWS region                  |
| `S3_FILE_MANAGER_CONFIG`          | No       | `./data/config.json` | Path to config file (under DATA_DIR by convention) |
| `DATA_DIR`                        | No       | `./data` (native), `/app/data` (Docker) | Data dir (SQLite DB + runtime data) |
| `COOKIE_SECURE`                   | No       | `true`          | `Secure` flag on auth cookie. MUST be `false` on local HTTP, else browser drops the cookie |

## Features

- Multiple AWS account support (assume_role, profiles, direct credentials)
- S3-compatible services (MinIO, R2, Wasabi)
- JWT authentication via `httpOnly + Secure + SameSite=Strict` cookie + CSRF protection (`X-CSRF-Token` from `/api/me`)
- Automatic refresh of expired credentials
- Granular per-role, per-bucket access control
- Brute-force defense: per-username ban (3 failed attempts → 1h ban). **Admins exempt** to avoid DoS on the predictable `admin` username — admin protection must come from deployment layer (see "Production deployment" in README).
- No application-level IP rate limit. Production exposure expects an authenticated reverse proxy (Cloudflare Access, Tunnel, WAF) — that's the right layer for IP-based throttling.
- React SPA on `/v2/*`: collapsible sidebar with role/bucket tree, file browser (table+grid toggle, hover actions, bulk delete, drag-drop upload, preview modal), one-time onboarding tour persisted via `tour_seen_v1` user flag.

### React API surface

The React SPA consumes existing backend endpoints plus a small set added for SPA UX:

- `GET /api/me` — extended to include `tour_seen_v1: bool` and `allowed_roles: string[]`
- `PUT /api/user/tour-seen` — marks the onboarding tour as seen (idempotent, CSRF-protected)
- `GET /api/buckets?role=...` — list buckets (already existed)
- `GET /api/buckets/{b}/files?path=...&role=...` — list files (already existed)
- `POST /api/buckets/{b}/upload` — single-file multipart upload (already existed)
- `DELETE /api/buckets/{b}/files?path=...&role=...` — file or folder delete (already existed)
- `GET /api/buckets/{b}/download?path=...&role=...` — streamed download (already existed)

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
