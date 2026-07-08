# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-07-08

### Changed

- The single "Inline preview extensions" setting is split into two independent
  settings, because it controlled two unrelated things: `preview_text_extensions`
  (which text files preview inline in the UI) and `upload_inline_extensions`
  (which uploads get `Content-Disposition: inline` so they open in the browser
  when served via a CDN or presigned link). Existing configs are migrated
  automatically: the preview list is preserved as-is, and the upload-inline list
  keeps every extension that was inline before while gaining sensible defaults
  (pdf + common images) — so PDFs open in the browser out of the box again
  without losing any customization. Settings now shows both fields with clear
  labels.

## [1.0.2] - 2026-07-08

### Added

- MCP server gains three tools: `copy_object` (server-side copy within a role;
  `delete_source=true` moves/renames), `presigned_url` (hand an agent a
  time-limited download link — works for binary files too), and
  `get_object_metadata` (size / last-modified / content-type / etag without
  downloading). Write-tool descriptions now clearly flag their side effects.

### Fixed

- Expired sessions no longer trap the page in a redirect loop between the login
  page and the app (the address bar flickered and nothing was clickable). The
  login page now only bounces to the app on a genuinely valid session.
- The Roles page no longer labels a role with no bucket restriction as "No
  buckets" (which read as broken/empty). It now shows "Any bucket" with a
  tooltip explaining the role lists every bucket its credentials can access.
- The documented minimum IAM policy now includes the required `s3:ListBucket`
  permission (needed for browsing) and explains which action powers each
  feature, including copy/move.

## [1.0.1] - 2026-07-08

### Fixed

- Browsing a folder with a very large number of sub-folders no longer hangs.
  Folders now count toward the load budget and paginate (Load more / Load all
  / lazy scroll) exactly like files, so a level made entirely of sub-folders
  behaves like one made of files. A long "Load all" is now stoppable and
  aborts automatically when you leave the folder.
- `assume_role` roles no longer fail with "You must specify a region" in
  containers without a shared AWS config: the STS client (and the assumed-role
  S3 client) now honor the role's `region` field and the `AWS_REGION` env var.

## [1.0.0] - 2026-07-04

### Added

- **Complete React interface (Mantine)** replacing the vanilla HTML/JS UI:
  collapsible sidebar with a role/bucket tree, file browser with table + grid
  views (image/video thumbnails), drag-and-drop file **and folder** upload,
  preview modal (images, video, PDF, text), shift-click range select, bulk
  selection with a bottom action bar (bulk delete with progress, bulk Copy
  URL), filtering, scroll-to-top, and a dark/light theme that cross-fades via
  the View Transitions API.
- **Huge-folder handling**: client-load pagination with an honest object
  counter ("Load more" / "Load all"), list virtualization (10k+ object folders
  stay responsive), lazy auto-loading on scroll; tune with `MAX_CLIENT_LOAD` /
  `max_client_load`.
- **Server-side prefix search** for truncated folders — a "Search on server"
  affordance runs a starts-with search at the current level via S3
  `ListObjectsV2`.
- **Admin console** at `/admin`: Users (create/edit/delete, reset password,
  self-protection guards), Roles (create wizard with type-specific credential
  fields, edit drawer), Bans (view/unban), Settings (typed form with
  General/Security/MCP tabs, sticky save bar, read-only k8s ConfigMap mode),
  and MCP token administration.
- **MCP server at `/mcp`** for AI agents (Claude Desktop, Cursor, …): per-user
  bearer tokens with the same role/permission model as the web UI, read tools
  with text detection and size caps, self-serve token management at
  `/api-tokens`, admin token issuing on behalf of users, editable token
  metadata without re-issuing. See `docs/mcp-setup.md`.
- **SQLite storage** (SQLAlchemy + Alembic) for users, bans and tokens —
  legacy `users.json` / `bans.json` are migrated automatically on first start
  (originals preserved as `*.migrated.bak`).
- **Configurable password policy** (min length / uppercase / lowercase /
  digits / special), self-service password change, and forced password change
  on first login for admin-created users.
- **Configurable presigned-URL lifetime**: `PRESIGNED_URL_DEFAULT_TTL` /
  `PRESIGNED_URL_MAX_TTL` (7-day SigV4 ceiling), per-link override (right-click
  Copy URL, or the bulk split button), expiry warnings for STS-backed roles.
- **Inline preview extensions** setting — the list of text extensions that
  preview inline is admin-editable (seeded with sensible defaults); images,
  video and PDF always preview.
- **Prometheus metrics** at `/metrics` (optional basic auth via
  `METRICS_PASSWORD`): HTTP, auth, S3 operations, MCP tool calls, DB timings.
- **Structured JSON logging** option (`LOG_FORMAT=json`) for log aggregators.
- Per-user default role, per-user theme persistence, and config export
  ("Download config (JSON)" in Settings).
- Typed S3 error handling — real error causes (permissions, endpoint, missing
  bucket) surface in the UI instead of an empty listing.

### Changed

- **Authentication** moved from a bearer token in the response body to an
  `httpOnly + Secure + SameSite=Strict` cookie with CSRF protection
  (`X-CSRF-Token` from `/api/me`). `COOKIE_SECURE=false` is required when
  running locally over plain HTTP.
- **Brute-force defense** is now a per-username ban (3 failed logins → 1 h
  ban). Admin accounts are exempt to avoid DoS on the predictable `admin`
  name — protect them at the deployment layer (reverse proxy / Cloudflare
  Access). The per-IP `slowapi` rate limiter was removed in favor of that
  model.
- Upgraded the SPA to Mantine 9 / React 19.2. Component default border-radius
  and light-variant colors follow Mantine 9 defaults.
- New environment variables are documented in the README table: `DATA_DIR`,
  `COOKIE_SECURE`, `LOG_FORMAT`, `METRICS_PASSWORD`, `PRESIGNED_URL_*`,
  `MAX_CLIENT_LOAD`.

### Fixed

- Admin edits to roles apply without a container restart — the S3 client and
  boto3 credential caches are flushed on config save, and config changes apply
  live in open browser tabs.
- Revoked MCP token names can be reused when creating a new token.
- Friendlier errors for Cloudflare R2 and other S3-compatible providers that
  reject `ListBuckets` (403 on bucket listing no longer breaks the role).
- Accessibility: color scheme is set before first paint (no black-on-dark
  flash on login), Modal/Drawer close buttons keep their `aria-label`, and the
  password-requirements checklist passes WCAG AA contrast in both schemes.
  An automated axe-core baseline (WCAG 2.1 AA) runs on every covered route in
  CI.

### Removed

- **Breaking:** the legacy vanilla UI is removed; the app now serves the React
  interface at `/`. Old vanilla URLs (`/`, `/login`, `/admin`) keep working —
  `/admin` redirects to `/admin/users`. `/v2/*` URLs no longer exist (no
  redirects — they render the SPA's 404 page). The `ITEMS_PER_PAGE` env var
  and `items_per_page` config key are removed (ignored if present in existing
  `config.json`). The MCP endpoint (`/mcp`) is unchanged.
- The demo mode from v0.1.x is removed.

### Security

- **Breaking (upgrade note):** the container now runs as a non-root user
  (uid 1001); v0.1.x images ran as root. When upgrading an existing
  deployment, the data volume created by v0.1.x contains root-owned files the
  new image cannot write. Do a one-time ownership fix before starting the new
  image:
  `docker run --rm -v <your-data-volume-or-dir>:/app/data alpine chown -R 1001:1001 /app/data`.
  The in-repo `docker-compose.yml` does this automatically via its `init-data`
  sidecar; fresh installs from `docker-compose.example.yml` are unaffected.
  The upgrade path is covered by `scripts/upgrade-smoke.sh` (v0.1.2 → current
  image, same volume and env).

## [0.1.2] - 2026-04-28

### Changed

- Migrated project layout from flat to `src/another_s3_manager/` package
- All imports updated to use fully qualified module paths
- Replaced `docker-build.yml` with standardized `ci.yml` workflow
- Multi-stage Dockerfile with `BUILD_VERSION` arg for version injection
- README rewritten — concise and structured

### Added

- `/health` endpoint exposing app version from `APP_VERSION` env var
- `CLAUDE.md` with project documentation for AI-assisted development
- React + Mantine frontend scaffold (`frontend/`) — no UI rewrite yet
- Ruff and Pyright configuration in `pyproject.toml`

### Fixed

- Docker build now installs the project with static assets included in the wheel (two-stage `uv sync`)

### Removed

- Standalone `pytest.ini` and `.coveragerc` (merged into `pyproject.toml`)
- Outdated `PUBLISHING.md`

## [0.1.1] - 2025-11-23

### Added

- Docker Compose configuration for local development (`docker-compose.yml`) with automatic build and config file mounting
- `auto_inline_extensions` configuration option: automatically set `Content-Disposition: inline` header for specified file extensions when uploading to S3 (e.g., PDF, JPG files can be opened directly in browser)

### Fixed

- Removed excessive console logging from frontend JavaScript, preventing sensitive configuration data from being exposed in browser console
- Fixed credential expiration errors being shown to users - they are now automatically handled with transparent retry
- Display of current DATA_DIR value in admin interface (read-only) to show the actual data directory path being used

## [0.1.0] - 2025-11-11

### Added

- Initial public release
- Multi-account AWS support via role assumption, profiles, and direct credentials
- User authentication with JWT tokens
- Admin panel for user management
- File browsing, upload, download, and deletion
- Dark/light theme support
- Virtual scrolling for large file lists
- Account lockout after failed login attempts
- Granular bucket access control
- Web-based configuration interface
- Support for custom S3-compatible endpoints (e.g., MinIO) via `endpoint_url`, `use_ssl`, `verify_ssl`, and path-style addressing in role configuration

### Security

- Password hashing with bcrypt
- JWT token-based authentication
- CSRF protection
- Login attempt rate limiting

[Unreleased]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kruchenburger/another-s3-manager/releases/tag/v0.1.0
