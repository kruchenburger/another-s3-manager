# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ADMIN_PASSWORD` is no longer first-boot-only: the app now records who last
  set the admin password (environment, UI, or the reset CLI) and re-applies
  `ADMIN_PASSWORD` on every restart as long as the environment still governs
  it. A password set through the UI, or via the new break-glass CLI, is never
  touched by the environment again.
- New `ADMIN_PASSWORD_FORCE` env var — a one-shot opt-in that overwrites the
  admin password with `ADMIN_PASSWORD` regardless of provenance and hands
  password management back to the environment. Every boot with it set logs a
  warning to remove it.
- New break-glass CLI:
  `docker compose exec app python -m another_s3_manager.reset_admin_password`
  — resets (or recreates) the `admin` user's password from inside the
  container without touching SQLite by hand. Interactive by default (hidden
  prompt, asked twice); `--yes` plus a positional password for non-interactive
  use (`docker compose exec -T ...`, CI). Enforces the same password policy
  as the UI. See the README's "Admin password lifecycle" section.
- Existing databases are upgraded via a new Alembic migration that adds
  `password_set_via` to `users`, backfilling non-admin users as `ui` and
  leaving the admin's provenance to be classified honestly at the next
  startup (see README) — the backfill never assigns `env` on its own.
  **This classification only applies to deployments that were already on
  SQLite.** A deployment upgrading straight from a legacy `users.json` file
  has every imported user, including `admin`, stamped `ui` up front by the
  JSON→SQLite migration — `ADMIN_PASSWORD` will not govern that admin's
  password on its own; use `ADMIN_PASSWORD_FORCE=1` once to hand it back to
  the environment (see README "Upgrading an existing deployment").

## [1.1.1] - 2026-07-13

### Changed

- The interface now says "Sign in" / "Sign out" everywhere instead of "Login" /
  "Logout", and the surrounding copy follows the same vocabulary — the sign-in
  page, the user menu, the bans list, password reset, and the MCP tokens page.
  URLs and API endpoints are unchanged.

### Added

- Sortable file-browser columns (Name / Size / Modified, asc/desc); on huge
  folders a size/date sort loads the whole level first so the order is exact.
  Since that load can be thousands of S3 requests on a very large folder, the
  UI now asks for confirmation before it starts — a header click alone never
  triggers it.
- MCP: new `bucket_summary` tool — an agent asked "what's in this bucket?"
  now gets an honest, compact summary (counts, sizes, per-prefix breakdown,
  extension histogram, largest objects) in ONE call instead of paging through
  thousands of keys. Partial scans are always labeled (`complete`, per-prefix
  `coverage`, `prefix_list_complete`) — numbers are never guessed.
- MCP: the server now orients connecting agents (start with `bucket_summary`;
  the REST API is cookie-authenticated and not usable with MCP Bearer
  tokens), and a truncated recursive `list_files` page carries a hint
  pointing at `bucket_summary`.
- MCP: admins can bound the default and maximum `list_files` page size
  (`mcp_list_page_size` / `mcp_list_max_page_size`) and the summary walk
  (`mcp_summary_max_keys` / `mcp_summary_prefix_scan_pages`) — all four
  editable in Settings → MCP.
- MCP: all ten tools now advertise `readOnlyHint`/`destructiveHint`
  annotations, so an MCP client can auto-approve reads while still gating
  writes (`idempotentHint` is deliberately left unset on every tool — see
  `docs/mcp-setup.md` for why). All three write tools (`upload_file`,
  `copy_object`, `delete_file`) are flagged destructive — none of them
  checks whether something already exists at the destination before
  overwriting it. `presigned_url` is read-only but mints a shareable,
  credential-bearing URL — flagged in `docs/mcp-setup.md` as worth a manual
  look rather than a blanket auto-approve despite the read-only hint.

### Fixed

- MCP: asking for a role that does not exist returned an opaque
  `INTERNAL_ERROR` when the token belonged to an **admin**. Admins bypass the
  role check ("admins have access to all roles"), so an unknown role only
  surfaced later as a config error and was swallowed by the tools' catch-all —
  the agent learned nothing and could not correct itself, and a routine "no such
  role" was counted as a server fault in the metrics. It now returns
  `ROLE_NOT_ALLOWED` naming the roles the token may use, exactly as it already
  did for non-admins.
- MCP: the endpoint now answers on a bare `/mcp` instead of redirecting it to
  `/mcp/` with a 307. MCP clients that don't follow redirects could not connect
  at all, and `/mcp` is both the conventional address and the one the server's
  own instructions hand to agents. Both forms work; existing `/mcp/` configs are
  unaffected.
- The object counter in the file browser header could show a wildly wrong,
  deeply negative number (e.g. `-871665980+ objects`) while "Load all" was
  draining a large folder. The count-up animation restarts on every batch of
  objects that arrives, and a small timing quirk in how animation frames are
  clamped let each restart overshoot slightly; on a big folder those
  overshoots compounded across thousands of restarts into a nonsensical
  value. The counter now animates within a mathematically guaranteed range,
  so it always converges to the correct total.
- MCP: tool errors now actually tell the agent what to do next. FastMCP only
  ever forwards `str(exception)` to the client — the `details` dict a tool
  raised alongside it (e.g. `ROLE_NOT_ALLOWED`'s list of roles the caller MAY
  use, or the `presigned_url` redirect on `BINARY_CONTENT`/`FILE_TOO_LARGE`)
  was silently discarded, so the agent was told "no" and never told what
  "yes" looks like. The useful, already-safe-to-share parts of `details` are
  now folded into the error text itself. `read_file`'s docstring also now
  states upfront (not just inside the error body) when to reach for
  `get_object_metadata` or `presigned_url` instead, and `list_roles`/
  `list_buckets` each got a one-line "call this first" trigger.

## [1.1.0] - 2026-07-11

### Security

- **Critical: unauthenticated upload DoS closed.** `POST /api/buckets/{bucket}/upload`
  used to receive and spool the entire request body to disk _before_
  authentication ran — a single unauthenticated request could fill the
  server's disk. A new upload body-guard middleware now rejects requests
  before the body is read: `401` (no/invalid session), `411 Length Required`
  (missing `Content-Length` — chunked-transfer bypass closed), `413`
  (`Content-Length` above the configured `max_file_size`).

### Fixed

- Web uploads now truly stream. The upload route buffered the whole file in
  memory and then copied it (peak RSS ≈ 2× file size); it now hands the
  spooled body to boto3's managed-multipart `upload_fileobj`, which also
  lifts the previous 5 GB `put_object` ceiling — uploads are bounded only by
  `max_file_size`. Uploads that under-report `Content-Length` are rejected
  with `413` on the true spooled size (defense-in-depth). The MCP
  `upload_file` tool is unchanged (base64 → bytes; its 5 GB ceiling remains
  and stays documented).

### Changed

- **Breaking (metrics):** every application metric is now namespaced under
  `as3m_` (for example `http_requests_total` → `as3m_http_requests_total`), so
  the app no longer collides with other services in a shared Prometheus. Three
  metrics also changed shape: `s3_operations_total`'s uninformative
  `result="ok|error"` label is replaced by `error_code`, which names the actual
  cause (`access_denied`, `throttled`, `credentials_expired`, …); the separate
  `s3_bytes_uploaded_total` / `s3_bytes_downloaded_total` counters are collapsed
  into `as3m_s3_bytes_total{direction}`; and `app_db_query_duration_seconds`
  drops its redundant `app_` prefix. The `/metrics` endpoint is the only
  affected surface — the HTTP API is unchanged. See "Upgrading from v1.0.x" in
  `docs/observability.md` for the full old → new table.

### Added

- Object-level accounting: `as3m_s3_objects_total{operation}` counts objects
  uploaded, deleted, and copied. Unlike the operations counter, deleting a
  folder of 5,000 objects registers 5,000 — not the handful of batched API
  calls it took.
- Visibility into credential handling: `as3m_sts_assume_role_total` and
  `as3m_credentials_refreshed_total` surface `assume_role` and refresh failures,
  which were previously silent until a user reported a broken bucket listing.
- Counters to complement the state gauges, so brute-force and token churn can be
  graphed as rates: `as3m_auth_bans_total`, `as3m_mcp_tokens_issued_total`,
  `as3m_mcp_tokens_revoked_total`.
- Proof that the MCP guards fire: `as3m_mcp_writes_denied_total{reason}` and
  `as3m_mcp_reads_refused_total{reason}`.
- `as3m_presigned_urls_total` and `as3m_presigned_url_ttl_seconds`,
  `as3m_upload_rejected_total{reason}`, `as3m_http_requests_in_flight`,
  `as3m_s3_retries_total`, `as3m_users`, `as3m_roles`,
  `as3m_db_errors_total{operation}`.
- Runtime metrics under their standard names: `process_cpu_seconds_total`,
  `process_resident_memory_bytes`, `process_open_fds`,
  `process_start_time_seconds` (Linux only) and `python_info`.
- A ready-made **Grafana dashboard** (`docs/grafana-dashboard.json`) over the
  whole metric set — Overview, Storage, S3 health, Auth & security, MCP, and
  Runtime rows, each panel described. It imports into any Grafana via a
  datasource variable (no hardwired UID). Plus a one-command local
  Prometheus + Grafana stack (`docker/docker-compose.observability.yml`) that
  scrapes the app and auto-loads the dashboard — see `docs/observability.md`.
- Admin **Settings** fields now show a concise one-line description plus a
  click-to-open info popover (the "i" chip) for the full explanation, instead
  of long inline paragraphs of grey text.

### Fixed

- `mcp_active_tokens` always reported `0`. It was defined, documented and
  exported, but nothing ever wrote to it. It now reports the number of
  non-revoked MCP tokens.
- S3 throttling (`SlowDown`, `RequestLimitExceeded`, HTTP 503) is now classified
  as its own error rather than being lumped in with unknown failures.
- Grafana dashboard count-panel Totals are now exact on fresh / low-volume
  counters: fixed-enum counter series are pre-seeded to `0` at startup, so
  `increase()` has a baseline and counts the very first event instead of
  missing it.
- The bulk-upload failure toast no longer clips the useful part on long
  filenames — the filename ellipsizes to one line (full name on hover) and the
  size/limit reason renders on its own line.
- Large uploads no longer look stuck at 100%. Once the file is fully sent, the
  progress toast shows **"Finalizing on server…"** with an animated bar while
  the server streams the body to S3, instead of a frozen 100%. During that
  phase a single-file upload can be closed safely ("Safe to close — the upload
  will finish on the server"); it completes in the background.

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

[Unreleased]: https://github.com/kruchenburger/another-s3-manager/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/kruchenburger/another-s3-manager/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/kruchenburger/another-s3-manager/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/kruchenburger/another-s3-manager/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/kruchenburger/another-s3-manager/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/kruchenburger/another-s3-manager/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kruchenburger/another-s3-manager/releases/tag/v0.1.0
