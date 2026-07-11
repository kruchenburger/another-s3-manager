# Observability

Everything the app exposes for monitoring: Prometheus metrics and structured logs.

## Metrics endpoint

Prometheus exposition format at `GET /metrics`.

**Auth:** optional HTTP Basic. Set the `METRICS_PASSWORD` env var and the endpoint
requires `Authorization: Basic` with username `metrics` and that password
(anything else gets 401). If the variable is unset, the endpoint is open —
a sane default when Prometheus and the app share a private network.

Example scrape config:

```yaml
scrape_configs:
  - job_name: another-s3-manager
    metrics_path: /metrics
    basic_auth:
      username: metrics
      password: ${METRICS_PASSWORD}
    static_configs:
      - targets: ["your-app.example.com:443"]
```

## Exported metrics

All application metrics live in a dedicated registry and are namespaced under
`as3m_`, so this app never collides with another service's metrics in a
shared Prometheus. The registry also carries Prometheus's standard runtime
collectors — `PlatformCollector` (`python_info`) and `ProcessCollector`
(`process_*`) — which keep their unprefixed, off-the-shelf names on purpose;
see [Runtime](#runtime) below. Everything follows a strict cardinality
budget: HTTP paths are labeled by route template (never concrete URLs), the
`role` label is capped at 50 distinct values (`safe_role_label()`, extra
roles collapse into `other`), and nothing is ever labeled by user, token, or
file path.

### HTTP

| Metric                               | Type      | Labels                                   | Notes                                                                                                                                                                                                                                                               |
| ------------------------------------ | --------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `as3m_http_requests_total`           | Counter   | `method`, `path_template`, `status_code` | Route pattern, not raw URL                                                                                                                                                                                                                                          |
| `as3m_http_request_duration_seconds` | Histogram | `method`, `path_template`                |                                                                                                                                                                                                                                                                     |
| `as3m_http_requests_in_flight`       | Gauge     | —                                        | HTTP requests currently being served                                                                                                                                                                                                                                |
| `as3m_upload_rejected_total`         | Counter   | `reason`                                 | Uploads refused before reaching S3 (`size_limit`). Emitted by both the upload body-guard middleware (declared `Content-Length` over the limit) and the handler's spooled-size check. `411` protocol rejects (missing `Content-Length`) are deliberately not counted |

### Auth

| Metric                   | Type    | Labels   | Notes                                                                                                                          |
| ------------------------ | ------- | -------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `as3m_auth_logins_total` | Counter | `result` | `success` \| `invalid_password` \| `banned`. Unknown usernames count as `invalid_password` so metrics can't enumerate accounts |
| `as3m_auth_bans_active`  | Gauge   | —        | Active bans, computed at scrape time                                                                                           |
| `as3m_auth_bans_total`   | Counter | —        | Bans issued after repeated failed logins — the rate-able companion to `as3m_auth_bans_active`, which can't be `rate()`d        |

### S3 operations

| Metric                               | Type      | Labels                            | Notes                                                                                                                                                                                                 |
| ------------------------------------ | --------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `as3m_s3_operations_total`           | Counter   | `role`, `operation`, `error_code` | `operation`: `list\|get\|put\|delete\|head`. `error_code`: `none` (success) \| `access_denied` \| `not_found` \| `credentials_expired` \| `network_error` \| `config_error` \| `throttled` \| `other` |
| `as3m_s3_operation_duration_seconds` | Histogram | `operation`                       |                                                                                                                                                                                                       |
| `as3m_s3_bytes_total`                | Counter   | `role`, `bucket`, `direction`     | `direction`: `upload` \| `download`                                                                                                                                                                   |
| `as3m_s3_objects_total`              | Counter   | `role`, `bucket`, `operation`     | `operation`: `upload\|delete\|copy`. Counts objects, not API calls — deleting a folder of 5,000 objects registers 5,000 here, even though S3 `delete_objects` batches at 1,000 keys per call          |
| `as3m_s3_retries_total`              | Counter   | `reason`                          | Transparent retries the app performs; only `credentials_expired` is emitted today                                                                                                                     |
| `as3m_sts_assume_role_total`         | Counter   | `role`, `result`                  | STS `AssumeRole` calls made when first building a client for a role. `result`: `ok` \| `error`                                                                                                        |
| `as3m_credentials_refreshed_total`   | Counter   | `role`, `result`                  | Assumed-role credential refreshes triggered by botocore. `result`: `ok` \| `error`                                                                                                                    |
| `as3m_presigned_urls_total`          | Counter   | `role`, `bucket`                  | Presigned GET URLs issued                                                                                                                                                                             |
| `as3m_presigned_url_ttl_seconds`     | Histogram | —                                 | Lifetime granted to issued presigned URLs                                                                                                                                                             |

### MCP

| Metric                           | Type      | Labels               | Notes                                                                                   |
| -------------------------------- | --------- | -------------------- | --------------------------------------------------------------------------------------- |
| `as3m_mcp_tool_calls_total`      | Counter   | `tool`, `error_code` | `error_code="none"` on success                                                          |
| `as3m_mcp_tool_duration_seconds` | Histogram | `tool`               |                                                                                         |
| `as3m_mcp_bytes_read_total`      | Counter   | `bucket`             | Bytes returned from `read_file`                                                         |
| `as3m_mcp_tool_response_bytes`   | Histogram | `tool`               | JSON response size — a proxy for LLM context consumed (~4 bytes/token)                  |
| `as3m_mcp_auth_failures_total`   | Counter   | `reason`             | `invalid_token` \| `revoked` \| `malformed`                                             |
| `as3m_mcp_active_tokens`         | Gauge     | —                    | Non-revoked MCP tokens                                                                  |
| `as3m_mcp_tokens_issued_total`   | Counter   | —                    | MCP tokens created — rate-able companion to `as3m_mcp_active_tokens`                    |
| `as3m_mcp_tokens_revoked_total`  | Counter   | —                    | MCP tokens revoked — rate-able companion to `as3m_mcp_active_tokens`                    |
| `as3m_mcp_writes_denied_total`   | Counter   | `tool`, `reason`     | `writes_disabled` \| `read_only_token` \| `deletion_disabled`                           |
| `as3m_mcp_reads_refused_total`   | Counter   | `tool`, `reason`     | `file_too_large` \| `binary_content` — `read_file` refuses outright, it never truncates |

### App health

| Metric                           | Type      | Labels      | Notes                                                 |
| -------------------------------- | --------- | ----------- | ----------------------------------------------------- |
| `as3m_app_info`                  | Info      | —           | `version`, `build_date`                               |
| `as3m_db_query_duration_seconds` | Histogram | `operation` | `SELECT` / `INSERT` / `UPDATE` / `DELETE` / `OTHER`   |
| `as3m_db_errors_total`           | Counter   | `operation` | Failed SQLAlchemy statements; same `operation` values |
| `as3m_users`                     | Gauge     | —           | Registered users                                      |
| `as3m_roles`                     | Gauge     | —           | Configured S3 roles                                   |

### Runtime

Prometheus's standard, unprefixed runtime metrics — the `as3m_` namespace
only applies to metrics this app authors.

| Metric                          | Type    | Labels | Notes                                                      |
| ------------------------------- | ------- | ------ | ---------------------------------------------------------- |
| `process_cpu_seconds_total`     | Counter | —      | Total user+system CPU time. **Linux only** — reads `/proc` |
| `process_resident_memory_bytes` | Gauge   | —      | Resident memory. **Linux only**                            |
| `process_open_fds`              | Gauge   | —      | Open file descriptors. **Linux only**                      |
| `process_start_time_seconds`    | Gauge   | —      | Process start time since epoch. **Linux only**             |
| `python_info`                   | Info    | —      | Python interpreter version/implementation. Cross-platform  |

`process_*` comes from `ProcessCollector`, which reads `/proc` — it is a
no-op outside Linux (e.g. running the app on Windows or macOS during local
dev exports no `process_*` series). `python_info` comes from
`PlatformCollector` and works everywhere.

### Accuracy caveats

Most metrics are exact — they increment only after the operation they measure
succeeds, and the state gauges (`as3m_auth_bans_active`, `as3m_mcp_active_tokens`,
`as3m_users`, `as3m_roles`) are recomputed from the database at every scrape, so
they cannot drift. Two counters have a documented edge case worth knowing before
you alert on them:

- **`as3m_s3_objects_total{operation="delete"}` can under-count.** A folder
  delete removes keys in 1000-key batches and adds the total only after the last
  batch. If credentials expire mid-delete, the operation transparently retries
  and re-lists — the already-deleted keys are gone, so only the survivors are
  counted. Treat cumulative delete totals as a lower bound. Uploads, copies, and
  single-object deletes are exact.
- **`as3m_mcp_tokens_issued_total` / `as3m_mcp_tokens_revoked_total` can
  over-count by 1.** They increment inside the DB transaction, just before it
  commits; a rare commit failure rolls back the row but not the counter. For the
  true current token count, read the `as3m_mcp_active_tokens` gauge — these two
  are for churn _rate_, not an exact ledger.

## Grafana dashboard

A ready-made dashboard covering the whole metric set lives at
[`docs/grafana-dashboard.json`](grafana-dashboard.json) — six rows (Overview,
Storage activity, S3 health, Auth & security, MCP, Runtime) with a short
description on every panel.

**Import it** into your Grafana: Dashboards → New → Import → upload the JSON (or
paste it). It uses a `Data source` template variable, so on import — and via the
dropdown at the top — you pick which Prometheus it queries; nothing is hardwired,
so it drops cleanly into an existing Grafana alongside your other dashboards.

**Or run the bundled stack** (Prometheus + Grafana, pre-wired to scrape the app
and auto-load the dashboard) for a zero-setup look:

```bash
docker compose -f docker-compose.yml -f docker/docker-compose.observability.yml up --build
```

Then open <http://localhost:3000> (anonymous admin, no login); Prometheus is on
`:9090`. Override ports with `GRAFANA_PORT` / `PROM_PORT` if they're taken. This
stack is a dev/self-host convenience — it never enters the app image or CI.

The dashboard file is the source of truth: edit `docs/grafana-dashboard.json` by
hand, never by exporting from the Grafana UI (an export bakes in a concrete
datasource UID and breaks portability). A pytest suite
(`tests/test_grafana_dashboard.py`) enforces the invariants — transparent panels,
per-panel descriptions, `${DS}` everywhere, `$__rate_interval`, and that every
metric a panel queries actually exists. An opt-in live smoke (bring the stack up,
then `E2E_GRAFANA=1 uv run pytest tests/test_grafana_dashboard.py -k live`)
confirms Grafana loads it end-to-end.

## Upgrading from v1.0.x

Every application metric was renamed under an `as3m_` namespace, and three
metrics changed shape. Update your dashboards and alert rules:

| v1.0.x                                | v1.1.0                                                     |
| ------------------------------------- | ---------------------------------------------------------- |
| `http_requests_total`                 | `as3m_http_requests_total`                                 |
| `http_request_duration_seconds`       | `as3m_http_request_duration_seconds`                       |
| `auth_logins_total`                   | `as3m_auth_logins_total`                                   |
| `auth_bans_active`                    | `as3m_auth_bans_active`                                    |
| `s3_operations_total{result="ok"}`    | `as3m_s3_operations_total{error_code="none"}`              |
| `s3_operations_total{result="error"}` | `as3m_s3_operations_total{error_code!="none"}`             |
| `s3_operation_duration_seconds`       | `as3m_s3_operation_duration_seconds`                       |
| `s3_bytes_uploaded_total`             | `as3m_s3_bytes_total{direction="upload"}`                  |
| `s3_bytes_downloaded_total`           | `as3m_s3_bytes_total{direction="download"}`                |
| `mcp_tool_calls_total`                | `as3m_mcp_tool_calls_total`                                |
| `mcp_tool_duration_seconds`           | `as3m_mcp_tool_duration_seconds`                           |
| `mcp_bytes_read_total`                | `as3m_mcp_bytes_read_total`                                |
| `mcp_tool_response_bytes`             | `as3m_mcp_tool_response_bytes`                             |
| `mcp_auth_failures_total`             | `as3m_mcp_auth_failures_total`                             |
| `mcp_active_tokens`                   | `as3m_mcp_active_tokens` (and it now reports a real value) |
| `app_info`                            | `as3m_app_info`                                            |
| `app_db_query_duration_seconds`       | `as3m_db_query_duration_seconds`                           |

`as3m_users`, `as3m_roles`, and everything else in the tables above that
isn't in the left column of this migration table is new in this release —
there's no v1.0.x equivalent to rename from.

## Logs

Set `LOG_FORMAT=json` for structured one-line-per-event JSON logs (for Loki,
CloudWatch, and other aggregators). The default `text` format is human-readable
and meant for `docker logs` / local development.

## Health check

`GET /health` returns `{"status": "ok", "version": "<semver>"}` — used by the
Docker `HEALTHCHECK` and suitable for k8s liveness/readiness probes. It is
always unauthenticated.
