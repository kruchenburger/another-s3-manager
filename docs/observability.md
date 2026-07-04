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

All metrics live in a dedicated registry (no default `python_*` collectors) and
follow a strict cardinality budget: HTTP paths are labeled by route template
(never concrete URLs), role labels are capped at 50 distinct values, and nothing
is ever labeled by user, token, or file path.

### HTTP

| Metric                          | Type      | Labels                                | Notes                        |
| ------------------------------- | --------- | ------------------------------------- | ---------------------------- |
| `http_requests_total`           | Counter   | `method`, `path_template`, `status_code` | Route pattern, not raw URL |
| `http_request_duration_seconds` | Histogram | `method`, `path_template`             |                              |

### Auth

| Metric              | Type    | Labels   | Notes                                          |
| ------------------- | ------- | -------- | ---------------------------------------------- |
| `auth_logins_total` | Counter | `result` | `success` \| `invalid_password` \| `banned`. Unknown usernames count as `invalid_password` so metrics can't enumerate accounts |
| `auth_bans_active`  | Gauge   | —        | Active bans, computed at scrape time           |

### S3 operations

| Metric                         | Type      | Labels                        | Notes                              |
| ------------------------------ | --------- | ----------------------------- | ---------------------------------- |
| `s3_operations_total`          | Counter   | `role`, `operation`, `result` | `list\|get\|put\|delete\|head`, `ok\|error` |
| `s3_operation_duration_seconds`| Histogram | `operation`                   |                                    |
| `s3_bytes_uploaded_total`      | Counter   | `role`, `bucket`              |                                    |
| `s3_bytes_downloaded_total`    | Counter   | `role`, `bucket`              |                                    |

### MCP

| Metric                     | Type      | Labels               | Notes                                                   |
| -------------------------- | --------- | -------------------- | ------------------------------------------------------- |
| `mcp_tool_calls_total`     | Counter   | `tool`, `error_code` | `error_code="none"` on success                          |
| `mcp_tool_duration_seconds`| Histogram | `tool`               |                                                         |
| `mcp_bytes_read_total`     | Counter   | `bucket`             | Bytes returned from `read_file`                         |
| `mcp_tool_response_bytes`  | Histogram | `tool`               | JSON response size — a proxy for LLM context consumed (~4 bytes/token) |
| `mcp_auth_failures_total`  | Counter   | `reason`             | `invalid_token` \| `revoked` \| `malformed`             |
| `mcp_active_tokens`        | Gauge     | —                    | Non-revoked MCP tokens                                  |

### App health

| Metric                          | Type      | Labels      | Notes                                  |
| ------------------------------- | --------- | ----------- | -------------------------------------- |
| `app_info`                      | Info      | —           | Version, Python version                |
| `app_db_query_duration_seconds` | Histogram | `operation` | `SELECT` / `INSERT` / `UPDATE` / `DELETE` / `OTHER` |

A ready-made Grafana dashboard JSON is on the roadmap.

## Logs

Set `LOG_FORMAT=json` for structured one-line-per-event JSON logs (for Loki,
CloudWatch, and other aggregators). The default `text` format is human-readable
and meant for `docker logs` / local development.

## Health check

`GET /health` returns `{"status": "ok", "version": "<semver>"}` — used by the
Docker `HEALTHCHECK` and suitable for k8s liveness/readiness probes. It is
always unauthenticated.
