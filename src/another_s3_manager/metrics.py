"""Prometheus metric definitions for another-s3-manager.

Single registry, module-level objects. Import where needed:
    from another_s3_manager.metrics import http_requests_total
    http_requests_total.labels(method="GET", path_template="/api/me", status_code=200).inc()

Cardinality discipline:
- Use path_template (route pattern) NOT concrete URLs.
- Cap `role` label at 50 distinct values (extra → "other").
- Never label by user_id, username, file path.
"""

import os

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    PlatformCollector,
    ProcessCollector,
)

REGISTRY = CollectorRegistry(auto_describe=True)

# Runtime metrics. Standard, UNPREFIXED names on purpose: `process_*` and
# `python_info` are a Prometheus-wide contract that every off-the-shelf alert
# and dashboard already knows. The `as3m_` rule governs metrics we author.
# ProcessCollector is a no-op off Linux (it reads /proc).
ProcessCollector(registry=REGISTRY)
PlatformCollector(registry=REGISTRY)

# --- HTTP / API ---
http_requests_total = Counter(
    "as3m_http_requests_total",
    "Total HTTP requests",
    ["method", "path_template", "status_code"],
    registry=REGISTRY,
)
http_request_duration_seconds = Histogram(
    "as3m_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path_template"],
    registry=REGISTRY,
)
http_requests_in_flight = Gauge(
    "as3m_http_requests_in_flight",
    "HTTP requests currently being served",
    registry=REGISTRY,
)
# `deletion_disabled` and `invalid_path` are reserved reasons for future PRs —
# do NOT wire them here without also emitting them from the route.
upload_rejected_total = Counter(
    "as3m_upload_rejected_total",
    "Uploads refused before reaching S3",
    ["reason"],  # size_limit
    registry=REGISTRY,
)

# --- Auth ---
auth_logins_total = Counter(
    "as3m_auth_logins_total",
    "Login attempts by result",
    ["result"],  # success | invalid_password | banned
    registry=REGISTRY,
)
auth_bans_active = Gauge(
    "as3m_auth_bans_active",
    "Active bans (banned_until > now)",
    registry=REGISTRY,
)
# The companion to auth_bans_active. A Gauge cannot be rate()d, so the gauge
# alone cannot answer "how many bans this hour" — which is the brute-force signal.
auth_bans_total = Counter(
    "as3m_auth_bans_total",
    "Bans issued after repeated failed logins",
    registry=REGISTRY,
)

# --- S3 ops ---
s3_operations_total = Counter(
    "as3m_s3_operations_total",
    "S3 operations executed",
    # operation: list|get|put|delete|head
    # error_code: none (success) | access_denied | not_found | credentials_expired
    #             | network_error | config_error | throttled | other
    ["role", "operation", "error_code"],
    registry=REGISTRY,
)
s3_operation_duration_seconds = Histogram(
    "as3m_s3_operation_duration_seconds",
    "S3 operation duration",
    ["operation"],
    registry=REGISTRY,
)
s3_bytes_total = Counter(
    "as3m_s3_bytes_total",
    "Bytes transferred to/from S3",
    ["role", "bucket", "direction"],  # direction: upload | download
    registry=REGISTRY,
)
# Objects, NOT API calls. `s3_operations_total{operation="delete"}` counts
# delete_objects batches (S3 caps multi-delete at 1000 keys per call), so a
# folder of 5000 objects registers 5 there and 5000 here.
#
# ACCURACY CAVEAT (operation="delete"): exact on the happy path, but can
# UNDER-count in one rare case. A folder delete lists every key, deletes them in
# 1000-key batches, and increments by the total only after the last batch. If
# credentials expire mid-delete, `execute_with_s3_retry` re-runs the whole
# callback: the already-deleted keys are gone from the fresh listing, so only the
# survivors are counted. Objects deleted before the retry are lost from the tally.
# Treat cumulative delete totals as a lower bound, not an exact ledger.
s3_objects_total = Counter(
    "as3m_s3_objects_total",
    "S3 objects added, removed, or copied",
    ["role", "bucket", "operation"],  # operation: upload | delete | copy
    registry=REGISTRY,
)
# Only `credentials_expired` is emitted today: our loop retries solely on an
# expired-credential error, on BOTH of its retry branches (client acquisition and
# the operation itself). Botocore's own throttle retries happen below us and are
# invisible — never invent a `throttled` reason here.
s3_retries_total = Counter(
    "as3m_s3_retries_total",
    "Transparent S3 retries performed by the app",
    ["reason"],  # credentials_expired
    registry=REGISTRY,
)

# --- MCP-specific (Task 11 wires these) ---
mcp_tool_calls_total = Counter(
    "as3m_mcp_tool_calls_total",
    "MCP tool calls",
    ["tool", "error_code"],  # error_code="none" on success
    registry=REGISTRY,
)
mcp_tool_duration_seconds = Histogram(
    "as3m_mcp_tool_duration_seconds",
    "MCP tool call duration",
    ["tool"],
    registry=REGISTRY,
)
mcp_bytes_read_total = Counter(
    "as3m_mcp_bytes_read_total",
    "Bytes returned from read_file",
    ["bucket"],
    registry=REGISTRY,
)
# Proxy for LLM input-token cost: how many bytes of JSON each MCP tool call
# returned to the agent. Agents reinject this into their next prompt, so the
# byte count is a reasonable proxy for "how much context this tool consumed"
# (≈4 bytes/token for English text / JSON). Labeled by tool only — token_id
# label was tempting (per-token attribution) but violates this module's own
# "Never label by user_id, username, file path" rule because revoked tokens
# never leave the Prometheus label set, growing unbounded over time.
# Per-token call accounting is still available via mcp_tool_calls_total which
# is keyed by tool+error_code (low cardinality regardless of churn).
mcp_tool_response_bytes = Histogram(
    "as3m_mcp_tool_response_bytes",
    "Size in bytes of the JSON response returned by an MCP tool call",
    ["tool"],
    # Buckets sized for typical LLM-context consumption: <100 bytes (empty
    # listings, OK responses), few KB (small reads, list_files), 10-100 KB
    # (medium files, deep listings), 1-10 MB (large reads at the cap).
    buckets=(100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000, 10_000_000),
    registry=REGISTRY,
)
mcp_auth_failures_total = Counter(
    "as3m_mcp_auth_failures_total",
    "MCP authentication failures",
    ["reason"],  # invalid_token | revoked | malformed
    registry=REGISTRY,
)
mcp_active_tokens = Gauge(
    "as3m_mcp_active_tokens",
    "Active (non-revoked) API tokens",
    registry=REGISTRY,
)
# The companions to mcp_active_tokens. A Gauge cannot be rate()d, so the gauge
# alone cannot answer "how many tokens issued/revoked this hour" — churn.
#
# ACCURACY CAVEAT: both are incremented inside the DB transaction, just before it
# commits. If the commit then fails, the row is rolled back but the counter is
# not — so a failed create/revoke can OVER-count by 1. Commit failures are rare
# (local SQLite), and the always-correct current count lives in the
# mcp_active_tokens gauge, which is recomputed from the DB at every scrape. Use
# these two for churn rate, the gauge for the true count.
mcp_tokens_issued_total = Counter(
    "as3m_mcp_tokens_issued_total",
    "MCP tokens created",
    registry=REGISTRY,
)
mcp_tokens_revoked_total = Counter(
    "as3m_mcp_tokens_revoked_total",
    "MCP tokens revoked",
    registry=REGISTRY,
)
# The observable proof that the MCP safety model actually fires: read-only
# tokens, the deletion kill-switch, and the per-token read cap.
mcp_writes_denied_total = Counter(
    "as3m_mcp_writes_denied_total",
    "MCP write attempts blocked by a guard",
    ["tool", "reason"],  # writes_disabled | read_only_token | deletion_disabled
    registry=REGISTRY,
)
# NOT "truncated": read_file refuses outright, it never clips a file.
mcp_reads_refused_total = Counter(
    "as3m_mcp_reads_refused_total",
    "MCP read_file calls refused by a guard",
    ["tool", "reason"],  # file_too_large | binary_content
    registry=REGISTRY,
)

# --- STS / credential lifecycle ---
sts_assume_role_total = Counter(
    "as3m_sts_assume_role_total",
    "STS AssumeRole calls made when first building a client for a role",
    ["role", "result"],  # result: ok | error
    registry=REGISTRY,
)
credentials_refreshed_total = Counter(
    "as3m_credentials_refreshed_total",
    "Assumed-role credential refreshes triggered by botocore",
    ["role", "result"],  # result: ok | error
    registry=REGISTRY,
)

# --- Presigned URLs ---
presigned_urls_total = Counter(
    "as3m_presigned_urls_total",
    "Presigned GET URLs issued",
    ["role", "bucket"],
    registry=REGISTRY,
)
# Unlabeled on purpose: role × bucket × buckets would multiply for no benefit.
# Boundaries mirror the TTL choices the UI offers (1m, 5m, 15m, 1h, 6h, 1d, 7d).
presigned_url_ttl_seconds = Histogram(
    "as3m_presigned_url_ttl_seconds",
    "Lifetime granted to issued presigned URLs",
    buckets=(60, 300, 900, 3600, 21600, 86400, 604800),
    registry=REGISTRY,
)

# --- App health ---
# Info("as3m_app", ...) exports the series `as3m_app_info`.
app_info = Info("as3m_app", "Application info", registry=REGISTRY)
# `app_` was redundant once everything carries `as3m_`. The Python name changes too.
db_query_duration_seconds = Histogram(
    "as3m_db_query_duration_seconds",
    "SQLAlchemy query duration by op",
    ["operation"],  # SELECT | INSERT | UPDATE | DELETE | OTHER
    registry=REGISTRY,
)
db_errors_total = Counter(
    "as3m_db_errors_total",
    "Failed SQLAlchemy statements",
    ["operation"],  # SELECT | INSERT | UPDATE | DELETE | OTHER
    registry=REGISTRY,
)

# --- Overview gauges ---
# The Python variable names have _gauge suffix to avoid colliding with the users module
# (imported in main.py). The exported metric names deliberately omit _total because these
# are gauges (point-in-time snapshots), not counters (cumulative values). Prometheus reserves
# _total for counters; promtool flags any non-counter carrying it.
users_gauge = Gauge("as3m_users", "Registered users", registry=REGISTRY)
roles_gauge = Gauge("as3m_roles", "Configured S3 roles", registry=REGISTRY)

# Populate static app info at module load time (env vars are stable after startup)
app_info.info(
    {
        "version": os.getenv("APP_VERSION", "dev"),
        "build_date": os.getenv("BUILD_DATE", ""),
    }
)


# --- Cardinality cap helpers ---
_KNOWN_ROLES: set[str] = set()
_ROLE_CAP = 50


def safe_role_label(role: str) -> str:
    """Bound the cardinality of `role` label to 50 distinct values."""
    if role in _KNOWN_ROLES:
        return role
    if len(_KNOWN_ROLES) < _ROLE_CAP:
        _KNOWN_ROLES.add(role)
        return role
    return "other"
