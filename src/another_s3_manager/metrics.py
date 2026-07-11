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


# --- Zero-series seeding for exact dashboard Totals --------------------------
#
# A labeled Counter only creates its per-label-combination series on the
# FIRST `.inc()` call -- it is born non-zero, with no earlier `0` sample.
# `rate()`/`increase()` in PromQL need two samples to compute a delta, so the
# very first real increment (0 -> 1) of a brand-new series is invisible: a
# Grafana panel computing `increase(...)` over a freshly-born series
# under-counts by exactly one until a second scrape captures a second data
# point (observed in production: 3 real upload rejections showed a Total of
# 1). Pre-creating the series at 0 by calling `.labels(...)` -- WITHOUT
# `.inc()` -- gives `increase()` a baseline sample so the very first real
# event is counted correctly.
#
# Only counters with a FIXED, statically-known label enum are seedable here.
# Counters labeled by `role` or `bucket` are excluded: those values come from
# admin-editable config (roles can be added/removed at runtime) or arbitrary
# bucket names, so they cannot be enumerated at import time -- pre-creating a
# guessed value would only produce a phantom series that never matches real
# traffic. This excludes s3_bytes_total, s3_objects_total, and
# presigned_urls_total (labeled role/bucket -- see their definitions above),
# and it ALSO excludes s3_operations_total, sts_assume_role_total, and
# credentials_refreshed_total: even though `operation`/`error_code`/`result`
# on those three are fixed enums in isolation, all three additionally carry a
# `role` label, so the same reasoning applies to them in full.
def _seed_zero_series() -> None:
    """Pre-create the Prometheus series for every fixed-enum counter label
    combination the app actually emits, at value 0.

    Called once at process startup (see main.py, near the scrape-time gauge
    callbacks). Safe to call more than once: `.labels(...)` returns the same
    child on repeat calls with the same label values, so re-seeding is a
    harmless no-op. Never raises: every call here is a pure in-memory
    `.labels()` lookup/creation on an already-constructed Counter, no I/O.
    """
    # upload_rejected_total{reason}: "size_limit" is the only reason ever
    # emitted by the two call sites in main.py. "deletion_disabled" and
    # "invalid_path" are reserved for future PRs (see the comment above the
    # Counter's definition) -- do not seed a reason nothing produces yet.
    upload_rejected_total.labels(reason="size_limit")

    # auth_logins_total{result}: the three outcomes /api/login emits.
    for result in ("success", "invalid_password", "banned"):
        auth_logins_total.labels(result=result)

    # s3_retries_total{reason}: only "credentials_expired" is ever emitted
    # (see the comment above the Counter -- botocore's own throttle retries
    # are invisible to this counter by design; never invent "throttled" here).
    s3_retries_total.labels(reason="credentials_expired")

    # mcp_auth_failures_total{reason}: authenticate_mcp_request only emits
    # "malformed" (missing/malformed Bearer header) and "invalid_token"
    # (unknown, dangling-user, or revoked token -- find_active_token_by_hash
    # only returns active tokens, so a revoked token is indistinguishable
    # from an unknown one and both fold into "invalid_token"). "revoked"
    # appears in this Counter's docstring as a reserved/aspirational value
    # the code doesn't actually produce -- do not seed it.
    for reason in ("malformed", "invalid_token"):
        mcp_auth_failures_total.labels(reason=reason)

    # mcp_writes_denied_total{tool, reason}: assert_write_allowed() only
    # checks "deletion_disabled" when tool_name == "delete_file", so that
    # combination is unreachable for upload_file. copy_object has its own
    # standalone deletion_disabled guard (the delete_source=True path in
    # mcp_server.copy_object) that emits the same label combination, so it IS
    # seeded for copy_object even though it doesn't go through
    # assert_write_allowed's own tool_name == "delete_file" branch.
    for tool in ("upload_file", "delete_file", "copy_object"):
        mcp_writes_denied_total.labels(tool=tool, reason="writes_disabled")
        mcp_writes_denied_total.labels(tool=tool, reason="read_only_token")
    mcp_writes_denied_total.labels(tool="delete_file", reason="deletion_disabled")
    mcp_writes_denied_total.labels(tool="copy_object", reason="deletion_disabled")

    # mcp_reads_refused_total{tool, reason}: only read_file emits this
    # counter, with exactly two reasons.
    for reason in ("file_too_large", "binary_content"):
        mcp_reads_refused_total.labels(tool="read_file", reason=reason)

    # mcp_tool_calls_total{tool, error_code}: every one of the 9 @mcp.tool()
    # functions in mcp_server.py shares an identical try/except skeleton --
    # authenticate, do the S3-backed work, and an exception chain
    # (`except S3AccessDeniedError` / `S3NotFoundError` / `S3ConfigError` /
    # `S3NetworkError` / `CredentialsExpiredError` / `S3OperationError` /
    # `Exception`) that maps to exactly these 8 literals (verified: every one
    # of the 9 functions assigns precisely this set to its local `error_code`
    # in its finally block). "none" is the success path. Tool-specific
    # McpErrors raised earlier in a given tool (ROLE_NOT_ALLOWED,
    # BUCKET_NOT_ALLOWED, INVALID_TOKEN, FILE_NOT_FOUND, INVALID_INPUT, ...)
    # are deliberately NOT seeded: they differ per tool (would need
    # re-verifying each tool's exact reachable set instead of relying on one
    # shared taxonomy) and INVALID_TOKEN in particular is already covered by
    # mcp_auth_failures_total.
    mcp_tools = (
        "list_roles",
        "list_buckets",
        "list_files",
        "upload_file",
        "delete_file",
        "read_file",
        "copy_object",
        "get_object_metadata",
        "presigned_url",
    )
    mcp_common_error_codes = (
        "none",
        "S3_ACCESS_DENIED",
        "S3_NOT_FOUND",
        "S3_CONFIG_ERROR",
        "S3_NETWORK_ERROR",
        "CREDENTIALS_EXPIRED",
        "S3_OPERATION_ERROR",
        "INTERNAL_ERROR",
    )
    for tool in mcp_tools:
        for error_code in mcp_common_error_codes:
            mcp_tool_calls_total.labels(tool=tool, error_code=error_code)

    # db_errors_total{operation}: _statement_op() in database.py classifies
    # every SQL statement into exactly these 5 buckets.
    for operation in ("SELECT", "INSERT", "UPDATE", "DELETE", "OTHER"):
        db_errors_total.labels(operation=operation)

    # --- Deliberately NOT seeded ---------------------------------------------
    # auth_bans_total, mcp_tokens_issued_total, mcp_tokens_revoked_total:
    #   unlabeled Counters. prometheus_client materializes an unlabeled
    #   metric's single sample at construction time -- no `.labels()` call is
    #   needed or even possible -- so these are already visible at 0 from the
    #   moment metrics.py is imported. They never had the born-non-zero
    #   problem this function exists to solve.
    #
    # s3_operations_total, sts_assume_role_total, credentials_refreshed_total,
    # s3_bytes_total, s3_objects_total, presigned_urls_total:
    #   all carry a `role` and/or `bucket` label -- see the module comment
    #   above this function for why those can't be safely pre-enumerated.
