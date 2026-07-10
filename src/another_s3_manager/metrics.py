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
