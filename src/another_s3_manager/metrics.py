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

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info

REGISTRY = CollectorRegistry(auto_describe=True)

# --- HTTP / API ---
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path_template", "status_code"],
    registry=REGISTRY,
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path_template"],
    registry=REGISTRY,
)

# --- Auth ---
auth_logins_total = Counter(
    "auth_logins_total",
    "Login attempts by result",
    ["result"],  # success | invalid_password | banned
    registry=REGISTRY,
)
auth_bans_active = Gauge(
    "auth_bans_active",
    "Active bans (banned_until > now)",
    registry=REGISTRY,
)

# --- S3 ops ---
s3_operations_total = Counter(
    "s3_operations_total",
    "S3 operations executed",
    ["role", "operation", "result"],  # operation: list|get|put|delete|head; result: ok|error
    registry=REGISTRY,
)
s3_operation_duration_seconds = Histogram(
    "s3_operation_duration_seconds",
    "S3 operation duration",
    ["operation"],
    registry=REGISTRY,
)
s3_bytes_uploaded_total = Counter(
    "s3_bytes_uploaded_total",
    "Bytes uploaded to S3",
    ["role", "bucket"],
    registry=REGISTRY,
)
s3_bytes_downloaded_total = Counter(
    "s3_bytes_downloaded_total",
    "Bytes downloaded from S3",
    ["role", "bucket"],
    registry=REGISTRY,
)

# --- MCP-specific (Task 11 wires these) ---
mcp_tool_calls_total = Counter(
    "mcp_tool_calls_total",
    "MCP tool calls",
    ["tool", "error_code"],  # error_code="none" on success
    registry=REGISTRY,
)
mcp_tool_duration_seconds = Histogram(
    "mcp_tool_duration_seconds",
    "MCP tool call duration",
    ["tool"],
    registry=REGISTRY,
)
mcp_bytes_read_total = Counter(
    "mcp_bytes_read_total",
    "Bytes returned from read_file",
    ["bucket"],
    registry=REGISTRY,
)
mcp_auth_failures_total = Counter(
    "mcp_auth_failures_total",
    "MCP authentication failures",
    ["reason"],  # invalid_token | revoked | malformed
    registry=REGISTRY,
)
mcp_active_tokens = Gauge(
    "mcp_active_tokens",
    "Active (non-revoked) API tokens",
    registry=REGISTRY,
)

# --- App health ---
app_info = Info("app", "Application info", registry=REGISTRY)
app_db_query_duration_seconds = Histogram(
    "app_db_query_duration_seconds",
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
