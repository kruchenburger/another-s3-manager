"""Configures the root logger before FastAPI app creation.

Without this call, our `logger = logging.getLogger(__name__)` calls land on
Python's default root logger (WARNING level, no handler) and are silently
dropped — which is why `docker compose logs` only shows uvicorn lines.
"""

import logging
import os
import re
import sys
from urllib.parse import unquote

from pythonjsonlogger.json import JsonFormatter

_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_QUIET_LOGGERS = ("boto3", "botocore", "urllib3", "s3transfer")

# Name tag for the handler this function installs on the root logger. Removing by name
# (rather than blindly clearing every handler, which is what logging.config.dictConfig/
# fileConfig do when configuring the root logger) keeps repeat calls idempotent without
# evicting handlers OTHER code attached to root -- e.g. pytest's log-capture handler when
# this function reruns mid-test (tests reload `main`, which re-executes this module-level
# call). Matching by name (not a stored object reference) also stays correct even if
# something else has directly manipulated root.handlers between calls (e.g. a test
# fixture's snapshot/restore of the handler list).
HANDLER_NAME = "another_s3_manager.console"

_SENSITIVE = r"code|state|token|id_token|access_token|id_token_hint|client_secret|code_verifier|refresh_token|cookie|cookies|authorization|body|headers|password|password_hash|oidc_tx_[a-zA-Z0-9_-]+"


def _decoded_name(value):
    # Decode names only: encoded separators inside values are still secret data.
    for _ in range(4):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def redact_auth_material(value):
    if not isinstance(value, str):
        return value

    def query_parameter(match):
        if re.fullmatch(_SENSITIVE, _decoded_name(match[2]), re.IGNORECASE):
            return match[1] + "auth=[redacted]"
        return match[0]

    # Split on raw query delimiters before inspecting encoded parameter names.
    value = re.sub(r"([?&])([^=&\s\"'<>]+)=([^&\s]*)", query_parameter, value)

    def field(match):
        if re.fullmatch(_SENSITIVE, _decoded_name(match[1]), re.IGNORECASE):
            return "auth=[redacted]"
        return match[0]

    value = re.sub(r"([\w%.-]+)[\"']?\s*[=:]\s*(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)", field, value)
    value = re.sub(r"https?://[^\s\"<>]+\?[^\s\"<>]*", "[authentication URL redacted]", value)
    for name in ("OIDC_CLIENT_SECRET", "JWT_SECRET_KEY"):
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "[redacted]")
    return value


def _redact_value(value):
    if isinstance(value, BaseException):
        return "[exception details redacted]"
    if isinstance(value, dict):
        return {
            key: "[redacted]"
            if isinstance(key, str) and re.fullmatch(_SENSITIVE, _decoded_name(key), re.IGNORECASE)
            else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return redact_auth_material(value)


class _AuthRedactionFilter(logging.Filter):
    def filter(self, record):
        if record.name.startswith(("httpx", "httpcore")):
            record.msg, record.args = "OIDC HTTP transport event", ()
        elif record.name == "uvicorn.access" and isinstance(record.args, tuple) and len(record.args) == 5:
            # AccessFormatter unpacks these five positional fields itself.
            record.args = _redact_value(record.args)
        else:
            if not isinstance(record.msg, str):
                record.msg = _redact_value(record.msg)
            record.args = _redact_value(record.args)
            record.msg = redact_auth_material(record.getMessage())
            record.args = ()
        for name, value in list(record.__dict__.items()):
            if re.fullmatch(_SENSITIVE, name, re.IGNORECASE):
                setattr(record, name, "[redacted]")
            elif name not in {"exc_info", "args"}:
                setattr(record, name, _redact_value(value))
        if record.exc_info:
            # Exception messages/locals may contain upstream bodies or credentials.
            record.exc_info = None
            record.exc_text = "[exception details redacted]"
        return True


def configure_logging() -> None:
    """Configure root logger from env vars LOG_LEVEL and LOG_FORMAT.

    LOG_LEVEL: standard Python level name (DEBUG/INFO/WARNING/ERROR), default INFO.
    LOG_FORMAT: 'text' (human-readable) or 'json' (structured), default 'text'.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("LOG_FORMAT", "text").lower()

    # Validate log level before configuring — an invalid value would otherwise silently
    # fall back to logging's own default (WARNING) with no indication why.
    if log_level not in _VALID_LOG_LEVELS:
        print(
            f"WARNING: LOG_LEVEL='{log_level}' is not a valid Python log level. Falling back to INFO.",
            file=sys.stderr,
        )
        log_level = "INFO"

    formatter: logging.Formatter
    if log_format == "json":
        formatter = JsonFormatter(fmt="%(asctime)s %(levelname)s %(name)s %(message)s")
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(_AuthRedactionFilter())
    handler.name = HANDLER_NAME

    root = logging.getLogger()
    # Idempotent re-configuration: remove every handler we previously installed (matched
    # by name -- see HANDLER_NAME comment above), then install the new one. Foreign
    # handlers are left untouched.
    for existing in [h for h in root.handlers if h.name == HANDLER_NAME]:
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(log_level)

    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


# Default paths whose successful access-log lines are pure infrastructure noise:
# the SPA/health root that load balancers and uptime monitors poll, the app's
# health endpoint, and the Prometheus scrape target. Overridable via env.
_DEFAULT_ACCESS_LOG_EXCLUDE = "/,/health,/metrics"


class _AccessLogPathFilter(logging.Filter):
    """Drop uvicorn access-log records for successful requests to noisy paths.

    uvicorn emits each access line via `uvicorn.access` with positional args
    `(client_addr, method, full_path, http_version, status_code)`. This filter
    suppresses a record only when the request path is in the exclude set AND the
    response was successful (status < 400) — a failing health check or a 5xx on
    `/` still gets logged, so the filter hides noise without hiding problems.
    Records whose args don't match uvicorn's shape are always kept.
    """

    def __init__(self, exclude_paths: set[str]) -> None:
        super().__init__()
        self._exclude = exclude_paths

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not isinstance(args, tuple) or len(args) < 5:
            return True
        full_path, status_code = args[2], args[4]
        try:
            status = int(status_code)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return True
        if status >= 400:
            return True
        path = str(full_path).split("?", 1)[0]
        return path not in self._exclude


def install_access_log_filter() -> None:
    """Attach the access-log path filter to uvicorn's `uvicorn.access` logger.

    Reads `ACCESS_LOG_EXCLUDE_PATHS` (comma-separated; default
    `/,/health,/metrics`). An empty value disables filtering entirely. Idempotent
    — repeat calls (e.g. test-driven restarts) replace, never stack, the filter.
    Call this at startup, after uvicorn has configured its access logger.
    """
    raw = os.getenv("ACCESS_LOG_EXCLUDE_PATHS", _DEFAULT_ACCESS_LOG_EXCLUDE)
    exclude = {p.strip() for p in raw.split(",") if p.strip()}

    access_logger = logging.getLogger("uvicorn.access")
    access_logger.filters = [
        f for f in access_logger.filters if not isinstance(f, (_AccessLogPathFilter, _AuthRedactionFilter))
    ]
    if exclude:
        access_logger.addFilter(_AccessLogPathFilter(exclude))

    access_logger.addFilter(_AuthRedactionFilter())
