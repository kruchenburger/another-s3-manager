"""Configures the root logger before FastAPI app creation.

Without this call, our `logger = logging.getLogger(__name__)` calls land on
Python's default root logger (WARNING level, no handler) and are silently
dropped — which is why `docker compose logs` only shows uvicorn lines.
"""

import logging
import os
import sys

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
