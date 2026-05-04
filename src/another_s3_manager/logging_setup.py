"""Configures the root logger before FastAPI app creation.

Without this call, our `logger = logging.getLogger(__name__)` calls land on
Python's default root logger (WARNING level, no handler) and are silently
dropped — which is why `docker compose logs` only shows uvicorn lines.
"""

import logging
import logging.config
import os
import sys


_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def configure_logging() -> None:
    """Configure root logger from env vars LOG_LEVEL and LOG_FORMAT.

    LOG_LEVEL: standard Python level name (DEBUG/INFO/WARNING/ERROR), default INFO.
    LOG_FORMAT: 'text' (human-readable) or 'json' (structured), default 'text'.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("LOG_FORMAT", "text").lower()

    # Validate log level before passing to dictConfig — an invalid value raises
    # ValueError inside dictConfig which produces a confusing startup traceback.
    if log_level not in _VALID_LOG_LEVELS:
        print(
            f"WARNING: LOG_LEVEL='{log_level}' is not a valid Python log level."
            " Falling back to INFO.",
            file=sys.stderr,
        )
        log_level = "INFO"

    # Clear existing root handlers to make this function idempotent.
    # dictConfig does NOT remove handlers added by previous calls, so a
    # double-call (e.g. import-time + test re-import) would duplicate output.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    if log_format == "json":
        formatter = {
            "()": "pythonjsonlogger.json.JsonFormatter",
            "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    else:
        formatter = {
            "format": "%(asctime)s %(levelname)s %(name)s: %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S%z",
        }

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"default": formatter},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": sys.stdout,
                },
            },
            "root": {"level": log_level, "handlers": ["console"]},
            "loggers": {
                "boto3": {"level": "WARNING"},
                "botocore": {"level": "WARNING"},
                "urllib3": {"level": "WARNING"},
                "s3transfer": {"level": "WARNING"},
            },
        }
    )
