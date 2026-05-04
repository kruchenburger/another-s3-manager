"""Tests for logging_setup module — verifies root logger is configured correctly."""
import logging

import pytest

from another_s3_manager.logging_setup import configure_logging


@pytest.fixture(autouse=True)
def _reset_logging():
    """Reset root logger between tests to avoid handler leakage."""
    yield
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(logging.WARNING)


def test_text_format_attaches_handler_at_info_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "info")
    monkeypatch.setenv("LOG_FORMAT", "text")
    configure_logging()
    root = logging.getLogger()
    assert root.level == logging.INFO
    assert len(root.handlers) >= 1


def test_json_format_uses_jsonformatter(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "info")
    monkeypatch.setenv("LOG_FORMAT", "json")
    configure_logging()
    handler = logging.getLogger().handlers[0]
    formatter_class_name = type(handler.formatter).__name__
    assert "Json" in formatter_class_name


def test_noisy_libs_quieted_to_warning(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "info")
    configure_logging()
    for name in ("boto3", "botocore", "urllib3", "s3transfer"):
        assert logging.getLogger(name).level == logging.WARNING


def test_default_log_level_is_info_when_env_unset(monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging()
    assert logging.getLogger().level == logging.INFO


def test_log_level_case_insensitive(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    configure_logging()
    assert logging.getLogger().level == logging.DEBUG
