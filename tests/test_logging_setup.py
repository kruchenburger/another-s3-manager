"""Tests for logging_setup module — verifies root logger is configured correctly."""

import logging

import pytest

from another_s3_manager.logging_setup import HANDLER_NAME, configure_logging


@pytest.fixture(autouse=True)
def _reset_logging():
    """Snapshot root logger state before each test, restore after."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    # Remove anything tests added; restore original handlers
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in saved_handlers:
        root.addHandler(h)
    root.setLevel(saved_level)


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
    # configure_logging() only owns its own named handler on root -- it deliberately
    # leaves any other handler (e.g. pytest's own log-capture handler) alone, so look up
    # OUR handler by name rather than assuming it's the only (or first) one on root.
    handler = next(h for h in logging.getLogger().handlers if h.name == HANDLER_NAME)
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


def test_configure_logging_is_idempotent(monkeypatch):
    """Calling configure_logging twice must not duplicate OUR handler.

    Counts only handlers configure_logging() itself owns (matched by HANDLER_NAME) --
    it deliberately leaves foreign handlers (e.g. pytest's own log-capture handler) on
    root untouched, so the total handler count on root is not a meaningful assertion here.
    """

    def _our_handler_count() -> int:
        return len([h for h in logging.getLogger().handlers if h.name == HANDLER_NAME])

    monkeypatch.setenv("LOG_LEVEL", "INFO")
    configure_logging()
    first_count = _our_handler_count()
    configure_logging()
    second_count = _our_handler_count()
    assert first_count == second_count == 1


def test_invalid_log_level_falls_back_to_info(monkeypatch, capsys):
    monkeypatch.setenv("LOG_LEVEL", "VERBOSE")
    configure_logging()
    assert logging.getLogger().level == logging.INFO
    captured = capsys.readouterr()
    assert "VERBOSE" in captured.err
    assert "INFO" in captured.err
