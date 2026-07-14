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


def test_configure_logging_leaves_foreign_handlers_alone(monkeypatch):
    """THE regression the named-handler rewrite exists for.

    configure_logging() used to clear EVERY handler on the root logger to stay idempotent,
    evicting handlers it never installed -- pytest's own log-capture handler among them, which
    is why log assertions behaved erratically once anything re-triggered the module-level call.

    test_configure_logging_is_idempotent cannot catch a regression here: it counts only OUR
    handlers, so an implementation that goes back to clearing root wholesale and then adds one
    of ours still passes it. This test is what actually pins the fix.
    """
    root = logging.getLogger()
    foreign = logging.NullHandler()
    foreign.name = "someone-elses-handler"
    root.addHandler(foreign)

    monkeypatch.setenv("LOG_LEVEL", "INFO")
    configure_logging()
    configure_logging()  # re-configure: the foreign handler must survive this too

    assert foreign in root.handlers, "configure_logging() evicted a handler it does not own"
    assert len([h for h in root.handlers if h.name == HANDLER_NAME]) == 1, "our own handler duplicated"


def test_invalid_log_level_falls_back_to_info(monkeypatch, capsys):
    monkeypatch.setenv("LOG_LEVEL", "VERBOSE")
    configure_logging()
    assert logging.getLogger().level == logging.INFO
    captured = capsys.readouterr()
    assert "VERBOSE" in captured.err
    assert "INFO" in captured.err


def test_alembic_upgrade_does_not_silence_the_app(monkeypatch, tmp_path):
    """THE regression this fix exists for, and the reason it went unnoticed.

    migrations/env.py calls logging.config.fileConfig(), whose stdlib default is
    disable_existing_loggers=True. Migrations run at startup, AFTER logging is configured
    and after every module-level logging.getLogger(__name__) has already run -- so it used
    to set .disabled = True on every another_s3_manager.* logger AND on uvicorn's own
    (uvicorn.error, uvicorn.access), and to replace root's handler with alembic.ini's
    (stderr, alembic's format, level WARNING). The process went essentially log-silent for
    the rest of its life: no auth events, no MCP audit lines, no security warnings, no
    access log, and LOG_FORMAT=json silently stopped working. It shipped in v1.1.1.

    Nothing failed, because nothing asserted it. This test does.
    """
    from another_s3_manager.main import _run_alembic_upgrade

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    monkeypatch.setenv("LOG_FORMAT", "text")
    configure_logging()

    # Loggers that exist BEFORE the migration runs -- exactly the situation at startup.
    app_logger = logging.getLogger("another_s3_manager.main")
    uvicorn_logger = logging.getLogger("uvicorn.error")
    assert not app_logger.disabled
    assert not uvicorn_logger.disabled

    _run_alembic_upgrade()

    assert not app_logger.disabled, "alembic's fileConfig disabled the app's loggers -- the app is now mute"
    assert not uvicorn_logger.disabled, "alembic's fileConfig disabled uvicorn's loggers -- no access log"
    root = logging.getLogger()
    assert any(h.name == HANDLER_NAME for h in root.handlers), "our root handler was replaced by alembic.ini's"
    assert root.level == logging.INFO, "root's level was overwritten by alembic.ini's"
