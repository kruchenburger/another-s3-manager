"""Tests for logging_setup module — verifies root logger is configured correctly."""

import logging

import pytest

from another_s3_manager.logging_setup import (
    HANDLER_NAME,
    _AccessLogPathFilter,
    configure_logging,
    install_access_log_filter,
)


@pytest.mark.parametrize("format", ["text", "json"])
def test_oidc_canaries_absent_from_final_text_and_json_logs(monkeypatch, capsys, format):
    monkeypatch.setenv("LOG_FORMAT", format)
    monkeypatch.setenv("ACCESS_LOG_EXCLUDE_PATHS", "")
    configure_logging()
    install_access_log_filter()
    logger = logging.getLogger("another_s3_manager.oidc")
    for key in ("code", "state", "token", "id_token_hint", "client_secret", "code_verifier", "refresh_token", "cookie"):
        logger.warning("request https://op.example/callback?%s=canary-%s&%%63ode=encoded-canary", key, key)
    logging.getLogger("uvicorn.access").warning(
        '%s - "%s %s HTTP/%s" %s',
        "client",
        "GET",
        "/api/auth/oidc/callback?code=access-canary&state=state-canary",
        "1.1",
        500,
    )
    try:
        raise ValueError("exception-body-canary")
    except ValueError:
        logger.exception("OIDC failed")
    logging.getLogger("httpx").warning("raw-upstream-canary")
    logger.warning("structured %s", {"client_secret": "mapping-canary"})
    logger.warning(
        "extra",
        extra={"payload": {"body": "body-canary", "code": "code-canary", "cookies": {"access_token": "cookie-canary"}}},
    )
    output = capsys.readouterr().out
    assert "OIDC failed" in output
    assert "canary" not in output


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


# --- access-log path filter -------------------------------------------------


def _access_record(path: str, status: int, method: str = "GET") -> logging.LogRecord:
    """A LogRecord shaped exactly like uvicorn.access emits: positional args
    (client_addr, method, full_path, http_version, status_code)."""
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("10.0.0.1:1234", method, path, "1.1", status),
        exc_info=None,
    )


@pytest.fixture
def _clean_access_logger():
    """Snapshot/restore uvicorn.access's filters around a test."""
    access = logging.getLogger("uvicorn.access")
    saved = list(access.filters)
    yield access
    access.filters = saved


@pytest.mark.parametrize("path", ["/", "/health", "/metrics"])
def test_access_filter_drops_successful_noise_paths(path):
    f = _AccessLogPathFilter({"/", "/health", "/metrics"})
    assert f.filter(_access_record(path, 200)) is False
    assert f.filter(_access_record(path, 204)) is False


def test_access_filter_keeps_real_paths_and_errors():
    f = _AccessLogPathFilter({"/", "/health", "/metrics"})
    # Real API traffic is always kept.
    assert f.filter(_access_record("/api/buckets?role=X", 200)) is True
    assert f.filter(_access_record("/favicon.ico", 200)) is True
    # A failure on a noise path is kept — the filter hides noise, not problems.
    assert f.filter(_access_record("/", 500)) is True
    assert f.filter(_access_record("/metrics", 503)) is True
    # The query string is stripped before matching the excluded path.
    assert f.filter(_access_record("/metrics?foo=bar", 200)) is False


def test_access_filter_ignores_non_uvicorn_records():
    f = _AccessLogPathFilter({"/"})
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "plain message", None, None)
    assert f.filter(rec) is True


def test_install_access_filter_default_drops_root(monkeypatch, _clean_access_logger):
    monkeypatch.delenv("ACCESS_LOG_EXCLUDE_PATHS", raising=False)
    install_access_log_filter()
    installed = [f for f in _clean_access_logger.filters if isinstance(f, _AccessLogPathFilter)]
    assert len(installed) == 1
    assert installed[0].filter(_access_record("/", 200)) is False
    assert installed[0].filter(_access_record("/metrics", 200)) is False
    assert installed[0].filter(_access_record("/api/me", 200)) is True


def test_install_access_filter_empty_disables(monkeypatch, _clean_access_logger):
    monkeypatch.setenv("ACCESS_LOG_EXCLUDE_PATHS", "")
    install_access_log_filter()
    installed = [f for f in _clean_access_logger.filters if isinstance(f, _AccessLogPathFilter)]
    assert installed == []


def test_install_access_filter_custom_paths(monkeypatch, _clean_access_logger):
    monkeypatch.setenv("ACCESS_LOG_EXCLUDE_PATHS", "/foo, /bar")
    install_access_log_filter()
    f = [f for f in _clean_access_logger.filters if isinstance(f, _AccessLogPathFilter)][0]
    assert f.filter(_access_record("/foo", 200)) is False
    assert f.filter(_access_record("/bar", 200)) is False
    # Defaults no longer apply once the env overrides the set.
    assert f.filter(_access_record("/metrics", 200)) is True


def test_install_access_filter_idempotent(monkeypatch, _clean_access_logger):
    monkeypatch.delenv("ACCESS_LOG_EXCLUDE_PATHS", raising=False)
    install_access_log_filter()
    install_access_log_filter()
    installed = [f for f in _clean_access_logger.filters if isinstance(f, _AccessLogPathFilter)]
    assert len(installed) == 1
