"""Tests for the upload size-limit resolver and the upload body-guard middleware.

The body-guard closes the unauthenticated upload DoS: FastAPI parses (and
Starlette spools to disk) the multipart body to satisfy `File(...)` BEFORE
route dependencies like get_current_user run, so without the guard an
unauthenticated 10 GB POST fills the temp dir and only then gets a 401.
"""

import importlib

from tests.test_main import login  # noqa: F401 - reused by the middleware tests added in Task 3


def reload_main():
    import another_s3_manager.main as main

    importlib.reload(main)
    return main


# --- resolve_max_file_size ---


def test_resolve_max_file_size_config_wins_over_env(monkeypatch):
    """The admin-editable config value beats the MAX_FILE_SIZE env var."""
    import another_s3_manager.config as config_module

    main = reload_main()
    monkeypatch.setenv("MAX_FILE_SIZE", "555")
    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 12345
    config_module.save_config(cfg)

    assert main.resolve_max_file_size() == 12345


def test_resolve_max_file_size_env_fallback_when_config_key_missing(monkeypatch, mocker):
    """Config without the key (bypassing migration) falls back to MAX_FILE_SIZE."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.load_config", return_value={})
    monkeypatch.setenv("MAX_FILE_SIZE", "777")

    assert main.resolve_max_file_size() == 777


def test_resolve_max_file_size_default_100mb(monkeypatch, mocker):
    """No config key, no env var → 100 MB default."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.load_config", return_value={})
    monkeypatch.delenv("MAX_FILE_SIZE", raising=False)

    assert main.resolve_max_file_size() == 100 * 1024 * 1024
