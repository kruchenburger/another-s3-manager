import builtins
import importlib
import json
import os
import threading
import time
from pathlib import Path

import pytest


def reload_config():
    import another_s3_manager.config as config

    importlib.reload(config)
    return config


def test_load_config_creates_default_when_missing(tmp_path):
    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])

    config.CONFIG_FILE.write_text(json.dumps({"roles": []}))
    if config.CONFIG_FILE.exists():
        config.CONFIG_FILE.unlink()
    config._config_cache = {}
    config._config_mtime = 0

    data = config.load_config(force_reload=True)
    assert "roles" in data
    assert "current_role" not in data  # current_role is no longer stored in config


def test_load_config_uses_cache(monkeypatch):
    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    config._config_cache = {"cached": True}
    config._config_mtime = config.CONFIG_FILE.stat().st_mtime

    data = config.load_config(force_reload=False)
    assert data == {"cached": True}


def test_migrate_config_adds_missing_fields(tmp_path):
    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    config.CONFIG_FILE.write_text(json.dumps({"roles": []}))
    config._config_cache = {}
    config._config_mtime = 0

    data = config.load_config(force_reload=True)
    assert "enable_lazy_loading" in data
    assert "max_file_size" in data


def test_migrate_config_splits_legacy_auto_inline(tmp_path):
    """A legacy config with auto_inline_extensions splits into the two new keys:
    preview_text_extensions inherits the legacy list verbatim; upload_inline_extensions
    is the legacy list UNIONED with the pdf+images default (zero upload-inline
    regression + restores browser-open PDFs); the legacy keys are dropped."""
    from another_s3_manager.constants import DEFAULT_UPLOAD_INLINE_EXTENSIONS

    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    # Mirror a customized legacy list (like a real deployment): pdf + docx + text.
    config.CONFIG_FILE.write_text(
        json.dumps({"roles": [], "auto_inline_extensions": ["pdf", "docx", "md"], "_auto_inline_seeded": True})
    )
    config._config_cache = {}
    config._config_mtime = 0

    data = config.load_config(force_reload=True)
    # Preview keeps the legacy list exactly.
    assert data["preview_text_extensions"] == ["pdf", "docx", "md"]
    # Upload-inline preserves every legacy entry, then unions in the defaults
    # (pdf already present isn't duplicated; images are appended).
    assert data["upload_inline_extensions"][:3] == ["pdf", "docx", "md"]
    for ext in DEFAULT_UPLOAD_INLINE_EXTENSIONS:
        assert ext in data["upload_inline_extensions"]
    assert data["upload_inline_extensions"].count("pdf") == 1  # no dup
    assert "auto_inline_extensions" not in data
    assert "_auto_inline_seeded" not in data


def test_migrate_config_fresh_seeds_both_defaults(tmp_path):
    """A config with neither key gets both text-preview and upload-inline defaults."""
    from another_s3_manager.constants import (
        DEFAULT_PREVIEW_TEXT_EXTENSIONS,
        DEFAULT_UPLOAD_INLINE_EXTENSIONS,
    )

    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    config.CONFIG_FILE.write_text(json.dumps({"roles": []}))
    config._config_cache = {}
    config._config_mtime = 0

    data = config.load_config(force_reload=True)
    assert data["preview_text_extensions"] == list(DEFAULT_PREVIEW_TEXT_EXTENSIONS)
    assert data["upload_inline_extensions"] == list(DEFAULT_UPLOAD_INLINE_EXTENSIONS)


def test_migrate_config_does_not_reseed_cleared_lists(tmp_path):
    """Once migrated (keys present), admin's intentional clears to [] persist."""
    config = reload_config()
    config.CONFIG_FILE = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    config.CONFIG_FILE.write_text(
        json.dumps({"roles": [], "preview_text_extensions": [], "upload_inline_extensions": []})
    )
    config._config_cache = {}
    config._config_mtime = 0

    data = config.load_config(force_reload=True)
    assert data["preview_text_extensions"] == []
    assert data["upload_inline_extensions"] == []


def test_load_config_tolerates_stale_items_per_page(tmp_path):
    """Phase 7 removed items_per_page, but pre-1.0 config.json files still
    contain it. The loader must keep loading (raw json.load, unknown keys
    preserved) and the API must simply ignore the key."""
    config = reload_config()
    config.CONFIG_FILE = tmp_path / "config.json"
    config.CONFIG_FILE.write_text(json.dumps({"roles": [], "items_per_page": 200}))
    config._config_cache = {}
    config._config_mtime = 0

    loaded = config.load_config(force_reload=True)
    assert loaded["roles"] == []
    assert loaded.get("items_per_page") == 200  # preserved, harmless


def test_get_default_config_respects_env(monkeypatch):
    monkeypatch.setenv("MAX_FILE_SIZE", str(10 * 1024 * 1024))

    config = reload_config()
    defaults = config._get_default_config()
    assert defaults["max_file_size"] == 10 * 1024 * 1024


def test_is_config_writable_true(tmp_path):
    config = reload_config()
    config.CONFIG_FILE = tmp_path / "config.json"
    config.CONFIG_FILE.write_text("{}")
    assert config.is_config_writable() is True


def test_is_config_writable_false(monkeypatch, tmp_path):
    config = reload_config()
    config.CONFIG_FILE = tmp_path / "config.json"
    config.CONFIG_FILE.write_text("{}")

    real_open = builtins.open

    def fail_open(file, mode="r", *args, **kwargs):
        if str(file) == str(config.CONFIG_FILE) and "a" in mode:
            raise PermissionError("Read-only")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fail_open)
    assert config.is_config_writable() is False


def test_save_config_writes_file(tmp_path):
    config = reload_config()
    config.CONFIG_FILE = tmp_path / "config.json"

    data = {"sample": "value"}
    config.save_config(data)
    saved = json.loads(config.CONFIG_FILE.read_text())
    assert saved["sample"] == "value"


def test_save_config_raises_when_read_only(monkeypatch, tmp_path):
    config = reload_config()
    config.CONFIG_FILE = tmp_path / "config.json"
    config.CONFIG_FILE.write_text("{}")

    monkeypatch.setattr("another_s3_manager.config.is_config_writable", lambda: False)
    with pytest.raises(PermissionError):
        config.save_config({"sample": "value"})


def test_get_config_value_returns_value():
    config = reload_config()
    data = config.load_config(force_reload=True)
    data["max_client_load"] = 123
    config.save_config(data)

    value = config.get_config_value("max_client_load", default=50)
    assert value == 123


def test_get_config_value_env_fallback(monkeypatch):
    monkeypatch.setenv("CUSTOM_VAR", "true")
    config = reload_config()
    value = config.get_config_value("missing", default=False, env_var="CUSTOM_VAR")
    assert value is True


def test_get_config_value_returns_default_when_missing():
    config = reload_config()
    value = config.get_config_value("not_there", default="fallback")
    assert value == "fallback"


def test_is_config_writable_creates_missing_directory(tmp_path):
    config = reload_config()
    target = tmp_path / "nested" / "config.json"
    if target.exists():
        target.unlink()
    config.CONFIG_FILE = target
    assert config.is_config_writable() is True
    assert target.parent.exists()


def test_is_config_writable_handles_permission_error(monkeypatch, tmp_path):
    config = reload_config()
    target = tmp_path / "denied" / "config.json"
    config.CONFIG_FILE = target

    def fail_mkdir(self, *args, **kwargs):
        raise PermissionError("no access")

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    assert config.is_config_writable() is False


def test_get_config_value_env_invalid_int(monkeypatch):
    monkeypatch.setenv("BROKEN_INT", "not-an-int")
    config = reload_config()
    value = config.get_config_value("missing", default=7, env_var="BROKEN_INT")
    assert value == 7


def test_is_config_writable_handles_write_failure(monkeypatch, tmp_path):
    config_module = reload_config()
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)

    if config_file.exists():
        config_file.unlink()

    monkeypatch.setattr(config_module, "_can_write_test_file", lambda path: False)

    assert config_module._can_write_test_file(config_file.parent / ".write_test") is False
    assert config_file.exists() is False

    assert config_module.is_config_writable() is False


def test_can_write_test_file_handles_errors():
    config_module = reload_config()

    class FakePath:
        def write_text(self, data):
            raise PermissionError("no write")

        def unlink(self):  # pragma: no cover - should not be called
            raise AssertionError("should not unlink")

    assert config_module._can_write_test_file(FakePath()) is False


def test_get_config_value_env_string(monkeypatch):
    monkeypatch.setenv("STRING_VALUE", "text")
    config = reload_config()
    value = config.get_config_value("missing", default="default", env_var="STRING_VALUE")
    assert value == "text"


def test_default_config_includes_mcp_fields():
    from another_s3_manager.config import _get_default_config

    cfg = _get_default_config()
    assert cfg["mcp_enabled"] is True
    assert cfg["mcp_disable_writes"] is False
    assert cfg["mcp_text_extensions"] == []
    assert cfg["mcp_global_max_read_bytes"] == 10_485_760


def test_migrate_config_adds_mcp_fields_to_legacy_config(monkeypatch, tmp_path):
    """A legacy config.json without MCP fields should get them auto-added on load."""
    import json

    from another_s3_manager import config as config_module

    legacy = tmp_path / "config.json"
    legacy.write_text(json.dumps({"roles": [], "items_per_page": 200}))
    monkeypatch.setattr(config_module, "CONFIG_FILE", legacy)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    loaded = config_module.load_config(force_reload=True)
    assert "mcp_enabled" in loaded
    assert "mcp_disable_writes" in loaded
    assert "mcp_text_extensions" in loaded
    assert "mcp_global_max_read_bytes" in loaded
    # Verify defaults are correct, not just presence
    assert loaded["mcp_enabled"] is True
    assert loaded["mcp_disable_writes"] is False
    assert loaded["mcp_text_extensions"] == []
    assert loaded["mcp_global_max_read_bytes"] == 10_485_760


def test_default_config_includes_big_bucket_mcp_fields():
    """The four summary/list-paging keys ship in the default config template."""
    from another_s3_manager.config import _get_default_config

    cfg = _get_default_config()
    assert cfg["mcp_summary_max_keys"] == 50_000
    assert cfg["mcp_summary_prefix_scan_pages"] == 20
    assert cfg["mcp_list_page_size"] == 1000
    assert cfg["mcp_list_max_page_size"] == 10_000


def test_migrate_config_adds_big_bucket_mcp_fields(monkeypatch, tmp_path):
    """A legacy config.json without the summary/list-paging keys gets them backfilled on load."""
    from another_s3_manager import config as config_module

    legacy = tmp_path / "config.json"
    legacy.write_text(json.dumps({"roles": [], "mcp_enabled": True}))
    monkeypatch.setattr(config_module, "CONFIG_FILE", legacy)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    loaded = config_module.load_config(force_reload=True)
    assert loaded["mcp_summary_max_keys"] == 50_000
    assert loaded["mcp_summary_prefix_scan_pages"] == 20
    assert loaded["mcp_list_page_size"] == 1000


# ---------------------------------------------------------------------------
# Concurrency: _config_cache reload must be atomic (R001 moved every request
# onto a worker-thread pool, so a reader hitting load_config() mid-reload is
# now a real scenario, not a theoretical one).
# ---------------------------------------------------------------------------


def test_load_config_reload_never_exposes_partially_migrated_dict(monkeypatch, tmp_path):
    """No reader may ever observe a config dict that's missing a migration-added key.

    Real concurrency, not a mock: a legacy config.json (missing `mcp_enabled`,
    a migration-added key) is force-reloaded on the main thread while several
    reader threads busy-poll `_config_cache` throughout. `_migrate_config` is
    wrapped to sleep AFTER it finishes migrating (widening the race window
    well past a few dict-key assignments) so readers get real scheduler time
    during exactly the window that used to be unsafe.

    This discriminates for real: the pre-fix code did
    `_config_cache = json.load(f)` (rebinding to the RAW dict) BEFORE calling
    `_migrate_config`, so during that window (including the injected sleep,
    since it wraps _migrate_config and therefore runs after the old rebind
    already happened) a reader's `_config_cache` snapshot was the raw,
    unmigrated dict — `"mcp_enabled" in snapshot` would be False. The fixed
    code builds the fully-migrated dict in a LOCAL variable and only rebinds
    `_config_cache` once, at the very end, so a reader here only ever sees
    the OLD complete dict (falsy/empty before the reload starts, since the
    test starts from `_config_cache = {}`) or the NEW complete one — never a
    dict bound mid-migration. Verified by temporarily reverting the
    load_config fix and observing this test fail.
    """
    from another_s3_manager import config as config_module

    legacy = tmp_path / "config.json"
    # Deliberately missing "mcp_enabled" and friends — the migration must add them.
    legacy.write_text(json.dumps({"roles": []}))
    monkeypatch.setattr(config_module, "CONFIG_FILE", legacy)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    orig_migrate_config = config_module._migrate_config

    def slow_migrate_config(cfg):
        result = orig_migrate_config(cfg)
        # Widen the race window between "migration finished on the local
        # dict" and "the reload path decides what to publish" — this is
        # exactly the window that was unsafe pre-fix.
        time.sleep(0.1)
        return result

    monkeypatch.setattr(config_module, "_migrate_config", slow_migrate_config)

    observations: list = []
    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            snapshot = config_module._config_cache
            if snapshot:
                observations.append("mcp_enabled" in snapshot)

    readers = [threading.Thread(target=reader) for _ in range(8)]
    for t in readers:
        t.start()

    try:
        loaded = config_module.load_config(force_reload=True)
    finally:
        stop.set()
        for t in readers:
            t.join(timeout=5)

    assert "mcp_enabled" in loaded
    assert observations, "reader threads never observed a populated cache — widen the race window"
    assert all(observations), "a reader observed a config dict missing a migration-added key mid-reload"
    assert loaded["mcp_list_max_page_size"] == 10_000
