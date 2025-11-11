import builtins
import importlib
import json
import os
from pathlib import Path

import pytest


def reload_config():
    import config

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


def test_get_default_config_respects_env(monkeypatch):
    monkeypatch.setenv("ITEMS_PER_PAGE", "50")
    monkeypatch.setenv("MAX_FILE_SIZE", str(10 * 1024 * 1024))

    config = reload_config()
    defaults = config._get_default_config()
    assert defaults["items_per_page"] == 50
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

    monkeypatch.setattr("config.is_config_writable", lambda: False)
    with pytest.raises(PermissionError):
        config.save_config({"sample": "value"})


def test_get_config_value_returns_value():
    config = reload_config()
    data = config.load_config(force_reload=True)
    data["items_per_page"] = 123
    config.save_config(data)

    value = config.get_config_value("items_per_page", default=50)
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


def test_config_import_fallback_when_constants_missing(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "constants":
            raise ImportError("mock")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("config"))
    try:
        expected = Path(module.__file__).parent / "config.json"
        assert module.CONFIG_FILE == expected
    finally:
        importlib.reload(module)


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
