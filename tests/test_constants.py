import importlib
import os
from pathlib import Path

import pytest


def reload_constants():
    import constants

    importlib.reload(constants)
    return constants


def test_get_data_dir_uses_environment_variable():
    constants = reload_constants()
    expected = Path(os.environ["DATA_DIR"])
    result = constants.get_data_dir()
    assert result == expected
    assert result.exists()


def test_get_data_dir_falls_back_to_config(monkeypatch, tmp_path):
    monkeypatch.delenv("DATA_DIR", raising=False)

    import config as config_module

    config_data = config_module.load_config(force_reload=True)
    custom_dir = tmp_path / "custom-data"
    config_data["data_dir"] = str(custom_dir)
    config_module.save_config(config_data)

    constants = reload_constants()
    result = constants.get_data_dir()
    assert result == custom_dir
    assert result.exists()


def test_get_data_dir_defaults_to_base_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("DATA_DIR", raising=False)

    import config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data.pop("data_dir", None)
    config_module.save_config(config_data)

    constants = reload_constants()
    result = constants.get_data_dir()
    assert result == constants.BASE_DIR
    assert result.exists()


def test_get_users_file(monkeypatch, tmp_path):
    custom_data = tmp_path / "users-data"
    custom_data.mkdir()
    monkeypatch.setenv("DATA_DIR", str(custom_data))

    constants = reload_constants()
    users_file = constants.get_users_file()
    assert users_file == custom_data / "users.json"


def test_get_bans_file(monkeypatch, tmp_path):
    custom_data = tmp_path / "bans-data"
    custom_data.mkdir()
    monkeypatch.setenv("DATA_DIR", str(custom_data))

    constants = reload_constants()
    bans_file = constants.get_bans_file()
    assert bans_file == custom_data / "bans.json"


def test_get_data_dir_handles_load_config_error(monkeypatch):
    constants = reload_constants()
    import config as config_module

    def boom(*args, **kwargs):
        raise RuntimeError("load_config failed")

    monkeypatch.setattr(config_module, "load_config", boom)
    monkeypatch.delenv("DATA_DIR", raising=False)
    result = constants.get_data_dir()
    assert result == constants.BASE_DIR


def test_invalid_jwt_expire_env_resets_to_default(monkeypatch):
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "not-a-number")
    constants = importlib.reload(importlib.import_module("constants"))
    try:
        assert constants.ACCESS_TOKEN_EXPIRE_MINUTES == constants.DEFAULT_JWT_EXPIRE_MINUTES
    finally:
        monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
        importlib.reload(constants)


def test_jwt_expire_minimum_enforced(monkeypatch):
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "0")
    module = importlib.reload(importlib.import_module("constants"))
    try:
        assert module.ACCESS_TOKEN_EXPIRE_MINUTES == module.DEFAULT_JWT_EXPIRE_MINUTES
    finally:
        monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
        importlib.reload(module)


def test_app_version_prefers_env(monkeypatch):
    import constants as constants_module

    monkeypatch.setenv("APP_VERSION", "9.9.9")
    reloaded = importlib.reload(constants_module)
    try:
        assert reloaded.APP_VERSION == "9.9.9"
    finally:
        monkeypatch.delenv("APP_VERSION", raising=False)
        importlib.reload(constants_module)


def test_app_version_from_pyproject(monkeypatch):
    import constants as constants_module

    monkeypatch.delenv("APP_VERSION", raising=False)
    if constants_module.tomllib is None:
        pytest.skip("tomllib not available")
    version = constants_module._read_version_from_pyproject()
    assert version is not None
    assert version.count('.') >= 1


def test_app_version_without_tomllib(monkeypatch):
    import constants as constants_module

    monkeypatch.setattr(constants_module, "tomllib", None)
    assert constants_module._read_version_from_pyproject() is None
    importlib.reload(constants_module)


def test_app_version_default_fallback(monkeypatch):
    import constants as constants_module

    monkeypatch.delenv("APP_VERSION", raising=False)
    monkeypatch.setattr(constants_module, "APP_VERSION", None, raising=False)
    monkeypatch.setattr(constants_module, "_read_version_from_pyproject", lambda: None, raising=False)
    exec(
        "if not APP_VERSION:\n    APP_VERSION = _read_version_from_pyproject()\nif not APP_VERSION:\n    APP_VERSION = '0.1.0'",
        constants_module.__dict__,
    )
    assert constants_module.APP_VERSION == "0.1.0"
    importlib.reload(constants_module)


def test_read_version_from_parent_pyproject(monkeypatch, tmp_path):
    import constants as constants_module

    if constants_module.tomllib is None:
        pytest.skip("tomllib not available")

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "3.2.1"\n', encoding="utf-8")

    monkeypatch.setattr(constants_module, "BASE_DIR", app_dir, raising=False)
    version = constants_module._read_version_from_pyproject()
    assert version == "3.2.1"


def test_read_version_missing_pyproject(monkeypatch, tmp_path):
    import constants as constants_module

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    monkeypatch.setattr(constants_module, "BASE_DIR", app_dir, raising=False)
    assert constants_module._read_version_from_pyproject() is None