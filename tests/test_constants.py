import importlib
import os
from pathlib import Path


def reload_constants():
    import another_s3_manager.constants as constants

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

    import another_s3_manager.config as config_module

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

    import another_s3_manager.config as config_module

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
    import another_s3_manager.config as config_module

    def boom(*args, **kwargs):
        raise RuntimeError("load_config failed")

    monkeypatch.setattr(config_module, "load_config", boom)
    monkeypatch.delenv("DATA_DIR", raising=False)
    result = constants.get_data_dir()
    assert result == constants.BASE_DIR


def test_invalid_jwt_expire_env_resets_to_default(monkeypatch):
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "not-a-number")
    constants = importlib.reload(importlib.import_module("another_s3_manager.constants"))
    try:
        assert constants.ACCESS_TOKEN_EXPIRE_MINUTES == constants.DEFAULT_JWT_EXPIRE_MINUTES
    finally:
        monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
        importlib.reload(constants)


def test_jwt_expire_minimum_enforced(monkeypatch):
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "0")
    module = importlib.reload(importlib.import_module("another_s3_manager.constants"))
    try:
        assert module.ACCESS_TOKEN_EXPIRE_MINUTES == module.DEFAULT_JWT_EXPIRE_MINUTES
    finally:
        monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
        importlib.reload(module)


def test_app_version_prefers_env(monkeypatch):
    import another_s3_manager.constants as constants_module

    monkeypatch.setenv("APP_VERSION", "9.9.9")
    reloaded = importlib.reload(constants_module)
    try:
        assert reloaded.APP_VERSION == "9.9.9"
    finally:
        monkeypatch.delenv("APP_VERSION", raising=False)
        importlib.reload(constants_module)


def test_app_version_defaults_to_dev(monkeypatch):
    import another_s3_manager.constants as constants_module

    monkeypatch.delenv("APP_VERSION", raising=False)
    reloaded = importlib.reload(constants_module)
    try:
        assert reloaded.APP_VERSION == "dev"
    finally:
        importlib.reload(constants_module)


def test_get_db_path_uses_data_dir(monkeypatch, tmp_path):
    """get_db_path() returns <DATA_DIR>/another_s3_manager.db."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import importlib

    from another_s3_manager import constants

    importlib.reload(constants)
    assert constants.get_db_path() == tmp_path / "another_s3_manager.db"


def test_get_db_path_creates_data_dir_if_missing(monkeypatch, tmp_path):
    """get_db_path() ensures the parent directory exists."""
    db_dir = tmp_path / "newly-created"
    assert not db_dir.exists()
    monkeypatch.setenv("DATA_DIR", str(db_dir))
    import importlib

    from another_s3_manager import constants

    importlib.reload(constants)
    constants.get_db_path()
    assert db_dir.exists()


def test_cookie_secure_defaults_to_true(monkeypatch):
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    import importlib
    from another_s3_manager import constants
    importlib.reload(constants)
    assert constants.COOKIE_SECURE is True


def test_cookie_secure_respects_env_false(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "false")
    import importlib
    from another_s3_manager import constants
    importlib.reload(constants)
    assert constants.COOKIE_SECURE is False


def test_cookie_secure_case_insensitive(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "FALSE")
    import importlib
    from another_s3_manager import constants
    importlib.reload(constants)
    assert constants.COOKIE_SECURE is False
