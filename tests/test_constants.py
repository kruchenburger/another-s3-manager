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
    monkeypatch.delenv("S3_FILE_MANAGER_CONFIG", raising=False)

    constants = reload_constants()
    result = constants.get_data_dir()
    assert result == constants.BASE_DIR
    assert result.exists()


def test_get_data_dir_follows_explicit_config_location(monkeypatch, tmp_path):
    # ASM-67: the image sets only S3_FILE_MANAGER_CONFIG; the DB must live beside it.
    monkeypatch.delenv("DATA_DIR", raising=False)
    cfg_dir = tmp_path / "mounted"
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_dir / "config.json"))
    constants = reload_constants()
    monkeypatch.setattr("another_s3_manager.config.load_config", lambda force_reload=False: {})
    assert constants.get_data_dir() == cfg_dir
    assert cfg_dir.is_dir()


def test_config_data_dir_still_wins_over_config_location(monkeypatch, tmp_path):
    # A ConfigMap-mounted config with "data_dir" pointing at a PVC keeps working.
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(tmp_path / "etc" / "config.json"))
    constants = reload_constants()
    pvc = tmp_path / "pvc"
    monkeypatch.setattr("another_s3_manager.config.load_config", lambda force_reload=False: {"data_dir": str(pvc)})
    assert constants.get_data_dir() == pvc


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
    # Without an explicit config location the fallback is the package dir.
    monkeypatch.delenv("S3_FILE_MANAGER_CONFIG", raising=False)
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


# --- ASM-67: legacy config.json fallback -------------------------------------


def _resolve(monkeypatch, tmp_path, *, new: bool, legacy: bool):
    constants = reload_constants()
    new_path = tmp_path / "data" / "config.json"
    legacy_path = tmp_path / "pkg" / "config.json"
    for path, present in ((new_path, new), (legacy_path, legacy)):
        if present:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(new_path))
    monkeypatch.setattr(constants, "LEGACY_CONFIG_FILE", legacy_path)
    return constants, constants._resolve_config_file(), new_path, legacy_path


def test_config_new_path_only(monkeypatch, tmp_path):
    _, chosen, new_path, _ = _resolve(monkeypatch, tmp_path, new=True, legacy=False)
    assert chosen == new_path


def test_config_legacy_only_falls_back(monkeypatch, tmp_path):
    _, chosen, _, legacy_path = _resolve(monkeypatch, tmp_path, new=False, legacy=True)
    assert chosen == legacy_path


def test_config_both_new_wins(monkeypatch, tmp_path):
    _, chosen, new_path, _ = _resolve(monkeypatch, tmp_path, new=True, legacy=True)
    assert chosen == new_path


def test_config_neither_uses_new_path(monkeypatch, tmp_path):
    _, chosen, new_path, _ = _resolve(monkeypatch, tmp_path, new=False, legacy=False)
    assert chosen == new_path


def test_legacy_config_warning_names_both_paths(monkeypatch, tmp_path, caplog):
    import logging

    constants, chosen, new_path, legacy_path = _resolve(monkeypatch, tmp_path, new=False, legacy=True)
    monkeypatch.setattr(constants, "CONFIG_FILE", chosen)
    from another_s3_manager import main

    logger = logging.getLogger("another_s3_manager.main")
    monkeypatch.setattr(logger, "disabled", False)
    with caplog.at_level(logging.WARNING, logger="another_s3_manager.main"):
        logger.addHandler(caplog.handler)
        try:
            main._warn_legacy_config_location()
        finally:
            logger.removeHandler(caplog.handler)
    assert str(new_path) in caplog.text and str(legacy_path) in caplog.text


def test_no_legacy_warning_on_new_path(monkeypatch, tmp_path):
    constants, chosen, _, _ = _resolve(monkeypatch, tmp_path, new=True, legacy=True)
    monkeypatch.setattr(constants, "CONFIG_FILE", chosen)
    assert constants.legacy_config_in_use() is False


def test_legacy_fallback_keeps_data_next_to_configured_path(monkeypatch, tmp_path):
    # Review: with the legacy config in use the DB must not go to the root-owned package dir.
    monkeypatch.delenv("DATA_DIR", raising=False)
    constants, chosen, new_path, legacy_path = _resolve(monkeypatch, tmp_path, new=False, legacy=True)
    monkeypatch.setattr(constants, "CONFIG_FILE", chosen)
    monkeypatch.setattr("another_s3_manager.config.load_config", lambda force_reload=False: {})
    assert chosen == legacy_path
    assert constants.get_data_dir() == new_path.parent


def test_read_only_config_dir_falls_back_to_image_data_dir(monkeypatch, tmp_path, caplog):
    # Review: a ConfigMap dir is read-only; without DATA_DIR the DB goes to the image's /app/data.
    monkeypatch.delenv("DATA_DIR", raising=False)
    ro_dir = tmp_path / "etc"
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(ro_dir / "config.json"))
    constants = reload_constants()
    image_dir = tmp_path / "image-data"
    monkeypatch.setattr(constants, "IMAGE_DATA_DIR", image_dir)
    real_usable = constants._usable_dir
    monkeypatch.setattr(constants, "_usable_dir", lambda p: p != ro_dir and real_usable(p))
    monkeypatch.setattr("another_s3_manager.config.load_config", lambda force_reload=False: {})
    assert constants.get_data_dir() == image_dir
