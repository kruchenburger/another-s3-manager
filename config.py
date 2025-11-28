"""
Configuration management module
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from constants import CONFIG_FILE
except ImportError:
    # Fallback for direct execution
    CONFIG_FILE = Path(__file__).parent / "config.json"


# Global cache for configuration
_config_cache: Dict[str, Any] = {}
_config_mtime: float = 0
_migrating: bool = False  # Flag to prevent recursive migration


def load_config(force_reload: bool = False) -> Dict[str, Any]:
    """
    Load configuration from file with caching.
    """
    global _config_cache, _config_mtime

    if CONFIG_FILE.exists():
        current_mtime = CONFIG_FILE.stat().st_mtime
        if force_reload or current_mtime > _config_mtime or not _config_cache:
            # Load main config file
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                _config_cache = json.load(f)
            _config_mtime = current_mtime

            # Migrate config: add missing fields if they don't exist
            # Prevent recursive migration calls
            global _migrating
            if not _migrating:
                _migrating = True
                try:
                    if _migrate_config():
                        # Try to save migrated config, but skip if file is read-only
                        # Use internal function to avoid recursion if save_config is wrapped
                        try:
                            _save_config_internal(_config_cache, skip_migration=True)
                            # Update mtime after save to prevent reload
                            if CONFIG_FILE.exists():
                                _config_mtime = CONFIG_FILE.stat().st_mtime
                        except PermissionError:
                            # Config file is read-only, migration applied in memory only
                            pass
                finally:
                    _migrating = False

            return _config_cache
        return _config_cache

    # Default config if file doesn't exist
    default_config = _get_default_config()
    if not _config_cache:
        _config_cache = default_config
    return _config_cache


def _migrate_config() -> bool:
    """Migrate config by adding missing fields with default values."""
    global _config_cache
    config_modified = False

    if "enable_lazy_loading" not in _config_cache:
        _config_cache["enable_lazy_loading"] = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"
        config_modified = True
    if "max_file_size" not in _config_cache:
        _config_cache["max_file_size"] = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
        config_modified = True
    if "auto_inline_extensions" not in _config_cache:
        _config_cache["auto_inline_extensions"] = []
        config_modified = True
    # Note: data_dir is not migrated automatically - it should be set explicitly if needed
    # Note: default_role is optional and not migrated automatically - it should be set explicitly if needed

    return config_modified


def _get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    from constants import DEFAULT_ITEMS_PER_PAGE, DEFAULT_MAX_FILE_SIZE

    return {
        "roles": [{"name": "Default", "type": "default", "description": "Use default AWS credentials"}],
        "items_per_page": int(os.getenv("ITEMS_PER_PAGE", str(DEFAULT_ITEMS_PER_PAGE))),
        "enable_lazy_loading": os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true",
        "max_file_size": int(os.getenv("MAX_FILE_SIZE", str(DEFAULT_MAX_FILE_SIZE))),
        "disable_deletion": False,
        "auto_inline_extensions": []
    }


def is_config_writable() -> bool:
    """
    Check if config file is writable (not read-only).

    Returns:
        True if config file can be written, False otherwise
    """
    if not CONFIG_FILE.exists():
        # If file doesn't exist, check if parent directory is writable
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            test_file = CONFIG_FILE.parent / ".write_test"
            return _can_write_test_file(test_file)
        except (OSError, PermissionError):
            return False

    # Check if file is writable
    try:
        # Try to open file in append mode (doesn't modify content but checks write permission)
        with open(CONFIG_FILE, 'a', encoding='utf-8'):
            pass
        return True
    except (OSError, PermissionError):
        return False


# Store original save_config for internal use (before it might be wrapped)
def _save_config_internal(config: Dict[str, Any], skip_migration: bool = False) -> None:
    """
    Internal save_config implementation (used to avoid recursion when wrapped).
    """
    global _config_cache, _config_mtime

    # Check if config is writable before attempting to save
    if not is_config_writable():
        raise PermissionError("Configuration file is read-only. Cannot save changes.")

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    _config_cache = config
    if CONFIG_FILE.exists():
        _config_mtime = CONFIG_FILE.stat().st_mtime


def save_config(config: Dict[str, Any], skip_migration: bool = False) -> None:
    """
    Save configuration to file.

    Args:
        config: Configuration dictionary to save
        skip_migration: If True, skip migration check (used internally to prevent recursion)

    Raises:
        PermissionError: If config file is read-only
    """
    _save_config_internal(config, skip_migration=skip_migration)


def get_config_value(key: str, default: Any = None, env_var: Optional[str] = None) -> Any:
    """
    Get a configuration value with fallback to environment variable and default.

    Args:
        key: Configuration key
        default: Default value if not found
        env_var: Environment variable name to check if config value is None

    Returns:
        Configuration value
    """
    config = load_config(force_reload=False)
    value = config.get(key)

    if value is None and env_var:
        env_value = os.getenv(env_var)
        if env_value is not None:
            # Try to convert to appropriate type
            if isinstance(default, bool):
                return env_value.lower() == "true"
            elif isinstance(default, int):
                try:
                    return int(env_value)
                except ValueError:
                    return default
            return env_value

    return value if value is not None else default


def _can_write_test_file(test_file: Path) -> bool:
    """Try to write and remove a temporary test file."""
    try:
        test_file.write_text("test")
        test_file.unlink()
        return True
    except (OSError, PermissionError):
        return False

