"""
Configuration management module
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from another_s3_manager.constants import CONFIG_FILE

logger = logging.getLogger(__name__)

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
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
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
    if "max_client_load" not in _config_cache:
        _config_cache["max_client_load"] = int(os.getenv("MAX_CLIENT_LOAD", "10000"))
        config_modified = True
    # auto_inline_extensions: the /v2 preview UI treats this list as the single
    # source of truth for which files preview inline as text. Seed it with the
    # built-in text defaults the FIRST time a config is migrated — this covers
    # fresh installs and legacy configs whose field was an inert []. The one-time
    # `_auto_inline_seeded` marker (preserved across saves in update_config) means
    # we never re-seed, so an admin who deliberately clears the list to [] keeps
    # it empty.
    if not _config_cache.get("_auto_inline_seeded"):
        from another_s3_manager.constants import DEFAULT_AUTO_INLINE_EXTENSIONS

        if not _config_cache.get("auto_inline_extensions"):
            _config_cache["auto_inline_extensions"] = list(DEFAULT_AUTO_INLINE_EXTENSIONS)
        _config_cache["_auto_inline_seeded"] = True
        config_modified = True
    # Password policy defaults — added Phase 4d. Conservative baseline:
    # require length+uppercase+lowercase+digit, leave special opt-in.
    if "password_min_length" not in _config_cache:
        _config_cache["password_min_length"] = 8
        config_modified = True
    if "password_min_uppercase" not in _config_cache:
        _config_cache["password_min_uppercase"] = 1
        config_modified = True
    if "password_min_lowercase" not in _config_cache:
        _config_cache["password_min_lowercase"] = 1
        config_modified = True
    if "password_min_digits" not in _config_cache:
        _config_cache["password_min_digits"] = 1
        config_modified = True
    if "password_min_special" not in _config_cache:
        _config_cache["password_min_special"] = 0
        config_modified = True
    # MCP server defaults — added Phase 5
    if "mcp_enabled" not in _config_cache:
        _config_cache["mcp_enabled"] = True
        config_modified = True
    if "mcp_disable_writes" not in _config_cache:
        _config_cache["mcp_disable_writes"] = False
        config_modified = True
    if "mcp_text_extensions" not in _config_cache:
        _config_cache["mcp_text_extensions"] = []
        config_modified = True
    if "mcp_global_max_read_bytes" not in _config_cache:
        _config_cache["mcp_global_max_read_bytes"] = 10_485_760
        config_modified = True
    if "presigned_url_default_ttl" not in _config_cache or "presigned_url_max_ttl" not in _config_cache:
        from another_s3_manager.constants import DEFAULT_PRESIGNED_URL_DEFAULT_TTL, DEFAULT_PRESIGNED_URL_MAX_TTL

        if "presigned_url_default_ttl" not in _config_cache:
            _config_cache["presigned_url_default_ttl"] = int(
                os.getenv("PRESIGNED_URL_DEFAULT_TTL", str(DEFAULT_PRESIGNED_URL_DEFAULT_TTL))
            )
            config_modified = True
        if "presigned_url_max_ttl" not in _config_cache:
            _config_cache["presigned_url_max_ttl"] = int(
                os.getenv("PRESIGNED_URL_MAX_TTL", str(DEFAULT_PRESIGNED_URL_MAX_TTL))
            )
            config_modified = True
    # Note: data_dir is not migrated automatically - it should be set explicitly if needed
    # Note: default_role is optional and not migrated automatically - it should be set explicitly if needed

    return config_modified


def _get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    from another_s3_manager.constants import (
        DEFAULT_AUTO_INLINE_EXTENSIONS,
        DEFAULT_MAX_CLIENT_LOAD,
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_PRESIGNED_URL_DEFAULT_TTL,
        DEFAULT_PRESIGNED_URL_MAX_TTL,
    )

    return {
        "roles": [{"name": "Default", "type": "default", "description": "Use default AWS credentials"}],
        "enable_lazy_loading": os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true",
        "max_file_size": int(os.getenv("MAX_FILE_SIZE", str(DEFAULT_MAX_FILE_SIZE))),
        "max_client_load": int(os.getenv("MAX_CLIENT_LOAD", str(DEFAULT_MAX_CLIENT_LOAD))),
        "disable_deletion": False,
        # Seeded with the text defaults; admin-owned thereafter (see migration).
        "auto_inline_extensions": list(DEFAULT_AUTO_INLINE_EXTENSIONS),
        "_auto_inline_seeded": True,
        "password_min_length": 8,
        "password_min_uppercase": 1,
        "password_min_lowercase": 1,
        "password_min_digits": 1,
        "password_min_special": 0,
        "mcp_enabled": True,
        "mcp_disable_writes": False,
        "mcp_text_extensions": [],
        "mcp_global_max_read_bytes": 10_485_760,
        "presigned_url_default_ttl": int(
            os.getenv("PRESIGNED_URL_DEFAULT_TTL", str(DEFAULT_PRESIGNED_URL_DEFAULT_TTL))
        ),
        "presigned_url_max_ttl": int(os.getenv("PRESIGNED_URL_MAX_TTL", str(DEFAULT_PRESIGNED_URL_MAX_TTL))),
    }


def resolve_presigned_ttls(config: Dict[str, Any]) -> tuple[int, int]:
    """Resolve (default_ttl, max_ttl) for presigned URLs in seconds.

    Resolution order per field: config value → env var → hardcoded default.
    `max_ttl` is clamped to the 7-day SigV4 ceiling. If a hand-edited config
    has default > max, the effective default is min(default, max) (logged).
    Garbage values fall back to the hardcoded defaults.
    """
    from another_s3_manager.constants import (
        DEFAULT_PRESIGNED_URL_DEFAULT_TTL,
        DEFAULT_PRESIGNED_URL_MAX_TTL,
        PRESIGNED_URL_HARD_CEILING,
    )

    def _coerce(value: Any, env_name: str, fallback: int) -> int:
        if value is None:
            value = os.getenv(env_name)
        if value is None:
            return fallback
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning("Invalid %s value %r — using default %d", env_name, value, fallback)
            return fallback

    max_ttl = _coerce(
        config.get("presigned_url_max_ttl"),
        "PRESIGNED_URL_MAX_TTL",
        DEFAULT_PRESIGNED_URL_MAX_TTL,
    )
    if max_ttl > PRESIGNED_URL_HARD_CEILING:
        logger.warning(
            "presigned_url_max_ttl %d exceeds the 7-day ceiling — clamping to %d",
            max_ttl,
            PRESIGNED_URL_HARD_CEILING,
        )
        max_ttl = PRESIGNED_URL_HARD_CEILING

    default_ttl = _coerce(
        config.get("presigned_url_default_ttl"),
        "PRESIGNED_URL_DEFAULT_TTL",
        DEFAULT_PRESIGNED_URL_DEFAULT_TTL,
    )
    if default_ttl > max_ttl:
        logger.warning(
            "presigned_url_default_ttl %d exceeds max %d — using max as the effective default",
            default_ttl,
            max_ttl,
        )
        default_ttl = max_ttl

    return default_ttl, max_ttl


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
        with open(CONFIG_FILE, "a", encoding="utf-8"):
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

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
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
