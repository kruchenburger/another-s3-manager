"""
Configuration management module
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from another_s3_manager.constants import CONFIG_FILE

logger = logging.getLogger(__name__)

# Global cache for configuration
_config_cache: Dict[str, Any] = {}
_config_mtime: float = 0
_migrating: bool = False  # Flag to prevent recursive migration

# Serializes the reload path (read file + migrate + persist) across threads.
# R001 moved every request onto a worker-thread pool, so concurrent reloads
# are now real: without this, two threads could both read the file, both
# migrate their own copy, and both write config.json back-to-back. The lock
# does not protect plain reads of `_config_cache` below (those stay lock-free
# and rely on the atomic-rebind argument documented in load_config).
_config_lock = threading.Lock()


def load_config(force_reload: bool = False) -> Dict[str, Any]:
    """
    Load configuration from file with caching.

    Concurrency: the reload branch (file read + migrate + persist) is
    serialized by `_config_lock` so two threads never race each other's
    reads/writes of config.json. The published cache itself is swapped with a
    single `_config_cache = new_config` assignment — atomic under the GIL —
    only AFTER the freshly-loaded dict has been fully migrated. A concurrent
    reader hitting the `return _config_cache` fast path therefore only ever
    observes the OLD fully-migrated dict or the NEW fully-migrated dict, never
    a dict rebound to the raw JSON before migration filled in missing keys.
    """
    global _config_cache, _config_mtime

    if not CONFIG_FILE.exists():
        # Default config if file doesn't exist
        default_config = _get_default_config()
        if not _config_cache:
            _config_cache = default_config
        return _config_cache

    current_mtime = CONFIG_FILE.stat().st_mtime
    if not (force_reload or current_mtime > _config_mtime or not _config_cache):
        return _config_cache

    with _config_lock:
        # Double-checked locking: another thread may have completed the
        # reload (and the migration + persist that comes with it) while this
        # thread was waiting for the lock — re-check before doing it again.
        current_mtime = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else current_mtime
        if not (force_reload or current_mtime > _config_mtime or not _config_cache):
            return _config_cache

        # Load main config file into a LOCAL variable — NOT the module cache —
        # so migration completes before anything becomes visible to readers.
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            new_config = json.load(f)

        # Migrate config: add missing fields if they don't exist.
        # Prevent recursive migration calls.
        global _migrating
        if not _migrating:
            _migrating = True
            try:
                if _migrate_config(new_config):
                    # Try to save migrated config, but skip if file is read-only.
                    # Use internal function to avoid recursion if save_config is wrapped.
                    try:
                        _save_config_internal(new_config, skip_migration=True)
                        # _save_config_internal already performs the atomic
                        # rebind of _config_cache/_config_mtime — nothing left
                        # to do here.
                        return _config_cache
                    except PermissionError:
                        # Config file is read-only, migration applied in memory only.
                        pass
            finally:
                _migrating = False

        # Atomic publish: a bare attribute rebind is a single bytecode op
        # under the GIL, so this is the moment concurrent readers flip from
        # seeing the old complete dict to the new complete (already-migrated)
        # one — there is no half-built state for them to observe.
        _config_cache = new_config
        _config_mtime = current_mtime
        return _config_cache


def resolve_max_file_size(config: Optional[Dict[str, Any]] = None) -> int:
    """Resolve the upload size limit in bytes — the single source of truth.

    Precedence: admin-editable config `max_file_size` -> `MAX_FILE_SIZE` env
    var -> 100 MB default. Shared by main.py's upload body-guard middleware,
    the web upload route handler, and mcp_server.py's upload_file tool, so
    all three enforcement points can never drift from each other (see
    backlog finding: the two resolvers used to be hand-copied and could
    silently diverge).

    `config` may be passed in by a caller that already loaded it this
    request (e.g. mcp_server.py's upload_file, which needs the config dict
    for assert_write_allowed anyway) to avoid a redundant load_config call.
    Defaults to loading it fresh when omitted.
    """
    if config is None:
        config = load_config(force_reload=False)
    max_file_size = config.get("max_file_size")
    if max_file_size is None:
        return int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    return int(max_file_size)


def _migrate_config(config: Dict[str, Any]) -> bool:
    """Migrate `config` in place by adding missing fields with default values.

    Takes the dict to migrate as an explicit argument (rather than reaching
    for the module-level `_config_cache`) so callers can migrate a LOCAL,
    not-yet-published dict to completion before ever exposing it as
    `_config_cache` — see load_config's atomic-rebind comment for why that
    matters under concurrent readers.
    """
    config_modified = False

    if "enable_lazy_loading" not in config:
        config["enable_lazy_loading"] = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"
        config_modified = True
    if "max_file_size" not in config:
        config["max_file_size"] = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
        config_modified = True
    if "max_client_load" not in config:
        config["max_client_load"] = int(os.getenv("MAX_CLIENT_LOAD", "10000"))
        config_modified = True
    # Split the legacy `auto_inline_extensions` key (which conflated two unrelated
    # features) into two:
    #   - preview_text_extensions: which TEXT files preview inline in the web UI
    #   - upload_inline_extensions: which uploads get Content-Disposition: inline
    #     (so they open in the browser when served via CDN / presigned URL)
    # Presence of `preview_text_extensions` is the "already migrated" marker, so
    # an admin who clears either list to [] keeps it empty (no re-seed).
    if "preview_text_extensions" not in config:
        from another_s3_manager.constants import (
            DEFAULT_PREVIEW_TEXT_EXTENSIONS,
            DEFAULT_UPLOAD_INLINE_EXTENSIONS,
        )

        legacy = config.get("auto_inline_extensions")
        legacy_list = list(legacy) if isinstance(legacy, list) else None
        # Preserve the current preview behavior verbatim; fall back to the text
        # defaults for fresh installs / configs that never had the key.
        config["preview_text_extensions"] = (
            legacy_list if legacy_list is not None else list(DEFAULT_PREVIEW_TEXT_EXTENSIONS)
        )
        # Upload-inline: preserve every extension the legacy list already made
        # inline (zero regression for admins who customized it) AND union in the
        # pdf+images defaults, so browser-open PDFs are restored even when the
        # legacy list was the text-only re-seed. Fresh installs get just the
        # defaults.
        if "upload_inline_extensions" not in config:
            if legacy_list is not None:
                config["upload_inline_extensions"] = legacy_list + [
                    e for e in DEFAULT_UPLOAD_INLINE_EXTENSIONS if e not in legacy_list
                ]
            else:
                config["upload_inline_extensions"] = list(DEFAULT_UPLOAD_INLINE_EXTENSIONS)
        # Drop the obsolete legacy keys so config.json stops carrying them.
        config.pop("auto_inline_extensions", None)
        config.pop("_auto_inline_seeded", None)
        config_modified = True
    # Password policy defaults — added Phase 4d. Conservative baseline:
    # require length+uppercase+lowercase+digit, leave special opt-in.
    if "password_min_length" not in config:
        config["password_min_length"] = 8
        config_modified = True
    if "password_min_uppercase" not in config:
        config["password_min_uppercase"] = 1
        config_modified = True
    if "password_min_lowercase" not in config:
        config["password_min_lowercase"] = 1
        config_modified = True
    if "password_min_digits" not in config:
        config["password_min_digits"] = 1
        config_modified = True
    if "password_min_special" not in config:
        config["password_min_special"] = 0
        config_modified = True
    # MCP server defaults — added Phase 5
    if "mcp_enabled" not in config:
        config["mcp_enabled"] = True
        config_modified = True
    if "mcp_disable_writes" not in config:
        config["mcp_disable_writes"] = False
        config_modified = True
    if "mcp_text_extensions" not in config:
        config["mcp_text_extensions"] = []
        config_modified = True
    if "mcp_global_max_read_bytes" not in config:
        config["mcp_global_max_read_bytes"] = 10_485_760
        config_modified = True
    # MCP big-bucket ergonomics — added 2026-07-12.
    if "mcp_summary_max_keys" not in config:
        config["mcp_summary_max_keys"] = 50_000
        config_modified = True
    if "mcp_summary_prefix_scan_pages" not in config:
        config["mcp_summary_prefix_scan_pages"] = 20
        config_modified = True
    if "mcp_list_page_size" not in config:
        config["mcp_list_page_size"] = 1000
        config_modified = True
    if "mcp_list_max_page_size" not in config:
        config["mcp_list_max_page_size"] = 10_000
        config_modified = True
    if "presigned_url_default_ttl" not in config or "presigned_url_max_ttl" not in config:
        from another_s3_manager.constants import DEFAULT_PRESIGNED_URL_DEFAULT_TTL, DEFAULT_PRESIGNED_URL_MAX_TTL

        if "presigned_url_default_ttl" not in config:
            config["presigned_url_default_ttl"] = int(
                os.getenv("PRESIGNED_URL_DEFAULT_TTL", str(DEFAULT_PRESIGNED_URL_DEFAULT_TTL))
            )
            config_modified = True
        if "presigned_url_max_ttl" not in config:
            config["presigned_url_max_ttl"] = int(
                os.getenv("PRESIGNED_URL_MAX_TTL", str(DEFAULT_PRESIGNED_URL_MAX_TTL))
            )
            config_modified = True
    # Note: data_dir is not migrated automatically - it should be set explicitly if needed
    # Note: default_role is optional and not migrated automatically - it should be set explicitly if needed

    return config_modified


def _get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    from another_s3_manager.constants import (
        DEFAULT_MAX_CLIENT_LOAD,
        DEFAULT_MAX_FILE_SIZE,
        DEFAULT_PRESIGNED_URL_DEFAULT_TTL,
        DEFAULT_PRESIGNED_URL_MAX_TTL,
        DEFAULT_PREVIEW_TEXT_EXTENSIONS,
        DEFAULT_UPLOAD_INLINE_EXTENSIONS,
    )

    return {
        "roles": [{"name": "Default", "type": "default", "description": "Use default AWS credentials"}],
        "enable_lazy_loading": os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true",
        "max_file_size": int(os.getenv("MAX_FILE_SIZE", str(DEFAULT_MAX_FILE_SIZE))),
        "max_client_load": int(os.getenv("MAX_CLIENT_LOAD", str(DEFAULT_MAX_CLIENT_LOAD))),
        "disable_deletion": False,
        # Two independent lists (see migration): text-preview vs upload-inline.
        "preview_text_extensions": list(DEFAULT_PREVIEW_TEXT_EXTENSIONS),
        "upload_inline_extensions": list(DEFAULT_UPLOAD_INLINE_EXTENSIONS),
        "password_min_length": 8,
        "password_min_uppercase": 1,
        "password_min_lowercase": 1,
        "password_min_digits": 1,
        "password_min_special": 0,
        "mcp_enabled": True,
        "mcp_disable_writes": False,
        "mcp_text_extensions": [],
        "mcp_global_max_read_bytes": 10_485_760,
        "mcp_summary_max_keys": 50_000,
        "mcp_summary_prefix_scan_pages": 20,
        "mcp_list_page_size": 1000,
        "mcp_list_max_page_size": 10_000,
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
