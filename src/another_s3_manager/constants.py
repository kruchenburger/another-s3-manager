"""
Application constants and configuration
"""

import os
from pathlib import Path

# File paths
BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
CONFIG_FILE = Path(os.getenv("S3_FILE_MANAGER_CONFIG", str(BASE_DIR / "config.json")))

# Application metadata
APP_NAME = "Another S3 Manager"
APP_DESCRIPTION = "Lightweight S3 file management interface"
APP_VERSION = os.environ.get("APP_VERSION", "dev")


def get_data_dir() -> Path:
    """
    Get the data directory for users.json and bans.json.
    Checks environment variable DATA_DIR first, then config.json, then defaults to BASE_DIR.
    """
    # Check environment variable first
    env_data_dir = os.getenv("DATA_DIR")
    if env_data_dir:
        data_dir = Path(env_data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    # Check config.json
    try:
        from another_s3_manager.config import load_config

        config = load_config(force_reload=False)
        config_data_dir = config.get("data_dir")
        if config_data_dir:
            data_dir = Path(config_data_dir)
            data_dir.mkdir(parents=True, exist_ok=True)
            return data_dir
    except (ImportError, Exception):
        pass

    # Default to BASE_DIR
    return BASE_DIR


def get_users_file() -> Path:
    """Get the path to users.json file."""
    return get_data_dir() / "users.json"


def get_bans_file() -> Path:
    """Get the path to bans.json file."""
    return get_data_dir() / "bans.json"


def get_db_path() -> Path:
    """Get the SQLite DB file path. Lives next to users.json/bans.json under DATA_DIR."""
    return get_data_dir() / "another_s3_manager.db"


# Security settings
JWT_ALGORITHM = "HS256"
# JWT token expiration - can be overridden by JWT_ACCESS_TOKEN_EXPIRE_MINUTES env var
DEFAULT_JWT_EXPIRE_MINUTES = 60 * 3  # 3 hours default
_env_jwt_expire = os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
if _env_jwt_expire:
    try:
        ACCESS_TOKEN_EXPIRE_MINUTES = int(_env_jwt_expire)
        if ACCESS_TOKEN_EXPIRE_MINUTES < 1:
            print(
                f"WARNING: JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be at least 1 minute. Using default: {DEFAULT_JWT_EXPIRE_MINUTES}"
            )
            ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_JWT_EXPIRE_MINUTES
    except ValueError:
        print(
            f"WARNING: Invalid JWT_ACCESS_TOKEN_EXPIRE_MINUTES value '{_env_jwt_expire}'. Using default: {DEFAULT_JWT_EXPIRE_MINUTES}"
        )
        ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_JWT_EXPIRE_MINUTES
else:
    ACCESS_TOKEN_EXPIRE_MINUTES = DEFAULT_JWT_EXPIRE_MINUTES

# The built-in default admin password. Single source of truth for the seed path,
# the startup env sync, and the lifespan default-password warning.
DEFAULT_ADMIN_PASSWORD = "change_me_pls"

# Provenance of the stored password (users.password_set_via). Decides whether the
# startup hook may re-apply ADMIN_PASSWORD to a user:
#   env     — written by the first-boot seed or a previous env sync; env governs it.
#   ui      — written through the web UI / HTTP API; startup never touches it.
#   cli     — written by the reset_admin_password CLI; startup never touches it.
#   unknown — pre-existing row backfilled by the migration; classified once at startup.
# ADMIN_PASSWORD_FORCE overrides all of them (see users.sync_admin_password_from_env).
PASSWORD_SET_VIA_ENV = "env"
PASSWORD_SET_VIA_UI = "ui"
PASSWORD_SET_VIA_CLI = "cli"
PASSWORD_SET_VIA_UNKNOWN = "unknown"

MAX_LOGIN_ATTEMPTS = 3
BAN_DURATION_MINUTES = 60  # 1 hour

# Cookie security — Set-Cookie Secure flag.
# Default true (production-safe). MUST be set to false on localhost (HTTP) or browser will silently drop the cookie.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

# File upload settings
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
DEFAULT_MAX_CLIENT_LOAD = 10000

# Presigned URL TTL settings (seconds).
# SigV4 allows up to 7 days when signing with long-lived IAM access keys.
# STS-backed roles (assume_role / profile) are signed with temporary
# credentials and can expire sooner regardless of the requested TTL — the
# presigned endpoint surfaces a warning for those, it does not hard-clamp.
DEFAULT_PRESIGNED_URL_DEFAULT_TTL = 3600  # 1 hour
DEFAULT_PRESIGNED_URL_MAX_TTL = 604800  # 7 days
PRESIGNED_URL_HARD_CEILING = 604800  # 7 days — absolute SigV4 ceiling
PRESIGNED_URL_MIN_TTL = 60  # reject links shorter than 1 minute
# When a request asks for more than this on an STS-backed role, attach a
# warning that the link may die when the role's session expires.
PRESIGNED_STS_WARNING_THRESHOLD = 3600  # 1 hour

# Text extensions seeded into config.preview_text_extensions for new/legacy
# configs. Controls which TEXT files preview inline in the web UI — admin-editable
# (add / remove / clear). Media (image/video/pdf) always previews regardless.
DEFAULT_PREVIEW_TEXT_EXTENSIONS = ["txt", "md", "json", "yaml", "yml", "log", "csv"]

# Extensions seeded into config.upload_inline_extensions. Files with these
# extensions get Content-Disposition: inline set on the S3 object at upload time,
# so they open in the browser (instead of downloading) when served directly via a
# CDN or presigned URL. svg is intentionally excluded — inline svg from a trusted
# origin is an XSS vector (same rationale as the presigned charset override).
DEFAULT_UPLOAD_INLINE_EXTENSIONS = ["pdf", "png", "jpg", "jpeg", "gif", "webp"]

# S3 settings
S3_USE_SSL = True
S3_VERIFY_SSL = True
