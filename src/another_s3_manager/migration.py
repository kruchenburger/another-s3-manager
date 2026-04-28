"""One-shot JSON → SQLite migration. Runs at startup if needed."""

import json
import logging
from pathlib import Path

from another_s3_manager.constants import get_bans_file, get_users_file
from another_s3_manager.users import save_bans, save_users

logger = logging.getLogger(__name__)


def _has_existing_users() -> bool:
    """Check if the DB already has users (other than what load_users() would seed)."""
    # load_users() seeds a default admin if empty — so we can't just call it.
    # Use a direct query.
    from sqlalchemy import select

    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as session:
        return session.execute(select(User).limit(1)).scalar_one_or_none() is not None


def _backup_file(path: Path) -> None:
    """Rename path to path.migrated.bak. Idempotent: appends counter if backup exists."""
    backup = path.with_suffix(path.suffix + ".migrated.bak")
    if backup.exists():
        # Already backed up once — append a counter
        i = 2
        while True:
            alt = path.with_suffix(f"{path.suffix}.migrated.bak.{i}")
            if not alt.exists():
                backup = alt
                break
            i += 1
    path.rename(backup)
    logger.info("Migration: renamed %s → %s", path.name, backup.name)


def migrate_json_if_needed() -> None:
    """Migrate users.json + bans.json to SQLite if both:
    1. Either JSON file exists
    2. The DB has no users yet

    Raises on JSON parse errors — caller (startup) should exit with a clear error.
    """
    users_file = get_users_file()
    bans_file = get_bans_file()

    if not users_file.exists() and not bans_file.exists():
        logger.info("Migration: no JSON files found, nothing to migrate.")
        return

    if _has_existing_users():
        logger.info("Migration: DB already has users, skipping JSON import.")
        return

    if users_file.exists():
        logger.info("Migration: importing users from %s", users_file)
        with open(users_file, "r", encoding="utf-8") as f:
            users_data = json.load(f)  # JSONDecodeError propagates intentionally
        save_users(users_data)
        _backup_file(users_file)

    if bans_file.exists():
        logger.info("Migration: importing bans from %s", bans_file)
        with open(bans_file, "r", encoding="utf-8") as f:
            bans_data = json.load(f)
        save_bans(bans_data)
        _backup_file(bans_file)

    logger.info("Migration: complete.")
