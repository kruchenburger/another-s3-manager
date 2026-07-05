"""Tests for one-shot JSON → SQLite migration."""

import json
import time

import pytest


def test_migration_imports_users_and_bans(db_session, tmp_path, monkeypatch):
    """JSON files exist + DB empty → users and bans imported, JSON renamed to .migrated.bak."""
    from another_s3_manager.constants import get_bans_file, get_users_file

    users_file = get_users_file()
    bans_file = get_bans_file()
    users_file.write_text(
        json.dumps(
            {
                "users": [
                    {
                        "username": "alice",
                        "password_hash": "h1",
                        "is_admin": False,
                        "allowed_roles": ["r1"],
                        "theme": "dark",
                    },
                    {"username": "bob", "password_hash": "h2", "is_admin": True, "allowed_roles": [], "theme": "auto"},
                ]
            }
        )
    )
    now = time.time()
    bans_file.write_text(
        json.dumps(
            {
                "alice": {"banned_until": now + 3600, "banned_at": now, "reason": "test"},
            }
        )
    )

    # Wipe any default admin so we know if migration ran
    from another_s3_manager.users import save_users

    save_users({"users": []})

    from another_s3_manager.migration import migrate_json_if_needed

    migrate_json_if_needed()

    from another_s3_manager.users import load_bans, load_users

    users = {u["username"] for u in load_users()["users"]}
    assert users == {"alice", "bob"}

    bans = load_bans()
    assert "alice" in bans

    # JSON files renamed
    assert not users_file.exists()
    assert (users_file.parent / "users.json.migrated.bak").exists()


def test_migration_skips_when_db_already_has_users(db_session, tmp_path):
    """If users already exist in the DB, migration is a no-op."""
    from another_s3_manager.constants import get_users_file
    from another_s3_manager.users import create_user

    create_user(username="existing", password_hash="h")
    users_file = get_users_file()
    users_file.write_text(json.dumps({"users": [{"username": "fromjson", "password_hash": "h"}]}))

    from another_s3_manager.migration import migrate_json_if_needed

    migrate_json_if_needed()

    from another_s3_manager.users import get_user_by_username

    assert get_user_by_username("fromjson") is None
    # JSON file untouched
    assert users_file.exists()


def test_migration_no_json_files_no_op(db_session, tmp_path):
    """No JSON files at all → migration does nothing, no error."""
    from another_s3_manager.migration import migrate_json_if_needed

    migrate_json_if_needed()  # should not raise


def test_migration_corrupt_users_json_raises(db_session, tmp_path):
    """Corrupt users.json → exception (caller decides what to do, e.g. exit at startup)."""
    from another_s3_manager.constants import get_users_file
    from another_s3_manager.users import save_users

    save_users({"users": []})
    get_users_file().write_text("{ not valid json")

    from another_s3_manager.migration import migrate_json_if_needed

    with pytest.raises(json.JSONDecodeError):
        migrate_json_if_needed()
