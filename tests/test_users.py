import builtins
import importlib
import time

import pytest


def test_load_users_creates_default_admin_when_db_empty(db_session, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test_admin_pw_123")
    from another_s3_manager.users import load_users

    result = load_users()
    assert "users" in result
    assert len(result["users"]) == 1
    admin = result["users"][0]
    assert admin["username"] == "admin"
    assert admin["is_admin"] is True
    assert admin["theme"] == "auto"
    assert admin["allowed_roles"] == []


def test_load_users_returns_existing_users(db_session):
    """If users exist, load_users returns them without creating defaults."""
    from another_s3_manager.users import load_users, save_users

    save_users(
        {
            "users": [
                {
                    "username": "alice",
                    "password_hash": "h",
                    "is_admin": False,
                    "allowed_roles": ["r1"],
                    "theme": "dark",
                },
            ]
        }
    )

    result = load_users()
    assert len(result["users"]) == 1
    assert result["users"][0]["username"] == "alice"
    assert result["users"][0]["allowed_roles"] == ["r1"]
    assert result["users"][0]["theme"] == "dark"


def test_save_users_replaces_all(db_session):
    """save_users() replaces the entire user set atomically."""
    from another_s3_manager.users import load_users, save_users

    save_users(
        {
            "users": [
                {
                    "username": "alice",
                    "password_hash": "h1",
                    "is_admin": False,
                    "allowed_roles": [],
                    "theme": "auto",
                },
                {
                    "username": "bob",
                    "password_hash": "h2",
                    "is_admin": True,
                    "allowed_roles": ["admin"],
                    "theme": "dark",
                },
            ]
        }
    )

    save_users(
        {
            "users": [
                {
                    "username": "carol",
                    "password_hash": "h3",
                    "is_admin": False,
                    "allowed_roles": [],
                    "theme": "auto",
                },
            ]
        }
    )

    result = load_users()
    usernames = sorted(u["username"] for u in result["users"])
    assert usernames == ["carol"]


def test_create_user_appends(db_session):
    from another_s3_manager.users import create_user, get_all_users

    create_user(username="alice", password_hash="h", is_admin=False, allowed_roles=["r1"])
    users = get_all_users()
    assert len(users) == 2  # default admin + alice
    assert any(u["username"] == "alice" for u in users)


def test_create_user_duplicate_raises(db_session):
    from another_s3_manager.users import create_user

    create_user(username="alice", password_hash="h")
    with pytest.raises(ValueError, match="already exists"):
        create_user(username="alice", password_hash="h")


def test_delete_user_removes(db_session):
    from another_s3_manager.users import create_user, delete_user, get_user_by_username

    create_user(username="alice", password_hash="h")
    delete_user("alice")
    assert get_user_by_username("alice") is None


def test_save_load_bans_roundtrip(db_session):
    from another_s3_manager.users import create_user, load_bans, save_bans

    create_user(username="alice", password_hash="h")
    now = time.time()
    save_bans({"alice": {"banned_until": now + 3600, "banned_at": now, "reason": "test"}})
    bans = load_bans()
    assert "alice" in bans
    assert bans["alice"]["banned_until"] == pytest.approx(now + 3600)


def test_load_bans_filters_expired(db_session):
    from another_s3_manager.users import create_user, load_bans, save_bans

    create_user(username="alice", password_hash="h")
    create_user(username="bob", password_hash="h")
    now = time.time()
    save_bans(
        {
            "alice": {"banned_until": now - 100, "banned_at": now - 200, "reason": "expired"},
            "bob": {"banned_until": now + 3600, "banned_at": now, "reason": "active"},
        }
    )
    bans = load_bans()
    assert "alice" not in bans
    assert "bob" in bans


def test_save_bans_for_unknown_user_skipped(db_session):
    """Bans reference users via FK — if the username doesn't exist, the ban is silently dropped."""
    from another_s3_manager.users import load_bans, save_bans

    now = time.time()
    save_bans({"ghost": {"banned_until": now + 3600, "banned_at": now}})
    assert load_bans() == {}


def test_get_user_by_username_found(db_session):
    from another_s3_manager.users import create_user, get_user_by_username

    create_user(username="findme", password_hash="hash")
    user = get_user_by_username("findme")
    assert user is not None
    assert user["username"] == "findme"


def test_get_user_by_username_not_found(db_session):
    from another_s3_manager.users import get_user_by_username

    assert get_user_by_username("missing") is None


def test_get_all_users(db_session):
    from another_s3_manager.users import create_user, get_all_users

    # First create_user seeds default admin (matching legacy behavior), then appends "one" and "two"
    create_user(username="one", password_hash="h")
    create_user(username="two", password_hash="h")
    all_users = get_all_users()
    assert sorted(u["username"] for u in all_users) == ["admin", "one", "two"]


def test_update_user_success(db_session):
    from another_s3_manager.users import create_user, update_user

    create_user(username="target", password_hash="hash")
    updated = update_user("target", is_admin=True)
    assert updated["is_admin"] is True


def test_update_user_not_found(db_session):
    from another_s3_manager.users import update_user

    with pytest.raises(ValueError, match="not found"):
        update_user("missing", is_admin=True)


def test_get_available_roles(db_session, monkeypatch):
    config_data = {
        "roles": [
            {"name": "Default"},
            {"name": "ReadOnly"},
        ],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100,
    }

    import another_s3_manager.config as config_module

    config_module.save_config(config_data)

    from another_s3_manager.users import get_available_roles

    roles = get_available_roles()
    assert roles == ["Default", "ReadOnly"]


def test_get_available_roles_handles_import_error(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "another_s3_manager.config":
            raise ImportError("missing config")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    users = importlib.reload(importlib.import_module("another_s3_manager.users"))
    try:
        assert users.get_available_roles() == []
    finally:
        importlib.reload(users)
