import builtins
import importlib
import json
import time
from pathlib import Path

import pytest


def reload_users():
    import users

    importlib.reload(users)
    return users


def write_users(data):
    users = reload_users()
    path = Path(users.get_users_file())
    path.write_text(json.dumps(data))


def test_load_users_existing_file():
    write_users({"users": [{"username": "test", "password_hash": "hash", "is_admin": False}]})
    users = reload_users()
    data = users.load_users()
    assert data["users"][0]["username"] == "test"


def test_load_users_creates_default_admin(tmp_path, monkeypatch):
    users = reload_users()
    users_file = Path(users.get_users_file())
    users_file.unlink(missing_ok=True)

    data = users.load_users()
    assert data["users"][0]["username"] == "admin"
    assert data["users"][0]["is_admin"] is True


def test_save_users_writes_file(tmp_path):
    users = reload_users()
    users_file = Path(users.get_users_file())
    payload = {"users": [{"username": "saved", "password_hash": "hash", "is_admin": False}]}
    users.save_users(payload)
    saved = json.loads(users_file.read_text())
    assert saved["users"][0]["username"] == "saved"


def test_load_bans_removes_expired():
    users = reload_users()
    users.save_bans(
        {
            "active": {"banned_until": time.time() + 100},
            "expired": {"banned_until": time.time() - 100},
        }
    )
    bans = users.load_bans()
    assert "active" in bans
    assert "expired" not in bans


def test_save_bans_writes_file():
    users = reload_users()
    data = {"user": {"banned_until": time.time() + 100}}
    users.save_bans(data)
    stored = json.loads(Path(users.get_bans_file()).read_text())
    assert stored["user"]["banned_until"] == data["user"]["banned_until"]


def test_get_user_by_username_found():
    write_users({"users": [{"username": "findme", "password_hash": "hash", "is_admin": False}]})
    users = reload_users()
    user = users.get_user_by_username("findme")
    assert user["username"] == "findme"


def test_get_user_by_username_not_found():
    write_users({"users": []})
    users = reload_users()
    assert users.get_user_by_username("missing") is None


def test_get_all_users():
    write_users({"users": [{"username": "one"}, {"username": "two"}]})
    users = reload_users()
    all_users = users.get_all_users()
    assert len(all_users) == 2


def test_create_user_success():
    write_users({"users": []})
    users = reload_users()
    result = users.create_user("new", "hash", is_admin=True, allowed_roles=["Default"])
    assert result["username"] == "new"
    stored = users.load_users()
    assert stored["users"][0]["username"] == "new"


def test_create_user_duplicate():
    write_users({"users": [{"username": "dup", "password_hash": "hash", "is_admin": False}]})
    users = reload_users()
    with pytest.raises(ValueError, match="already exists"):
        users.create_user("dup", "hash")


def test_update_user_success():
    write_users({"users": [{"username": "target", "password_hash": "hash", "is_admin": False}]})
    users = reload_users()
    updated = users.update_user("target", is_admin=True)
    assert updated["is_admin"] is True


def test_update_user_not_found():
    write_users({"users": []})
    users = reload_users()
    with pytest.raises(ValueError, match="not found"):
        users.update_user("missing", is_admin=True)


def test_delete_user():
    write_users({"users": [{"username": "remove", "password_hash": "hash", "is_admin": False}]})
    users = reload_users()
    users.delete_user("remove")
    stored = users.load_users()
    assert stored["users"] == []


def test_get_available_roles(monkeypatch):
    config_data = {
        "roles": [
            {"name": "Default"},
            {"name": "ReadOnly"},
        ],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100,
    }

    import config as config_module

    config_module.save_config(config_data)

    users = reload_users()
    roles = users.get_available_roles()
    assert roles == ["Default", "ReadOnly"]


def test_load_users_invalid_structure(tmp_path):
    path = Path(reload_users().get_users_file())
    path.write_text(json.dumps({"not_users": []}))
    users = reload_users()
    data = users.load_users()
    assert data["users"][0]["username"] == "admin"


def test_users_import_fallback(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "constants":
            raise ImportError("mock")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("users"))
    try:
        assert module.get_users_file().name == "users.json"
    finally:
        importlib.reload(module)


def test_get_available_roles_handles_import_error(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("missing config")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    users = importlib.reload(importlib.import_module("users"))
    try:
        assert users.get_available_roles() == []
    finally:
        importlib.reload(users)


def test_users_import_without_constants(monkeypatch):
    import users
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "constants":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(users)
    try:
        assert module.get_users_file().name == "users.json"
        assert module.get_bans_file().name == "bans.json"
    finally:
        importlib.reload(module)


def test_load_bans_removes_missing(monkeypatch, tmp_path):
    users_module = reload_users()
    bans_path = tmp_path / "bans.json"
    monkeypatch.setattr(users_module, "get_bans_file", lambda: bans_path)

    bans_path.write_text(json.dumps({"user": {"banned_until": 0}}))

    bans = users_module.load_bans()
    assert bans == {}


def test_load_bans_returns_empty_when_missing(monkeypatch, tmp_path):
    users_module = reload_users()
    bans_path = tmp_path / "bans.json"
    if bans_path.exists():
        bans_path.unlink()

    monkeypatch.setattr(users_module, "get_bans_file", lambda: bans_path)

    assert users_module.load_bans() == {}

