from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from another_s3_manager import access, users
from another_s3_manager.access import passwords
from another_s3_manager.database import session_scope
from another_s3_manager.models import User


@pytest.mark.parametrize("writer", ["update", "save", "reset", "env", "own", "admin"])
def test_every_password_writer_bumps_epoch_atomically(writer, monkeypatch):
    original_hash = access.hash_password("old-password")
    admin = users.create_user("admin", original_hash, is_admin=True, password_set_via="env", must_change_password=False)
    actor = users.create_user("operator", "hash", is_admin=True)
    if writer == "update":
        users.update_user("admin", password_hash="new-hash")
    elif writer == "save":
        data = users.load_users()
        next(u for u in data["users"] if u["username"] == "admin")["password_hash"] = "new-hash"
        users.save_users(data)
    elif writer == "reset":
        access.reset_admin_password("new-hash")
    elif writer == "env":
        monkeypatch.setenv("ADMIN_PASSWORD", "new-password")
        assert users.sync_admin_password_from_env()
    elif writer == "own":
        access.change_own_password(admin, "old-password", "new-password")
    else:
        access.update_account(actor, "admin", {"password_hash": "new-hash"})
    current = users.get_user_by_id(admin["id"])
    assert current["session_epoch"] == 1
    assert current["password_hash"] != original_hash
    users.update_user("admin", password_hash=current["password_hash"], password_set_via="env")
    assert users.get_user_by_id(admin["id"])["session_epoch"] == 1


def password_race(monkeypatch, action, change=False):
    old = users.create_user("alice", access.hash_password("old-password"), must_change_password=False)
    verified, mutated = Barrier(2), Barrier(2)
    original = passwords.verify_password

    def verify(plain, hashed):
        result = original(plain, hashed)
        verified.wait(timeout=10)
        mutated.wait(timeout=10)
        return result

    monkeypatch.setattr(passwords, "verify_password", verify)
    with ThreadPoolExecutor(max_workers=1) as pool:
        if change:
            future = pool.submit(access.change_own_password, old, "old-password", "own-new-password")
        else:
            future = pool.submit(access.authenticate_local, "alice", "old-password", {})
        verified.wait(timeout=10)
        action(old)
        mutated.wait(timeout=10)
        with pytest.raises(access.AuthenticationError):
            future.result(timeout=10)
    return old


def test_login_reset_race_cannot_issue_with_new_epoch(monkeypatch):
    old = password_race(monkeypatch, lambda old: users.update_user("alice", password_hash="admin-reset"))
    current = users.get_user_by_id(old["id"])
    assert (current["session_epoch"], current["password_hash"]) == (1, "admin-reset")


def test_own_change_admin_reset_race_does_not_overwrite_reset(monkeypatch):
    old = password_race(monkeypatch, lambda old: users.update_user("alice", password_hash="admin-reset"), change=True)
    current = users.get_user_by_id(old["id"])
    assert (current["session_epoch"], current["password_hash"]) == (1, "admin-reset")
    assert current["must_change_password"] is False


@pytest.mark.parametrize("change", [False, True])
def test_password_verification_delete_recreate_refuses_old_proof(monkeypatch, change):
    def replace(old):
        users.delete_user("alice")
        with session_scope() as session:
            session.add(User(id=old["id"], username="alice", password_hash="replacement"))

    old = password_race(monkeypatch, replace, change=change)
    current = users.get_user_by_id(old["id"])
    assert current["auth_generation"] != old["auth_generation"]
    assert (current["session_epoch"], current["password_hash"]) == (0, "replacement")


def test_concurrent_password_and_disable_do_not_lose_increment():
    admin = users.create_user("admin", "hash", is_admin=True)
    user = users.create_user("alice", "old")
    start = Barrier(2)

    def password():
        start.wait(timeout=10)
        users.update_user("alice", password_hash="new")

    def disable():
        start.wait(timeout=10)
        access.update_account(admin, "alice", {"is_disabled": True})

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(password), pool.submit(disable)
        a.result(timeout=10)
        b.result(timeout=10)
    current = users.get_user_by_id(user["id"])
    assert (current["session_epoch"], current["is_disabled"], current["password_hash"]) == (2, True, "new")


def test_same_second_password_change_invalidates_session():
    user = users.create_user("alice", "old")
    token = access.issue_session(access.Principal(user), method="pwd", lifetime_minutes=180)
    users.update_user("alice", password_hash="new")
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_session(token)
    assert error.value.code == "SESSION_EPOCH_MISMATCH"


@pytest.mark.parametrize("writer", ["update", "save", "reset", "env"])
def test_noop_password_writes_do_not_bump_epoch(writer, monkeypatch):
    hashed = access.hash_password("unchanged-password")
    user = users.create_user("admin", hashed, is_admin=True, password_set_via="env")
    if writer == "update":
        users.update_user("admin", password_hash=hashed, password_set_via="cli")
    elif writer == "save":
        data = users.load_users()
        data["users"][0]["password_set_via"] = "unknown"
        users.save_users(data)
    elif writer == "reset":
        access.reset_admin_password(hashed)
    else:
        monkeypatch.setenv("ADMIN_PASSWORD", "unchanged-password")
        assert users.sync_admin_password_from_env() is False
    assert users.get_user_by_id(user["id"])["session_epoch"] == 0
