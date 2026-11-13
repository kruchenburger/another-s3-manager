from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from another_s3_manager import access, users
from another_s3_manager.database import session_scope
from another_s3_manager.models import User


@pytest.mark.parametrize(
    "changes,code", [({"is_admin": False}, "self_demote"), ({"is_disabled": True}, "self_disable")]
)
def test_self_protection(changes, code):
    actor = users.create_user("admin", "hash", is_admin=True)
    with pytest.raises(access.AccessDenied) as error:
        access.update_account(actor, "admin", changes)
    assert error.value.code == code
    with pytest.raises(access.AccessDenied) as error:
        access.delete_account(actor, "admin")
    assert error.value.code == "self_delete"


@pytest.mark.parametrize("action", ["delete", "disable", "demote"])
def test_last_enabled_local_admin(action):
    local = users.create_user("local", "hash", is_admin=True)
    actor = users.create_user("sso", "!", is_admin=True)
    with session_scope() as session:
        session.get(User, actor["id"]).auth_source = "oidc"
    actor = users.get_user_by_id(actor["id"])
    with pytest.raises(access.AccessDenied) as error:
        if action == "delete":
            access.delete_account(actor, "local")
        else:
            access.update_account(actor, "local", {"is_disabled": True} if action == "disable" else {"is_admin": False})
    assert error.value.code == "LAST_LOCAL_ADMIN"
    assert users.get_user_by_id(local["id"])["is_admin"]


def test_two_last_admin_mutations_serialize():
    a = users.create_user("alice", "hash", is_admin=True)
    b = users.create_user("bob", "hash", is_admin=True)
    start = Barrier(2)

    def disable(actor, target):
        start.wait(timeout=10)
        try:
            access.update_account(actor, target, {"is_disabled": True})
            return "ok"
        except access.AccessDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(disable, a, "bob")
        two = pool.submit(disable, b, "alice")
        assert sorted([one.result(timeout=15), two.result(timeout=15)]) == ["denied", "ok"]
    assert sum(u["is_admin"] and not u["is_disabled"] for u in users.get_all_users()) == 1


@pytest.mark.parametrize("stale", ["demoted", "replaced"])
def test_actor_rechecked_inside_transaction(stale):
    actor = users.create_user("admin", "hash", is_admin=True)
    target = users.create_user("target", "hash")
    if stale == "demoted":
        users.update_user("admin", is_admin=False)
    else:
        users.delete_user("admin")
        with session_scope() as session:
            session.add(User(id=actor["id"], username="admin", password_hash="hash", is_admin=True))
    with pytest.raises(access.AccessDenied):
        access.update_account(actor, "target", {"is_disabled": True})
    assert users.get_user_by_id(target["id"])["is_disabled"] is False
