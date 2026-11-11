"""Role grants must never authorize names absent from configuration."""

import json
import logging
from types import SimpleNamespace

import pytest

from another_s3_manager import config, users
from tests.test_default_role import _login_as, _test_password_hash
from tests.test_main import login


def set_roles(*names):
    cfg = config.load_config(force_reload=True)
    cfg["roles"] = [{"name": name, "type": "default"} for name in names]
    config.save_config(cfg)
    return cfg


def member(roles=("A", "B"), username="member"):
    users.load_users()  # Seed the admin before targeted insertion into an empty test database.
    return users.create_user(username, _test_password_hash(), allowed_roles=list(roles), must_change_password=False)


def external_roles(*names):
    import os
    from pathlib import Path

    path = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    cfg = json.loads(path.read_text())
    cfg["roles"] = [{"name": name, "type": "default"} for name in names]
    path.write_text(json.dumps(cfg))
    # Model an observed mtime change without depending on filesystem clock resolution.
    os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 2))


@pytest.fixture
def main_log(caplog, monkeypatch):
    """caplog that still sees main.py's logger after other tests ran alembic's fileConfig.

    fileConfig() defaults to disable_existing_loggers=True, so in a full-suite run
    the module logger can be disabled before these tests execute.
    """
    logger = logging.getLogger("another_s3_manager.main")
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "propagate", False)
    logger.addHandler(caplog.handler)
    yield caplog
    logger.removeHandler(caplog.handler)


@pytest.mark.parametrize(
    "stored,names,expected", [(["B", "gone", "A"], {"A", "B"}, ["B", "A"]), (["A"], set(), []), ([], {"A"}, [])]
)
def test_effective_roles(stored, names, expected):
    assert users.effective_allowed_roles(stored, names) == expected


@pytest.mark.parametrize("grants,expected,default", [(("A", "B"), ["B"], "B"), (("A",), [], None)])
def test_external_removal_hides_roles_and_default(app_client, grants, expected, default):
    set_roles("A", "B")
    member(grants)
    users.update_user("member", default_role="A")
    _login_as(app_client, "member")
    external_roles("B")
    body = app_client.get("/api/me").json()
    assert body["allowed_roles"] == expected
    assert body["default_role"] == default
    cfg = app_client.get("/api/config").json()
    assert cfg.get("current_role") != "A"
    assert users.get_user_by_username("member")["default_role"] == "A"


@pytest.mark.parametrize("endpoint", ["/api/buckets", "/api/buckets/b/presigned"])
def test_deleted_role_denied_before_s3(app_client, monkeypatch, endpoint):
    set_roles("A")
    member(("A",))
    _login_as(app_client, "member")
    external_roles()
    from another_s3_manager import s3_client

    monkeypatch.setattr(s3_client, "get_s3_client", lambda *a: pytest.fail("S3 must not be reached"))
    response = app_client.get(endpoint, params={"role": "A", "path": "file.txt"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied: You don't have permission to use role 'A'"
    with pytest.raises(PermissionError, match="don't have permission"):
        s3_client.validate_role_access("A", {"allowed_roles": ["A"]})


@pytest.mark.parametrize("method", ["post", "put"])
@pytest.mark.parametrize("admin_target", [False, True])
def test_unknown_grant_rejected_without_writes(app_client, method, admin_target):
    set_roles("Default")
    if method == "put":
        member(("Default",), "target")
    _, headers = login(app_client)
    data = {
        "username": "target",
        "password": "GoodPassword123",
        "is_admin": str(admin_target).lower(),
        "allowed_roles": "Z, X, Z",
    }
    url = "/api/admin/users" + ("/target" if method == "put" else "")
    response = getattr(app_client, method)(url, data=data, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown role(s): Z, X. Create the role first or remove it from the list."
    target = users.get_user_by_username("target")
    assert target is None if method == "post" else target["allowed_roles"] == ["Default"]


def test_targeted_create_preserves_other_grants_and_defaults(app_client, monkeypatch):
    set_roles("Default")
    member(("Default", "stale"), "other")
    users.update_user("other", default_role="stale")
    _, headers = login(app_client)
    monkeypatch.setattr(users, "save_users", lambda *a: pytest.fail("No bulk rewrite"))
    response = app_client.post(
        "/api/admin/users",
        data={
            "username": "new",
            "password": "GoodPassword123",
            "allowed_roles": "Default",
            "must_change_password": "false",
        },
        headers=headers,
    )
    assert response.status_code == 200
    other = users.get_user_by_username("other")
    assert other["allowed_roles"] == ["Default", "stale"]
    assert other["default_role"] == "stale"
    new = users.get_user_by_username("new")
    assert new["default_role"] == "Default"
    assert new["created_at"]
    assert new["password_set_via"] == "ui"
    assert new["must_change_password"] is False


def test_prune_counts_and_resets_only_named_roles(app_client):
    member()
    member(("A",), "second")
    users.update_user("member", default_role="A")
    assert users.count_grants_by_role() == {"A": 2, "B": 1}
    assert users.prune_role_grants({"A"}) == {"A": 2}
    assert users.get_user_by_username("member")["allowed_roles"] == ["B"]
    assert users.get_user_by_username("member")["default_role"] is None
    assert users.count_grants_by_role() == {"B": 1}


def test_empty_prune_does_not_open_transaction(monkeypatch):
    monkeypatch.setattr(users, "session_scope", lambda: pytest.fail("No transaction"))
    assert users.prune_role_grants(set()) == {}


@pytest.mark.parametrize("external", [False, True])
def test_recreate_never_restores_old_grants(app_client, external):
    set_roles("Default", "A", "B")
    member()
    _, headers = login(app_client)
    if external:
        external_roles("Default", "B")
    else:
        cfg = config.load_config(force_reload=True)
        cfg["roles"] = [r for r in cfg["roles"] if r["name"] != "A"]
        assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200
        assert users.get_user_by_username("member")["default_role"] is None
    cfg = config.load_config(force_reload=True)
    cfg["roles"].append({"name": "A", "type": "default"})
    assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200
    assert users.get_user_by_username("member")["allowed_roles"] == ["B"]
    _login_as(app_client, "member")
    assert app_client.get("/api/me").json()["allowed_roles"] == ["B"]
    assert app_client.get("/api/buckets", params={"role": "A"}).status_code == 403


@pytest.mark.parametrize("names", [["A,B"], [" A"], ["A "], ["A", "A"], [""], [None], [[]]])
def test_new_role_name_hygiene_before_pruning(app_client, monkeypatch, names):
    _, headers = login(app_client)
    monkeypatch.setattr(users, "prune_role_grants", lambda *a: pytest.fail("Invalid names must not prune"))
    cfg = config.load_config(force_reload=True)
    cfg["roles"].extend({"name": name, "type": "default"} for name in names)
    response = app_client.post("/api/config", json=cfg, headers=headers)
    assert response.status_code == 400
    assert "role" in response.json()["detail"].lower()


def test_case_distinct_names_allowed(app_client):
    _, headers = login(app_client)
    cfg = config.load_config(force_reload=True)
    cfg["roles"].extend({"name": name, "type": "default"} for name in ["a", "A"])
    assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200


def test_admin_list_exposes_missing_roles(app_client):
    set_roles("Default", "B")
    member(("A", "B", "C"))
    _, headers = login(app_client)
    body = app_client.get("/api/admin/users", headers=headers).json()
    row = next(u for u in body["users"] if u["username"] == "member")
    assert row["allowed_roles"] == ["B"]
    assert row["missing_roles"] == ["A", "C"]
    assert body["available_roles"] == ["Default", "B"]


def test_startup_report_does_not_delete(app_client, main_log):
    from another_s3_manager import main

    member(("gone",))
    with main_log.at_level(logging.WARNING):
        main._report_dangling_role_grants()
    assert "Dangling role grants (role no longer in config): gone (1 user)" in main_log.text
    assert users.count_grants_by_role() == {"gone": 1}


@pytest.mark.asyncio
async def test_mcp_filters_identity_and_denies_deleted_presign(app_client, monkeypatch):
    from another_s3_manager import api_tokens, mcp_server, s3_client
    from tests.test_mcp_unknown_role import _call

    set_roles("A", "B")
    user = member()
    _, plaintext = api_tokens.create_token(user["id"], "roles", is_read_only=True, max_read_bytes=1024)
    request = SimpleNamespace(headers={"authorization": f"Bearer {plaintext}"})
    external_roles("B")
    _, identity = await mcp_server.authenticate_mcp_request(request)
    assert identity["allowed_roles"] == ["B"]
    registry = {t.name: t.fn for t in mcp_server.mcp._tool_manager._tools.values()}
    visible = await _call(registry, "list_roles", request)
    assert visible == {"roles": ["B"]}
    monkeypatch.setattr(s3_client, "get_s3_client", lambda *a: pytest.fail("No S3"))
    with pytest.raises(mcp_server.McpError) as error:
        await _call(registry, "presigned_url", request, role="A", bucket="b", path="f")
    assert error.value.code == "ROLE_NOT_ALLOWED"
    assert error.value.details["allowed_roles"] == ["B"]


@pytest.mark.parametrize("failure", [RuntimeError, PermissionError])
def test_pre_prune_failure_prevents_publication(app_client, monkeypatch, failure):
    _, headers = login(app_client)
    old = config.load_config(force_reload=True)
    new = {**old, "roles": old["roles"] + [{"name": "A", "type": "default"}]}

    def fail(names):
        raise failure("prune failed")

    monkeypatch.setattr(users, "prune_role_grants", fail)
    assert app_client.post("/api/config", json=new, headers=headers).status_code == 500
    assert config.load_config(force_reload=True)["roles"] == old["roles"]


def test_post_prune_failure_is_success_and_hidden(app_client, monkeypatch, main_log):
    set_roles("Default", "A")
    member(("A",))
    _, headers = login(app_client)

    def fail(names):
        raise RuntimeError("prune failed")

    monkeypatch.setattr(users, "prune_role_grants", fail)
    cfg = config.load_config(force_reload=True)
    cfg["roles"] = [cfg["roles"][0]]
    with main_log.at_level(logging.ERROR):
        assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200
    assert "Failed to prune grants after role removal" in main_log.text
    assert users.count_grants_by_role() == {"A": 1}
    _login_as(app_client, "member")
    assert app_client.get("/api/me").json()["allowed_roles"] == []


def test_unchanged_names_do_not_prune_and_legacy_names_survive(app_client, monkeypatch):
    set_roles("Default", "old,bad")
    member(("old,bad",))
    _, headers = login(app_client)
    monkeypatch.setattr(users, "prune_role_grants", lambda *a: pytest.fail("No changed names"))
    cfg = config.load_config(force_reload=True)
    cfg["roles"].reverse()
    assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200
    assert users.count_grants_by_role() == {"old,bad": 1}


def test_save_failure_does_not_remove_old_grants(app_client, monkeypatch):
    from another_s3_manager import main

    set_roles("Default", "A")
    member(("A",))
    _, headers = login(app_client)
    cfg = config.load_config(force_reload=True)
    cfg["roles"] = [cfg["roles"][0]]

    def fail(cfg):
        raise OSError("save failed")

    monkeypatch.setattr(main, "save_config", fail)
    assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 500
    assert users.count_grants_by_role() == {"A": 1}
    assert users.get_user_by_username("member")["default_role"] == "A"


def test_prune_rolls_back_deleted_grants_if_default_update_fails(app_client, monkeypatch):
    from sqlalchemy import event
    from sqlalchemy.sql.dml import Update

    from another_s3_manager.database import get_engine

    member(("A",))
    engine = get_engine()

    def fail_update(conn, clause, multiparams, params, execution_options):
        if isinstance(clause, Update):
            raise RuntimeError("default update failed")

    event.listen(engine, "before_execute", fail_update)
    try:
        with pytest.raises(RuntimeError, match="default update failed"):
            users.prune_role_grants({"A"})
    finally:
        event.remove(engine, "before_execute", fail_update)
    assert users.count_grants_by_role() == {"A": 1}
    assert users.get_user_by_username("member")["default_role"] == "A"


def test_report_silent_without_dangling_roles(app_client, main_log):
    from another_s3_manager import main

    with main_log.at_level(logging.WARNING):
        main._report_dangling_role_grants()
    assert not main_log.records


def test_report_failure_is_nonfatal(app_client, monkeypatch, main_log):
    from another_s3_manager import main

    def fail():
        raise RuntimeError("read failed")

    monkeypatch.setattr(users, "count_grants_by_role", fail)
    with main_log.at_level(logging.WARNING):
        main._report_dangling_role_grants()
    assert "continuing startup" in main_log.text


@pytest.mark.parametrize("method", ["post", "put"])
def test_grant_validation_and_write_hold_same_lock(app_client, monkeypatch, method):
    from another_s3_manager import main

    _, headers = login(app_client)
    member(("Default",), "target")
    lock = users.role_grants_lock
    original_load = main.load_config
    original_write = users.create_user if method == "post" else users.update_user
    calls = []

    def load(*args, **kwargs):
        if kwargs.get("force_reload"):
            assert lock._is_owned()
            calls.append("validate")
        return original_load(*args, **kwargs)

    def write(*args, **kwargs):
        assert lock._is_owned()
        calls.append("write")
        return original_write(*args, **kwargs)

    monkeypatch.setattr(main, "load_config", load)
    monkeypatch.setattr(users, "create_user" if method == "post" else "update_user", write)
    url = "/api/admin/users" + ("/target" if method == "put" else "")
    response = getattr(app_client, method)(
        url, data={"username": "new", "password": "GoodPassword123", "allowed_roles": "Default"}, headers=headers
    )
    assert response.status_code == 200
    assert calls == ["validate", "write"]


def test_config_lock_covers_old_snapshot_preprune_save_postprune(app_client, monkeypatch):
    from another_s3_manager import main

    set_roles("Default", "A")
    _, headers = login(app_client)
    cfg = config.load_config(force_reload=True)
    cfg["roles"] = [{"name": n, "type": "default"} for n in ["Default", "B"]]
    lock = users.role_grants_lock
    original_load, original_save = main.load_config, main.save_config
    calls = []

    def load(*args, **kwargs):
        assert lock._is_owned()
        calls.append("old")
        return original_load(*args, **kwargs)

    def prune(names):
        assert lock._is_owned()
        calls.append(sorted(names))
        return {}

    def save(value):
        assert lock._is_owned()
        calls.append("save")
        return original_save(value)

    monkeypatch.setattr(main, "load_config", load)
    monkeypatch.setattr(main, "save_config", save)
    monkeypatch.setattr(users, "prune_role_grants", prune)
    assert app_client.post("/api/config", json=cfg, headers=headers).status_code == 200
    assert calls == ["old", ["B"], "save", ["A"]]


def test_put_without_roles_preserves_dangling_grants(app_client):
    _, headers = login(app_client)
    member(("gone",), "target")
    response = app_client.put("/api/admin/users/target", data={"is_admin": "true"}, headers=headers)
    assert response.status_code == 200
    assert users.get_user_by_username("target")["allowed_roles"] == ["gone"]


def test_put_known_and_empty_roles_allowed(app_client):
    _, headers = login(app_client)
    member(("gone",), "target")
    for roles, expected in [("Default", ["Default"]), ("", [])]:
        assert (
            app_client.put("/api/admin/users/target", data={"allowed_roles": roles}, headers=headers).status_code == 200
        )
        assert users.get_user_by_username("target")["allowed_roles"] == expected


def test_rest_guard_and_default_choice_reject_dangling_role(app_client):
    from fastapi import HTTPException

    from another_s3_manager import main

    set_roles("A", "B")
    member()
    _login_as(app_client, "member")
    external_roles("B")
    with pytest.raises(HTTPException) as error:
        main.validate_role_access("A", {"username": "member", "is_admin": False})
    assert error.value.status_code == 403
    assert error.value.detail == "Access denied: You don't have permission to use role 'A'"
    assert app_client.put("/api/me/default-role", json={"role": "A"}).status_code == 400
    assert app_client.put("/api/me/default-role", json={"role": "B"}).status_code == 200


def test_nameless_config_role_does_not_break_non_admin_paths(app_client):
    # A hand-edited config may hold a role without "name"; it must be skipped, not 500.
    set_roles("A")
    member(("A",))
    _login_as(app_client, "member")
    import os
    from pathlib import Path

    path = Path(os.environ["S3_FILE_MANAGER_CONFIG"])
    cfg = json.loads(path.read_text())
    cfg["roles"].append({"type": "default"})
    path.write_text(json.dumps(cfg))
    os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 2))
    assert app_client.get("/api/me").json()["allowed_roles"] == ["A"]
    assert app_client.get("/api/config").status_code == 200
