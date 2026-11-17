import pytest

from another_s3_manager import access, users
from another_s3_manager.database import session_scope
from another_s3_manager.models import User


def authenticate(client, user):
    token = access.issue_session(access.Principal(user), method="pwd", lifetime_minutes=180)
    client.cookies.set("access_token", token)
    return {"X-CSRF-Token": access.decode_session_payload(token)["csrf_token"]}


@pytest.mark.parametrize("mode", ["sync", "initial"])
def test_oidc_password_and_applied_sync_management_conflicts(app_client, mode):
    actor = users.create_user("local-admin", "hash", is_admin=True)
    target = users.create_user("sso", "!", allowed_roles=["Default"])
    with session_scope() as session:
        row = session.get(User, target["id"])
        row.auth_source = "oidc"
        row.mapping_mode_applied = mode
    headers = authenticate(app_client, actor)
    response = app_client.put("/api/admin/users/sso", data={"is_admin": "true"}, headers=headers)
    assert response.status_code == (409 if mode == "sync" else 200)
    if mode == "sync":
        assert response.json()["detail"]["code"] == "MANAGED_BY_SSO"
    before = users.get_user_by_id(target["id"])
    response = app_client.put("/api/admin/users/sso/password", json={"password": "NewPassword1"}, headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "NO_LOCAL_PASSWORD"
    assert users.get_user_by_id(target["id"])["password_hash"] == before["password_hash"]


def test_lifecycle_boolean_omission_csrf_and_listing(app_client):
    actor = users.create_user("admin", "hash", is_admin=True)
    target = users.create_user("alice", "hash")
    headers = authenticate(app_client, actor)
    listing = app_client.get("/api/admin/users").json()["users"]
    row = next(u for u in listing if u["username"] == "alice")
    assert (row["auth_source"], row["is_disabled"]) == ("local", False)
    url = "/api/admin/users/alice"
    assert app_client.put(url, data={"is_disabled": "true"}).status_code == 403
    assert app_client.put(url, data={"is_disabled": "typo"}, headers=headers).status_code == 422
    assert app_client.put(url, data={"is_disabled": "true"}, headers=headers).status_code == 200
    assert users.get_user_by_id(target["id"])["session_epoch"] == 1
    assert app_client.put(url, data={"is_admin": "false"}, headers=headers).status_code == 200
    assert users.get_user_by_id(target["id"])["is_disabled"] is True
    assert app_client.put(url, data={"is_disabled": "false"}, headers=headers).status_code == 200
    assert users.get_user_by_id(target["id"])["session_epoch"] == 1


def test_last_local_admin_conflict_mapping(app_client):
    local = users.create_user("local", "hash", is_admin=True)
    actor = users.create_user("sso", "!", is_admin=True)
    with session_scope() as session:
        session.get(User, actor["id"]).auth_source = "oidc"
    headers = authenticate(app_client, actor)
    response = app_client.put("/api/admin/users/local", data={"is_disabled": "true"}, headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "LAST_LOCAL_ADMIN"
    assert users.get_user_by_id(local["id"])["is_disabled"] is False


@pytest.mark.parametrize("credentials", ["valid", "missing", "invalid"])
def test_logout_does_not_claim_cookie_replay_revocation(app_client, credentials):
    user = users.create_user("alice", "hash")
    authenticate(app_client, user)
    token = app_client.cookies.get("access_token")
    if credentials == "missing":
        app_client.cookies.clear()
    elif credentials == "invalid":
        app_client.cookies.clear()
        app_client.cookies.set("access_token", "invalid")
    response = app_client.post("/api/logout", headers={"X-CSRF-Token": "invalid"})
    assert response.status_code == 200 and response.json() == {"ok": True}
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert access.authenticate_session(token).id == user["id"]
    app_client.cookies.set("access_token", token)
    assert app_client.get("/api/me").status_code == 200


def test_stale_admin_grant_save_does_not_reenable_or_restore_pat(app_client):
    from another_s3_manager import api_tokens

    a = users.create_user("admin_a", "hash", is_admin=True)
    b = users.create_user("admin_b", "hash", is_admin=True)
    target = users.create_user("alice", "hash", allowed_roles=["Default"])
    _, plaintext = api_tokens.create_token(target["id"], "automation", False, 1048576)
    authorization = f"Bearer {plaintext}"
    assert (
        access.authenticate_bearer(authorization, lambda: {"roles": [{"name": "Default"}]}).principal.id == target["id"]
    )
    headers = authenticate(app_client, a)
    stale = next(u for u in app_client.get("/api/admin/users").json()["users"] if u["username"] == "alice")
    assert stale["is_disabled"] is False
    b_headers = authenticate(app_client, b)
    assert app_client.put("/api/admin/users/alice", data={"is_disabled": "true"}, headers=b_headers).status_code == 200
    epoch = users.get_user_by_id(target["id"])["session_epoch"]
    with pytest.raises(access.AuthenticationError):
        access.authenticate_bearer(authorization, lambda: {})
    headers = authenticate(app_client, a)
    response = app_client.put(
        "/api/admin/users/alice", data={"allowed_roles": ",".join(stale["allowed_roles"])}, headers=headers
    )
    assert response.status_code == 200
    current = users.get_user_by_id(target["id"])
    assert current["is_disabled"] is True
    assert current["session_epoch"] == epoch
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_bearer(authorization, lambda: {})
    assert error.value.code == "ACCOUNT_DISABLED"
    assert len(api_tokens.list_tokens_for_user(target["id"])) == 1
