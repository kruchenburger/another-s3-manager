"""Integration tests for /api/me/tokens and /api/admin/tokens endpoints."""

import importlib

import pytest
from fastapi import status

from another_s3_manager.database import session_scope
from another_s3_manager.models import User


def _ensure_admin(users_module, auth_module):
    """Make sure the admin user exists in the DB and the JSON user store."""
    data = users_module.load_users()
    if not any(u.get("username") == "admin" for u in data.get("users", [])):
        data.setdefault("users", []).append(
            {
                "username": "admin",
                "password_hash": auth_module.hash_password("admin123"),
                "is_admin": True,
                "allowed_roles": [],
                "theme": "auto",
            }
        )
        users_module.save_users(data)


def _login(client, username: str, password: str):
    """Log in via /api/login and return the CSRF token.

    The TestClient cookie jar captures the Set-Cookie header automatically, so
    subsequent requests on the same client are authenticated.
    """
    resp = client.post("/api/login", data={"username": username, "password": password})
    assert resp.status_code == status.HTTP_200_OK, resp.text
    me_resp = client.get("/api/me")
    assert me_resp.status_code == status.HTTP_200_OK, me_resp.text
    return me_resp.json()["csrf_token"]


def _insert_db_user(username: str, is_admin: bool = False) -> int:
    """Insert a User row directly into the test DB and return its id."""
    with session_scope() as session:
        user = User(username=username, password_hash="x", is_admin=is_admin)
        session.add(user)
        session.flush()
        return user.id


@pytest.fixture
def client_with_admin(app_client):
    """Return (TestClient, csrf_token) authenticated as admin."""
    import another_s3_manager.auth as auth_module
    import another_s3_manager.users as users_module

    importlib.reload(auth_module)
    importlib.reload(users_module)
    auth_module._login_attempts = {}
    users_module.save_bans({})
    _ensure_admin(users_module, auth_module)
    csrf = _login(app_client, "admin", "admin123")
    return app_client, csrf


# ---------------------------------------------------------------------------
# GET /api/me/tokens
# ---------------------------------------------------------------------------


def test_get_me_tokens_returns_shape(client_with_admin):
    client, _ = client_with_admin
    resp = client.get("/api/me/tokens")
    assert resp.status_code == 200
    body = resp.json()
    assert "tokens" in body
    assert "used" in body
    assert "limit" in body
    assert body["limit"] == 10
    assert body["used"] == 0
    assert body["tokens"] == []


# ---------------------------------------------------------------------------
# POST /api/me/tokens
# ---------------------------------------------------------------------------


def test_post_me_tokens_returns_plaintext_once(client_with_admin):
    client, csrf = client_with_admin
    resp = client.post(
        "/api/me/tokens",
        json={"name": "Claude Desktop", "is_read_only": True, "max_read_bytes": 1_048_576},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_plaintext"].startswith("as3m_")
    assert body["name"] == "Claude Desktop"
    assert body["is_read_only"] is True
    assert "id" in body

    # Subsequent GET must NOT include token_plaintext
    list_resp = client.get("/api/me/tokens")
    assert list_resp.status_code == 200
    items = list_resp.json()["tokens"]
    assert len(items) == 1
    assert "token_plaintext" not in items[0]
    assert items[0]["name"] == "Claude Desktop"


def test_post_me_tokens_updates_used_count(client_with_admin):
    client, csrf = client_with_admin
    client.post(
        "/api/me/tokens",
        json={"name": "t1", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": csrf},
    )
    list_resp = client.get("/api/me/tokens")
    body = list_resp.json()
    assert body["used"] == 1
    assert len(body["tokens"]) == 1


def test_post_me_tokens_validates_max_read_bytes_too_large(client_with_admin):
    """max_read_bytes > 10 MB (10_485_760) must return 422."""
    client, csrf = client_with_admin
    resp = client.post(
        "/api/me/tokens",
        json={"name": "x", "is_read_only": True, "max_read_bytes": 100_000_000},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 422


def test_post_me_tokens_validates_max_read_bytes_zero(client_with_admin):
    """max_read_bytes = 0 must return 422 (ge=1)."""
    client, csrf = client_with_admin
    resp = client.post(
        "/api/me/tokens",
        json={"name": "x", "is_read_only": True, "max_read_bytes": 0},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 422


def test_post_me_tokens_duplicate_name_returns_409(client_with_admin):
    client, csrf = client_with_admin
    payload = {"name": "dup", "is_read_only": True, "max_read_bytes": 1024}
    r1 = client.post("/api/me/tokens", json=payload, headers={"X-CSRF-Token": csrf})
    assert r1.status_code == 200
    r2 = client.post("/api/me/tokens", json=payload, headers={"X-CSRF-Token": csrf})
    assert r2.status_code == 409


def test_post_me_tokens_limit_exceeded_returns_422(client_with_admin):
    """Creating the 11th token must return 422."""
    client, csrf = client_with_admin
    for i in range(10):
        r = client.post(
            "/api/me/tokens",
            json={"name": f"t{i}", "is_read_only": True, "max_read_bytes": 1024},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, f"token #{i} failed: {r.text}"

    overflow = client.post(
        "/api/me/tokens",
        json={"name": "overflow", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": csrf},
    )
    assert overflow.status_code == 422
    assert "limit" in overflow.json()["detail"].lower()


def test_post_me_tokens_requires_csrf(client_with_admin):
    """POST without X-CSRF-Token header must be rejected."""
    client, _ = client_with_admin
    resp = client.post(
        "/api/me/tokens",
        json={"name": "no-csrf", "is_read_only": True, "max_read_bytes": 1024},
    )
    assert resp.status_code in (401, 403)


def test_post_me_tokens_requires_auth(app_client):
    """Unauthenticated POST must return 401."""
    resp = app_client.post(
        "/api/me/tokens",
        json={"name": "anon", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": "fake"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# DELETE /api/me/tokens/{id}
# ---------------------------------------------------------------------------


def test_delete_me_token_removes_from_active_list(client_with_admin):
    client, csrf = client_with_admin
    create_resp = client.post(
        "/api/me/tokens",
        json={"name": "to_revoke", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": csrf},
    )
    assert create_resp.status_code == 200
    token_id = create_resp.json()["id"]

    del_resp = client.delete(f"/api/me/tokens/{token_id}", headers={"X-CSRF-Token": csrf})
    assert del_resp.status_code == 200
    assert del_resp.json()["ok"] is True

    list_resp = client.get("/api/me/tokens")
    assert list_resp.status_code == 200
    ids = [t["id"] for t in list_resp.json()["tokens"]]
    assert token_id not in ids
    assert list_resp.json()["used"] == 0


def test_delete_me_token_404_on_unknown_id(client_with_admin):
    client, csrf = client_with_admin
    resp = client.delete("/api/me/tokens/999999", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 404


def test_delete_me_token_non_owner_403(app_client):
    """User alice cannot revoke admin's token."""
    import another_s3_manager.auth as auth_module
    import another_s3_manager.users as users_module

    importlib.reload(auth_module)
    importlib.reload(users_module)
    auth_module._login_attempts = {}
    users_module.save_bans({})

    # Ensure admin exists
    _ensure_admin(users_module, auth_module)

    # Create alice in JSON store — migrate_json_if_needed() will insert her into
    # the DB when the first request (login) triggers the startup hook.
    alice_data = users_module.load_users()
    alice_data["users"].append(
        {
            "username": "alice",
            "password_hash": auth_module.hash_password("alicepass"),
            "is_admin": False,
            "allowed_roles": [],
            "theme": "auto",
        }
    )
    users_module.save_users(alice_data)

    # Admin logs in and creates a token
    admin_csrf = _login(app_client, "admin", "admin123")
    create_resp = app_client.post(
        "/api/me/tokens",
        json={"name": "admin-token", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert create_resp.status_code == 200
    token_id = create_resp.json()["id"]

    # Alice logs in on a fresh client (new cookie jar)
    from fastapi.testclient import TestClient

    import another_s3_manager.main as main_module

    alice_client = TestClient(main_module.app)
    alice_csrf = _login(alice_client, "alice", "alicepass")

    del_resp = alice_client.delete(f"/api/me/tokens/{token_id}", headers={"X-CSRF-Token": alice_csrf})
    assert del_resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/admin/tokens
# ---------------------------------------------------------------------------


def test_admin_list_tokens_includes_owner_username(client_with_admin):
    client, csrf = client_with_admin
    client.post(
        "/api/me/tokens",
        json={"name": "admin-tok", "is_read_only": False, "max_read_bytes": 2_000_000},
        headers={"X-CSRF-Token": csrf},
    )
    resp = client.get("/api/admin/tokens")
    assert resp.status_code == 200
    tokens = resp.json()["tokens"]
    assert len(tokens) == 1
    assert tokens[0]["owner_username"] == "admin"
    assert tokens[0]["name"] == "admin-tok"
    assert "token_plaintext" not in tokens[0]


def test_admin_list_tokens_non_admin_403(app_client):
    """Non-admin user must receive 403 on the admin list endpoint."""
    import another_s3_manager.auth as auth_module
    import another_s3_manager.users as users_module

    importlib.reload(auth_module)
    importlib.reload(users_module)
    auth_module._login_attempts = {}
    users_module.save_bans({})

    bob_data = users_module.load_users()
    bob_data.setdefault("users", []).append(
        {
            "username": "bob",
            "password_hash": auth_module.hash_password("bobpass"),
            "is_admin": False,
            "allowed_roles": [],
            "theme": "auto",
        }
    )
    users_module.save_users(bob_data)
    # No _insert_db_user — startup migration inserts bob from JSON on first request.

    bob_csrf = _login(app_client, "bob", "bobpass")
    resp = app_client.get("/api/admin/tokens", headers={"X-CSRF-Token": bob_csrf})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/admin/tokens
# ---------------------------------------------------------------------------


def test_admin_create_token_on_behalf_of_user(client_with_admin):
    """Admin creates a token for another user by user_id."""
    client, csrf = client_with_admin
    # Insert target user into DB
    target_id = _insert_db_user("target_user", is_admin=False)

    resp = client.post(
        "/api/admin/tokens",
        json={
            "name": "agent-token",
            "is_read_only": True,
            "max_read_bytes": 1024,
            "user_id": target_id,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_plaintext"].startswith("as3m_")
    assert body["name"] == "agent-token"

    # Admin list should show it with correct owner
    list_resp = client.get("/api/admin/tokens")
    tokens = list_resp.json()["tokens"]
    assert any(t["name"] == "agent-token" for t in tokens)


def test_admin_create_token_non_admin_403(app_client):
    """Non-admin must receive 403 on POST /api/admin/tokens."""
    import another_s3_manager.auth as auth_module
    import another_s3_manager.users as users_module

    importlib.reload(auth_module)
    importlib.reload(users_module)
    auth_module._login_attempts = {}
    users_module.save_bans({})

    carol_data = users_module.load_users()
    carol_data.setdefault("users", []).append(
        {
            "username": "carol",
            "password_hash": auth_module.hash_password("carolpass"),
            "is_admin": False,
            "allowed_roles": [],
            "theme": "auto",
        }
    )
    users_module.save_users(carol_data)
    # No _insert_db_user — startup migration inserts carol from JSON on first request.

    carol_csrf = _login(app_client, "carol", "carolpass")
    resp = app_client.post(
        "/api/admin/tokens",
        json={"name": "x", "is_read_only": True, "max_read_bytes": 1024, "user_id": 999},
        headers={"X-CSRF-Token": carol_csrf},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /api/admin/tokens/{id}
# ---------------------------------------------------------------------------


def test_admin_delete_any_token(client_with_admin):
    """Admin can revoke a token belonging to any user."""
    client, csrf = client_with_admin
    target_id = _insert_db_user("victim", is_admin=False)

    create_resp = client.post(
        "/api/admin/tokens",
        json={"name": "victim-tok", "is_read_only": True, "max_read_bytes": 1024, "user_id": target_id},
        headers={"X-CSRF-Token": csrf},
    )
    assert create_resp.status_code == 200
    token_id = create_resp.json()["id"]

    del_resp = client.delete(f"/api/admin/tokens/{token_id}", headers={"X-CSRF-Token": csrf})
    assert del_resp.status_code == 200
    assert del_resp.json()["ok"] is True

    # Token must no longer appear in admin list
    list_resp = client.get("/api/admin/tokens")
    ids = [t["id"] for t in list_resp.json()["tokens"]]
    assert token_id not in ids


def test_admin_delete_token_404_on_unknown(client_with_admin):
    client, csrf = client_with_admin
    resp = client.delete("/api/admin/tokens/999999", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 404


def test_admin_create_token_for_nonexistent_user_returns_404(client_with_admin):
    """Spec §11.4: admin POST with bogus user_id should be 404, not 409."""
    client, csrf = client_with_admin
    resp = client.post(
        "/api/admin/tokens",
        json={
            "user_id": 999_999,
            "name": "ghost",
            "is_read_only": True,
            "max_read_bytes": 1024,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert "999999" in str(body) or "not found" in str(body).lower()


def test_admin_delete_token_non_admin_403(app_client):
    """Non-admin must receive 403 on DELETE /api/admin/tokens/{id}."""
    import another_s3_manager.auth as auth_module
    import another_s3_manager.users as users_module

    importlib.reload(auth_module)
    importlib.reload(users_module)
    auth_module._login_attempts = {}
    users_module.save_bans({})

    dave_data = users_module.load_users()
    dave_data.setdefault("users", []).append(
        {
            "username": "dave",
            "password_hash": auth_module.hash_password("davepass"),
            "is_admin": False,
            "allowed_roles": [],
            "theme": "auto",
        }
    )
    users_module.save_users(dave_data)
    # No _insert_db_user — startup migration inserts dave from JSON on first request.

    dave_csrf = _login(app_client, "dave", "davepass")
    resp = app_client.delete("/api/admin/tokens/1", headers={"X-CSRF-Token": dave_csrf})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Timezone serialization (regression: SQLite drops tzinfo, frontend needs UTC marker)
# ---------------------------------------------------------------------------


def test_serialized_token_timestamps_carry_utc_marker(client_with_admin):
    """Spec: every serialized timestamp must end with 'Z' or '+00:00' so the
    browser parses it as UTC. SQLite strips tzinfo on storage, so naive
    datetimes round-trip — _serialize_token must add the suffix back.
    Without this, the UI showed 'Last used 2 hours ago' right after use on
    a UTC+2 browser.
    """
    client, csrf = client_with_admin

    # Create + read back a token; created_at should be UTC-marked.
    create = client.post(
        "/api/me/tokens",
        json={"name": "tz-check", "is_read_only": True, "max_read_bytes": 1024},
        headers={"X-CSRF-Token": csrf},
    )
    assert create.status_code == 200
    body = create.json()
    assert body["created_at"].endswith("Z") or body["created_at"].endswith("+00:00"), (
        f"created_at='{body['created_at']}' must carry a UTC marker"
    )
    assert body["last_used_at"] is None
    assert body["revoked_at"] is None

    # last_used_at is set on the next MCP-style auth lookup; emulate via touch_last_used.
    from another_s3_manager import api_tokens as svc

    token_id = body["id"]
    svc.touch_last_used(token_id, throttle_seconds=0)

    listing = client.get("/api/me/tokens").json()
    matched = next((t for t in listing["tokens"] if t["id"] == token_id), None)
    assert matched is not None
    assert matched["last_used_at"] is not None
    assert matched["last_used_at"].endswith("Z") or matched["last_used_at"].endswith("+00:00")
