"""Tests for the per-user default role feature (Phase 6a-4)."""

from sqlalchemy import inspect

from another_s3_manager.database import get_engine


def _test_password_hash() -> str:
    """Bcrypt hash for password 'test-password-1A' — meets the default policy."""
    from another_s3_manager.auth import hash_password

    return hash_password("test-password-1A")


def _login_as(client, username: str) -> None:
    """Log in as the given user; sets the auth cookie + CSRF header on the test client."""
    login_response = client.post(
        "/api/login",
        data={"username": username, "password": "test-password-1A"},
    )
    assert login_response.status_code == 200, login_response.text
    # CSRF token is not in the login body — it lives in the JWT cookie and is
    # exposed only via /api/me (mirrors the pattern in test_main.py::login()).
    me_response = client.get("/api/me")
    assert me_response.status_code == 200, me_response.text
    csrf = me_response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf


def test_users_table_has_default_role_column():
    """Migration must add a nullable `default_role` column to `users`."""
    inspector = inspect(get_engine())
    columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "default_role" in columns, "default_role column missing from users table"
    assert columns["default_role"]["nullable"] is True, "default_role must be nullable"


def test_create_user_auto_sets_default_role_when_single_allowed_role(app_client):
    """create_user(allowed_roles=[X]) should set default_role=X automatically."""
    from another_s3_manager import users

    user = users.create_user(
        username="solo",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    assert user["default_role"] == "RoleA", user


def test_create_user_does_not_auto_set_default_role_when_multiple_allowed_roles(app_client):
    """Multiple roles → no auto-default; user must pick explicitly."""
    from another_s3_manager import users

    user = users.create_user(
        username="multi",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    assert user["default_role"] is None, user


def test_update_user_clears_default_role_when_no_longer_in_allowed_roles(app_client):
    """If admin removes the role that is the user's default, fall back to the first remaining."""
    from another_s3_manager import users

    users.create_user(
        username="shifter",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    users.update_user("shifter", default_role="RoleA")
    updated = users.update_user("shifter", allowed_roles=["RoleB", "RoleC"])
    assert updated["default_role"] == "RoleB", updated


def test_update_user_accepts_explicit_default_role(app_client):
    """update_user(default_role=X) sets the explicit choice."""
    from another_s3_manager import users

    users.create_user(
        username="picker",
        password_hash="hash-irrelevant",
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    updated = users.update_user("picker", default_role="RoleB")
    assert updated["default_role"] == "RoleB"


def test_api_me_returns_explicit_default_role_when_in_allowed(app_client):
    """If user.default_role is set AND is in allowed_roles → return it."""
    from another_s3_manager import users

    users.create_user(
        username="explicit",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    users.update_user("explicit", default_role="RoleB")

    _login_as(app_client, "explicit")
    response = app_client.get("/api/me")
    assert response.status_code == 200
    body = response.json()
    assert body["default_role"] == "RoleB", body


def test_api_me_falls_back_to_first_allowed_when_default_role_missing(app_client):
    """If user.default_role is NULL → return first of allowed_roles."""
    from another_s3_manager import users

    users.create_user(
        username="implicit",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    _login_as(app_client, "implicit")
    response = app_client.get("/api/me")
    assert response.status_code == 200
    body = response.json()
    assert body["default_role"] == "RoleA", body


def test_api_me_returns_null_default_role_when_no_allowed_roles(app_client):
    """User with no allowed roles → default_role is null."""
    from another_s3_manager import users

    users.create_user(
        username="orphan",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=[],
    )
    _login_as(app_client, "orphan")
    response = app_client.get("/api/me")
    assert response.status_code == 200
    body = response.json()
    assert body["default_role"] is None, body


def test_put_my_default_role_sets_explicit_value(app_client):
    """PUT /api/me/default-role with a valid role updates the user's record."""
    from another_s3_manager import users

    users.create_user(
        username="picker_e",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    _login_as(app_client, "picker_e")

    response = app_client.put("/api/me/default-role", json={"role": "RoleB"})
    assert response.status_code == 200, response.text

    me = app_client.get("/api/me").json()
    assert me["default_role"] == "RoleB"


def test_put_my_default_role_rejects_role_not_in_allowed(app_client):
    """PUT /api/me/default-role with a role outside allowed_roles returns 400."""
    from another_s3_manager import users

    users.create_user(
        username="picker_x",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA"],
    )
    _login_as(app_client, "picker_x")

    response = app_client.put("/api/me/default-role", json={"role": "RoleZ"})
    assert response.status_code == 400, response.text


def test_put_my_default_role_null_clears_explicit_choice(app_client):
    """PUT with role=null clears the explicit choice (fallback to first allowed)."""
    from another_s3_manager import users

    users.create_user(
        username="picker_n",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    users.update_user("picker_n", default_role="RoleB")
    _login_as(app_client, "picker_n")

    response = app_client.put("/api/me/default-role", json={"role": None})
    assert response.status_code == 200, response.text

    me = app_client.get("/api/me").json()
    # Fallback to first allowed.
    assert me["default_role"] == "RoleA"


def test_startup_migration_imports_legacy_global_default_role(app_client, monkeypatch, tmp_path):
    """First boot copies legacy config.default_role into compatible user records."""
    from another_s3_manager import config as config_module
    from another_s3_manager import main as main_module
    from another_s3_manager import users

    # Pre-create a user with NULL default_role and RoleA in allowed_roles.
    users.create_user(
        username="legacy",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    # Force NULL (create_user auto-sets when len==1; explicitly clear here for safety).
    users.update_user("legacy", default_role=None)

    # Inject a config.json with a global default_role of "RoleA".
    cfg = config_module.load_config(force_reload=True)
    cfg["default_role"] = "RoleA"
    cfg.setdefault("roles", []).append({"name": "RoleA", "type": "default"})
    cfg.setdefault("roles", []).append({"name": "RoleB", "type": "default"})
    config_module.save_config(cfg)

    # Trigger the startup migration manually.
    main_module._migrate_legacy_default_role()

    # Verify the user now has default_role=RoleA.
    me = users.get_user_by_username("legacy")
    assert me["default_role"] == "RoleA"


def test_startup_migration_is_idempotent_and_skips_users_with_explicit_default(app_client):
    """Re-running the migration does NOT overwrite users who already have a value."""
    from another_s3_manager import config as config_module
    from another_s3_manager import main as main_module
    from another_s3_manager import users

    users.create_user(
        username="picky",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    users.update_user("picky", default_role="RoleB")

    cfg = config_module.load_config(force_reload=True)
    cfg["default_role"] = "RoleA"
    cfg.setdefault("roles", []).extend(
        [
            {"name": "RoleA", "type": "default"},
            {"name": "RoleB", "type": "default"},
        ]
    )
    config_module.save_config(cfg)

    main_module._migrate_legacy_default_role()
    main_module._migrate_legacy_default_role()  # twice — must be idempotent

    me = users.get_user_by_username("picky")
    assert me["default_role"] == "RoleB", "user's explicit choice must be preserved"


# ---------------------------------------------------------------------------
# Pure helper unit tests — no app_client fixture needed.
# ---------------------------------------------------------------------------


def test_compute_default_role_returns_explicit_when_still_allowed():
    from another_s3_manager.users import compute_default_role

    assert compute_default_role("RoleB", ["RoleA", "RoleB", "RoleC"]) == "RoleB"


def test_compute_default_role_falls_back_to_first_when_explicit_invalid():
    from another_s3_manager.users import compute_default_role

    assert compute_default_role("RoleZ", ["RoleA", "RoleB"]) == "RoleA"


def test_compute_default_role_falls_back_to_first_when_no_explicit():
    from another_s3_manager.users import compute_default_role

    assert compute_default_role(None, ["RoleA", "RoleB"]) == "RoleA"


def test_compute_default_role_returns_none_when_no_allowed_roles():
    from another_s3_manager.users import compute_default_role

    assert compute_default_role("RoleA", []) is None
    assert compute_default_role(None, []) is None


def test_validate_default_role_choice_accepts_none_and_in_set():
    from another_s3_manager.users import validate_default_role_choice

    # Neither call should raise.
    validate_default_role_choice(None, ["RoleA"])
    validate_default_role_choice("RoleA", ["RoleA", "RoleB"])


def test_validate_default_role_choice_rejects_role_not_in_set():
    import pytest

    from another_s3_manager.users import validate_default_role_choice

    with pytest.raises(ValueError, match="RoleZ"):
        validate_default_role_choice("RoleZ", ["RoleA", "RoleB"])


def test_save_users_resets_default_role_when_role_removed(app_client):
    """save_users (admin bulk-upsert path) must reset a now-orphaned default_role.

    Regression: before this fix, save_users left a dangling default_role in
    the DB when an admin removed the role from a user's allowed_roles via
    PUT /api/admin/users/{username}. /api/me masked the dangling value with
    its computed fallback, but the DB row was inconsistent.
    """
    from another_s3_manager import users

    users.create_user(
        username="dangler",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    users.update_user("dangler", default_role="RoleA")

    # Admin bulk-upsert removes RoleA from the user's allowed_roles.
    users.save_users(
        {
            "users": [
                {
                    "username": "dangler",
                    "password_hash": _test_password_hash(),
                    "is_admin": False,
                    "theme": "auto",
                    "allowed_roles": ["RoleB"],
                }
            ]
        }
    )

    me = users.get_user_by_username("dangler")
    assert me["default_role"] == "RoleB", me


def test_save_users_preserves_default_role_when_still_allowed(app_client):
    """save_users must NOT touch default_role if the current value is still valid."""
    from another_s3_manager import users

    users.create_user(
        username="keeper",
        password_hash=_test_password_hash(),
        is_admin=False,
        allowed_roles=["RoleA", "RoleB"],
    )
    users.update_user("keeper", default_role="RoleB")

    # allowed_roles still contains RoleB — default must survive.
    users.save_users(
        {
            "users": [
                {
                    "username": "keeper",
                    "password_hash": _test_password_hash(),
                    "is_admin": False,
                    "theme": "auto",
                    "allowed_roles": ["RoleB", "RoleC"],
                }
            ]
        }
    )

    me = users.get_user_by_username("keeper")
    assert me["default_role"] == "RoleB", me
