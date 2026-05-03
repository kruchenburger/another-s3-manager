"""Unit tests for the validate_password pure function."""

import json

import pytest

from another_s3_manager.utils import validate_password
from tests.test_main import create_user, login

# Sensible default policy used in most cases
DEFAULT_POLICY = {
    "password_min_length": 8,
    "password_min_uppercase": 1,
    "password_min_lowercase": 1,
    "password_min_digits": 1,
    "password_min_special": 0,
}


def test_strong_password_passes_default_policy():
    assert validate_password("Abcdef12", DEFAULT_POLICY) == []


def test_too_short_fails():
    failures = validate_password("Ab1", DEFAULT_POLICY)
    assert len(failures) == 1
    assert "password_min_length" in failures[0]
    assert "need 8" in failures[0]
    assert "got 3" in failures[0]


def test_missing_uppercase_fails():
    failures = validate_password("abcdef12", DEFAULT_POLICY)
    assert any("password_min_uppercase" in f for f in failures)


def test_missing_lowercase_fails():
    failures = validate_password("ABCDEF12", DEFAULT_POLICY)
    assert any("password_min_lowercase" in f for f in failures)


def test_missing_digit_fails():
    failures = validate_password("Abcdefgh", DEFAULT_POLICY)
    assert any("password_min_digits" in f for f in failures)


def test_special_required_when_policy_demands():
    policy = {**DEFAULT_POLICY, "password_min_special": 1}
    failures = validate_password("Abcdef12", policy)
    assert any("password_min_special" in f for f in failures)
    assert validate_password("Abcdef12!", policy) == []


def test_zero_means_not_required():
    policy = {
        "password_min_length": 0,
        "password_min_uppercase": 0,
        "password_min_lowercase": 0,
        "password_min_digits": 0,
        "password_min_special": 0,
    }
    # Even an empty string passes a fully-disabled policy
    assert validate_password("", policy) == []
    assert validate_password("anything", policy) == []


def test_multiple_failures_reported_together():
    failures = validate_password("ab", DEFAULT_POLICY)
    # Too short, no uppercase, no digit — at least 3 failures
    assert len(failures) >= 3


def test_missing_policy_key_treated_as_zero():
    """When a policy key is absent, treat it as not required (default 0)."""
    sparse_policy = {"password_min_length": 8}
    # Has 8 chars; no other requirements
    assert validate_password("abcdefgh", sparse_policy) == []


def test_unicode_letters_count_as_lowercase_or_uppercase():
    """Unicode letters should match Python's str.islower/.isupper, not just ASCII."""
    policy = {
        "password_min_length": 4,
        "password_min_uppercase": 1,
        "password_min_lowercase": 1,
        "password_min_digits": 0,
        "password_min_special": 0,
    }
    # Cyrillic uppercase + Cyrillic lowercase
    assert validate_password("Абвг", policy) == []


def test_higher_minimums_require_multiple_chars_of_class():
    """min_uppercase: 2 requires 2 uppercase letters."""
    policy = {**DEFAULT_POLICY, "password_min_uppercase": 2}
    failures = validate_password("Abcdef12", policy)  # only 1 uppercase
    assert any("password_min_uppercase" in f for f in failures)
    assert validate_password("ABcdef12", policy) == []


def test_special_chars_definition():
    """Special = anything not alphanumeric. Spaces and punctuation both count."""
    policy = {
        "password_min_length": 5,
        "password_min_uppercase": 0,
        "password_min_lowercase": 0,
        "password_min_digits": 0,
        "password_min_special": 1,
    }
    # Punctuation — clearly special
    assert validate_password("aaaa!", policy) == []
    # Space — also counts as special
    assert validate_password("aa aa", policy) == []
    # All letters — fails
    assert any("password_min_special" in f for f in validate_password("aaaaa", policy))


@pytest.fixture
def isolated_config(monkeypatch, tmp_path):
    """Point CONFIG_FILE at a fresh temp file and reload the config module."""
    cfg_path = tmp_path / "config.json"
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))
    # Force constants reload so CONFIG_FILE picks up the new env
    import importlib

    import another_s3_manager.constants as constants_module

    importlib.reload(constants_module)
    import another_s3_manager.config as config_module

    importlib.reload(config_module)
    return cfg_path, config_module


def test_default_config_includes_password_policy_fields(isolated_config):
    """A fresh config (file does not exist) gets default password policy fields."""
    _, config_module = isolated_config
    cfg = config_module._get_default_config()
    assert cfg["password_min_length"] == 8
    assert cfg["password_min_uppercase"] == 1
    assert cfg["password_min_lowercase"] == 1
    assert cfg["password_min_digits"] == 1
    assert cfg["password_min_special"] == 0


def test_migration_adds_missing_password_policy_fields(isolated_config):
    """Loading an existing config without policy fields auto-populates defaults."""
    cfg_path, config_module = isolated_config
    legacy = {
        "roles": [{"name": "Default", "type": "default"}],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
        "disable_deletion": False,
    }
    cfg_path.write_text(json.dumps(legacy))
    cfg = config_module.load_config(force_reload=True)
    assert cfg["password_min_length"] == 8
    assert cfg["password_min_uppercase"] == 1
    assert cfg["password_min_lowercase"] == 1
    assert cfg["password_min_digits"] == 1
    assert cfg["password_min_special"] == 0


def test_migration_preserves_existing_password_policy_values(isolated_config):
    """If config already has policy fields, migration does NOT overwrite them."""
    cfg_path, config_module = isolated_config
    existing = {
        "roles": [{"name": "Default", "type": "default"}],
        "items_per_page": 200,
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
        "disable_deletion": False,
        "password_min_length": 12,
        "password_min_uppercase": 2,
        "password_min_lowercase": 0,
        "password_min_digits": 0,
        "password_min_special": 3,
    }
    cfg_path.write_text(json.dumps(existing))
    cfg = config_module.load_config(force_reload=True)
    assert cfg["password_min_length"] == 12
    assert cfg["password_min_uppercase"] == 2
    assert cfg["password_min_lowercase"] == 0
    assert cfg["password_min_digits"] == 0
    assert cfg["password_min_special"] == 3


# ---------------------------------------------------------------------------
# Integration tests — wired endpoints (Task 3)
# ---------------------------------------------------------------------------


def test_change_my_password_rejects_weak_password(app_client):
    """PUT /api/me/password returns 422 with structured detail when policy fails."""
    create_user("alice", password="OldPass123", is_admin=False)
    _, headers = login(app_client, username="alice", password="OldPass123")
    response = app_client.put(
        "/api/me/password",
        json={"current_password": "OldPass123", "new_password": "weak"},
        headers=headers,
    )
    assert response.status_code == 422, response.text
    body = response.json()
    detail = body["detail"]
    assert detail["error"] == "Password does not meet policy"
    assert isinstance(detail["failed_requirements"], list)
    assert any("password_min_length" in f for f in detail["failed_requirements"])


def test_change_my_password_accepts_strong_password(app_client):
    """A password meeting all default-policy requirements still works."""
    create_user("alice", password="OldPass123", is_admin=False)
    _, headers = login(app_client, username="alice", password="OldPass123")
    response = app_client.put(
        "/api/me/password",
        json={"current_password": "OldPass123", "new_password": "NewPass456"},
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_admin_create_user_rejects_weak_password(app_client):
    """POST /api/admin/users returns 422 when the password fails policy."""
    _, headers = login(app_client)
    response = app_client.post(
        "/api/admin/users",
        data={"username": "weakpw", "password": "weak", "is_admin": "false"},
        headers=headers,
    )
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "Password does not meet policy"


def test_admin_create_user_accepts_strong_password(app_client):
    """A strong password creates the user successfully."""
    _, headers = login(app_client)
    response = app_client.post(
        "/api/admin/users",
        data={"username": "strongpw", "password": "Strong123", "is_admin": "false"},
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_admin_reset_user_password_rejects_weak(app_client):
    """PUT /api/admin/users/{u}/password returns 422 when password fails policy."""
    create_user("victim", password="OldPass123", is_admin=False)
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/victim/password",
        json={"password": "weak"},
        headers=headers,
    )
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "Password does not meet policy"


def test_admin_reset_user_password_accepts_strong(app_client):
    create_user("victim", password="OldPass123", is_admin=False)
    _, headers = login(app_client)
    response = app_client.put(
        "/api/admin/users/victim/password",
        json={"password": "NewStrong456"},
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_get_config_includes_password_policy_fields(app_client):
    """GET /api/config returns the 5 policy fields so frontend can render the checklist."""
    _, headers = login(app_client)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    for field in (
        "password_min_length",
        "password_min_uppercase",
        "password_min_lowercase",
        "password_min_digits",
        "password_min_special",
    ):
        assert field in body, f"GET /api/config missing {field}"


def test_post_config_persists_password_policy_fields(app_client):
    """POST /api/config saves the 5 policy fields and they round-trip via GET."""
    _, headers = login(app_client)
    payload = {
        "roles": [{"name": "Default", "type": "default"}],
        "password_min_length": 10,
        "password_min_uppercase": 2,
        "password_min_lowercase": 1,
        "password_min_digits": 1,
        "password_min_special": 1,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == 200, response.text

    fresh = app_client.get("/api/config", headers=headers).json()
    assert fresh["password_min_length"] == 10
    assert fresh["password_min_uppercase"] == 2
    assert fresh["password_min_special"] == 1


def test_post_config_rejects_out_of_range_policy(app_client):
    """POST /api/config returns 400 for policy values outside [0, 50]."""
    _, headers = login(app_client)
    payload = {
        "roles": [{"name": "Default", "type": "default"}],
        "password_min_length": 100,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == 400, response.text
    assert "password_min_length" in response.json()["detail"]
