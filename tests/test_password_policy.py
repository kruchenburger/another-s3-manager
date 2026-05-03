"""Unit tests for the validate_password pure function."""

import json

import pytest

from another_s3_manager.utils import validate_password

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
