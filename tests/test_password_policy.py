"""Unit tests for the validate_password pure function."""

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
