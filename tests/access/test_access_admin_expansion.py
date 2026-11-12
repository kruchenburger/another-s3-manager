import pytest

from another_s3_manager.access import allowed_roles, require_role


@pytest.mark.parametrize(
    "user,expected",
    [({"is_admin": True}, ["b", "a", "b"]), ({"allowed_roles": ["a", "gone", "b"]}, ["a", "b"]), ({}, [])],
)
def test_role_expansion_uses_config_names_and_preserves_order(user, expected):
    config = {"roles": [{"name": "b"}, {}, {"name": ""}, {"name": "a"}, {"name": "b"}]}
    assert allowed_roles(user, config) == expected


def test_admin_may_use_unknown_role_before_storage_lookup():
    assert require_role("unknown", {"is_admin": True}, {}) == "unknown"
