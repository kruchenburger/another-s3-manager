import pytest

from another_s3_manager import access


@pytest.mark.parametrize(
    "policy,source,admin,disabled,expected",
    [
        ("all", "local", False, False, True),
        ("admins", "local", True, False, True),
        ("admins", "local", False, False, False),
        ("off", "local", True, False, False),
        ("all", "oidc", True, False, False),
        ("all", "local", True, True, False),
    ],
)
def test_local_login_policy(policy, source, admin, disabled, expected):
    assert (
        access.local_login_allowed({"auth_source": source, "is_admin": admin, "is_disabled": disabled}, policy)
        is expected
    )
