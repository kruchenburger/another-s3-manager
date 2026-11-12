import pytest

from another_s3_manager.access import AccessDenied, require_bucket
from another_s3_manager.access.policies import bucket_is_allowed


@pytest.mark.parametrize(
    "role_config,expected",
    [
        ({}, True),
        ({"allowed_buckets": []}, True),
        ({"allowed_buckets": None}, True),
        ({"allowed_buckets": ["b"]}, True),
        ({"allowed_buckets": ["other"]}, False),
    ],
)
def test_bucket_allowlist_is_unrestricted_only_when_empty(role_config, expected):
    assert bucket_is_allowed(role_config, "b") is expected


@pytest.mark.parametrize("user", [{"is_admin": True}, {"allowed_roles": ["role"]}])
def test_bucket_denial_has_storage_compatible_message_even_for_admin(user):
    with pytest.raises(AccessDenied) as caught:
        require_bucket("role", "private", user, {"roles": [{"name": "role", "allowed_buckets": ["public"]}]})
    assert caught.value.code == "bucket_not_allowed"
    assert str(caught.value) == "bucket 'private' not in allowed_buckets for role 'role'"


def test_allowed_bucket_passes_after_separate_role_check():
    assert require_bucket("role", "public", {}, {"roles": [{"name": "role", "allowed_buckets": ["public"]}]}) is None
