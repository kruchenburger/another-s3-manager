"""The destructive policy composes the existing Access rules in order."""

import pytest

from another_s3_manager import access


@pytest.mark.parametrize(
    "user,roles,disabled,code",
    [
        ({"allowed_roles": []}, [{"name": "storage", "allow_delete": False}], True, "role_not_allowed"),
        (
            {"allowed_roles": ["storage"]},
            [{"name": "storage", "allowed_buckets": ["other"]}],
            True,
            "bucket_not_allowed",
        ),
        ({"allowed_roles": ["storage"]}, [{"name": "storage"}], True, "DELETION_DISABLED"),
        ({"is_admin": True}, [{"name": "storage", "allow_delete": False}], False, "DELETION_DISABLED_FOR_ROLE"),
        ({"is_admin": True}, [], False, "role_not_found"),
    ],
)
def test_destructive_denial_order(monkeypatch, user, roles, disabled, code):
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    with pytest.raises(access.AccessDenied) as caught:
        access.require_destructive(user, "storage", "bucket", {"roles": roles, "disable_deletion": disabled})
    assert caught.value.code == code


def test_destructive_uses_passed_grants_and_config(monkeypatch):
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    user = {"allowed_roles": ["storage"]}
    cfg = {"roles": [{"name": "storage", "allowed_buckets": ["bucket"]}]}
    assert access.require_destructive(user, "storage", "bucket", cfg) is None
    with pytest.raises(access.AccessDenied) as caught:
        access.require_destructive({"allowed_roles": []}, "storage", "bucket", cfg)
    assert caught.value.code == "role_not_allowed"
    assert access.require_destructive({"is_admin": True}, "storage", "bucket", cfg) is None
    cfg["roles"][0]["allowed_buckets"] = ["other"]
    with pytest.raises(access.AccessDenied) as caught:
        access.require_destructive(user, "storage", "bucket", cfg)
    assert caught.value.code == "bucket_not_allowed"
