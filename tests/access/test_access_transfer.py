"""Transfers require both buckets, independently of deletion permissions."""

import pytest

from another_s3_manager import access


@pytest.mark.parametrize(
    "grants,buckets,code",
    [
        ([], ["source", "dest"], "role_not_allowed"),
        (["role"], ["dest"], "bucket_not_allowed"),
        (["role"], ["source"], "bucket_not_allowed"),
    ],
)
def test_transfer_denies_missing_access(grants, buckets, code):
    with pytest.raises(access.AccessDenied) as caught:
        access.require_transfer(
            {"allowed_roles": grants},
            "role",
            "source",
            "dest",
            {"roles": [{"name": "role", "allowed_buckets": buckets}]},
        )
    assert caught.value.code == code


def test_transfer_expands_admin_roles():
    access.require_transfer(
        {"is_admin": True},
        "role",
        "source",
        "dest",
        {"roles": [{"name": "role", "allowed_buckets": ["source", "dest"]}]},
    )


def test_transfer_ignores_deletion_disabled(monkeypatch):
    monkeypatch.setenv("DISABLE_DELETION", "true")
    access.require_transfer(
        {"allowed_roles": ["role"]},
        "role",
        "source",
        "dest",
        {"disable_deletion": True, "roles": [{"name": "role", "allow_delete": False}]},
    )
