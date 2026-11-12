from unittest.mock import Mock

import pytest

from another_s3_manager import access as service
from another_s3_manager import move_jobs
from another_s3_manager.access import AccessDenied
from another_s3_manager.errors import MoveError


@pytest.mark.parametrize(
    "source,code,expected,message",
    [
        ("require_delete", "DELETION_DISABLED", "DELETION_DISABLED", "Deletion is disabled by the administrator."),
        (
            "require_delete",
            "DELETION_DISABLED_FOR_ROLE",
            "DELETION_DISABLED_FOR_ROLE",
            "Deleting is turned off for this role. Partial copies stay at the destination.",
        ),
        ("require_role", "role_required", "ACCESS_DENIED", "Access to this storage location is not allowed."),
        ("require_role", "role_not_allowed", "ACCESS_DENIED", "Access to this storage location is not allowed."),
        ("require_bucket", "bucket_not_allowed", "ACCESS_DENIED", "Access to this storage location is not allowed."),
        (
            "require_delete",
            "deletion_disabled",
            "DELETION_DISABLED",
            "Deletion is disabled by the administrator.",
        ),
    ],
)
def test_move_maps_access_denials_without_exposing_policy_messages(monkeypatch, source, code, expected, message):
    # The destructive branch delegates to Storage's fresh-state helper, which calls Access;
    # each Access denial is raised from there and must map through the job table.
    monkeypatch.setattr(service, source, Mock(side_effect=AccessDenied(code, "private policy details")))
    monkeypatch.setattr(
        move_jobs.s3_client,
        "require_current_destructive",
        lambda user, role, bucket, **kwargs: getattr(service, source)(),
    )
    with pytest.raises(MoveError) as caught:
        move_jobs.require_access({"is_admin": True}, "Default", "b", deleting=True)
    assert caught.value.code == expected
    assert caught.value.http_status == 403
    assert str(caught.value) == message


@pytest.mark.parametrize(
    "role,code,message",
    [
        (None, "ROLE_REQUIRED", "A storage role is required."),
        (" ", "ROLE_REQUIRED", "A storage role is required."),
        ("x" * 1025, "INVALID_REQUEST", "The request is invalid."),
        ("gone", "ROLE_NOT_FOUND", "The storage role does not exist."),
    ],
)
def test_move_request_guards_precede_access_policy(monkeypatch, role, code, message):
    policy = Mock(side_effect=AssertionError("Access must not run before request guards"))
    monkeypatch.setattr(service, "require_role", policy)
    # Role existence is a request guard only on the non-destructive branch; for deletes
    # the check order lives in Access (see test_destructive_role_denial_precedes_role_existence).
    with pytest.raises(MoveError) as caught:
        move_jobs.require_access({"is_admin": True}, role, "b", deleting=code != "ROLE_NOT_FOUND")
    assert caught.value.code == code
    assert caught.value.http_status == 400
    assert str(caught.value) == message
    policy.assert_not_called()
