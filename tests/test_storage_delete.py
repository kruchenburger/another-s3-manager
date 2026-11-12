"""Storage refreshes destructive access and reports actual per-key outcomes."""

from unittest.mock import Mock

import pytest

from another_s3_manager import access, config, s3_client, users
from another_s3_manager.errors import S3OperationError


def test_batch_errors_win_and_missing_results_fail():
    client = Mock()
    client.delete_objects.return_value = {
        "Deleted": [{"Key": "ok"}, {"Key": "denied"}, {"Key": "unexpected"}],
        "Errors": [{"Key": "denied", "Code": "AccessDenied"}],
    }
    deleted, failed = s3_client.delete_keys_batch(client, "bucket", ["ok", "denied", "missing"])
    assert deleted == {"ok"}
    assert failed == {"denied": "AccessDenied", "missing": "STORAGE_ERROR"}
    client.delete_objects.assert_called_once_with(
        Bucket="bucket", Delete={"Objects": [{"Key": "ok"}, {"Key": "denied"}, {"Key": "missing"}], "Quiet": False}
    )


@pytest.mark.parametrize(
    "change,code",
    [
        ("grant", "role_not_allowed"),
        ("demote", "role_not_allowed"),
        ("delete", "role_not_allowed"),
        ("bucket", "bucket_not_allowed"),
    ],
)
def test_current_access_ignores_stale_identity(change, code):
    user = users.create_user(
        "deleter", "password123", is_admin=change == "demote", allowed_roles=["Default"] if change != "demote" else []
    )
    if change == "grant":
        users.update_user("deleter", allowed_roles=[])
    elif change == "demote":
        users.update_user("deleter", is_admin=False)
    elif change == "delete":
        users.delete_user("deleter")
    else:
        cfg = config.load_config()
        cfg["roles"][0]["allowed_buckets"] = ["other"]
        config.save_config(cfg)
    with pytest.raises(access.AccessDenied) as caught:
        s3_client.require_current_destructive(user, "Default", "bucket")
    assert caught.value.code == code


def test_directory_partial_delete_continues_and_counts(moto_s3, monkeypatch):
    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="partial-bucket")
    keys = [f"dir/{i:04}" for i in range(1001)]
    # Stub enumeration/HTTP results rather than create a thousand remote objects.
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = [{"Contents": [{"Key": key} for key in keys]}]
    client.delete_objects.side_effect = [
        {"Deleted": [{"Key": key} for key in keys[:999]], "Errors": [{"Key": keys[999], "Code": "AccessDenied"}]},
        {"Deleted": [{"Key": keys[1000]}]},
    ]
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
    from another_s3_manager.metrics import s3_objects_total

    metric = s3_objects_total.labels(role="Default", bucket="partial-bucket", operation="delete")
    before = metric._value.get()
    with pytest.raises(S3OperationError) as caught:
        s3_client.delete_object_for_role("Default", "partial-bucket", "dir/", user)
    error = caught.value
    assert error.code == "PARTIAL_DELETE"
    assert error.deleted_count == 1000
    assert error.failed == {"dir/0999": "AccessDenied"}
    assert str(error) == "Deleted 1000 of 1001 objects; 1 could not be deleted (first: dir/0999: AccessDenied)"
    assert metric._value.get() - before == 1000
    assert client.delete_objects.call_count == 2


@pytest.mark.parametrize(
    "field",
    ["type", "endpoint_url", "region", "role_arn", "profile_name", "account_id", "access_key_id", "addressing_style"],
)
def test_storage_fingerprint_tracks_target_only(field):
    role = {"name": "role", "type": "default"}
    original = s3_client.storage_target_fingerprint(role)
    assert s3_client.storage_target_fingerprint({**role, field: "changed"}) != original
    assert (
        s3_client.storage_target_fingerprint(
            {**role, "secret_access_key": "secret", "allow_delete": False, "description": "edited"}
        )
        == original
    )
    assert s3_client.storage_target_fingerprint(dict(reversed(list(role.items())))) == original


def test_cached_client_changes_with_storage_target(monkeypatch):
    built = []

    def build(role):
        client = Mock()
        built.append((dict(role), client))
        return client

    monkeypatch.setattr(s3_client, "_create_s3_client_from_role", build)
    first = s3_client.get_s3_client("Default")
    cfg = config.load_config()
    cfg["roles"][0]["endpoint_url"] = "http://new.test"
    config.save_config(cfg)
    second = s3_client.get_s3_client("Default")
    assert second is not first
    assert len(built) == 2
    assert built[1][0]["endpoint_url"] == "http://new.test"
    assert s3_client.get_s3_client("Default") is second
    s3_client.invalidate_s3_client("Default")
    assert s3_client.get_s3_client("Default") is not second


@pytest.mark.parametrize("path", ["job", "cleanup"])
def test_job_paths_use_current_destructive_helper(moto_s3, monkeypatch, path):
    from another_s3_manager import move_jobs as moves

    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="job-helper")
    etag = moto_s3.put_object(Bucket="job-helper", Key="file", Body=b"x")["ETag"]
    job = moves.Job("helper", moves.owner_identity(user), "Default", "job-helper", "op", "hash")
    helper = Mock(wraps=s3_client.require_current_destructive)
    monkeypatch.setattr(s3_client, "require_current_destructive", helper)
    if path == "job":
        assert moves.delete_batch(job, ["file"]) == {"file"}
    else:
        registry = moves.MoveRegistry()
        job.state = "failed_copy"
        job.copied = {"file": etag}
        registry.jobs[job.id] = job
        assert registry.cleanup(job.id, user)["removed"] == 1
    assert helper.call_args.args[0]["id"] == user["id"]
    assert helper.call_args.args[1:] == ("Default", "job-helper")
    assert not moto_s3.list_objects_v2(Bucket="job-helper").get("Contents")


def test_target_change_between_delete_batches_stops_next_batch(moto_s3):
    from another_s3_manager import move_jobs as moves
    from another_s3_manager.errors import MoveError

    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="pinned-batches")
    for key in ("first", "second"):
        moto_s3.put_object(Bucket="pinned-batches", Key=key, Body=b"keep")
    job = moves.Job("pinned", moves.owner_identity(user), "Default", "pinned-batches", "op", "hash")
    job.delete_started = True
    assert moves.delete_batch(job, ["first"]) == {"first"}
    cfg = config.load_config()
    cfg["roles"][0]["endpoint_url"] = "http://changed.test"
    config.save_config(cfg)
    with pytest.raises(MoveError) as caught:
        moves.delete_batch(job, ["second"])
    assert caught.value.code == "ROLE_CHANGED"
    assert moto_s3.get_object(Bucket="pinned-batches", Key="second")["Body"].read() == b"keep"


def test_cleanup_stops_on_target_change_after_partial_cleanup(moto_s3, monkeypatch):
    from another_s3_manager import move_jobs as moves

    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="pinned-cleanup")
    copied = {
        key: moto_s3.put_object(Bucket="pinned-cleanup", Key=key, Body=b"keep")["ETag"] for key in ("first", "second")
    }
    job = moves.Job("cleanup-pinned", moves.owner_identity(user), "Default", "pinned-cleanup", "op", "hash")
    job.state = "failed_copy"
    job.copied = copied
    registry = moves.MoveRegistry()
    registry.jobs[job.id] = job
    original = moto_s3.delete_objects

    def delete_and_change(**kwargs):
        result = original(**kwargs)
        cfg = config.load_config()
        cfg["roles"][0]["endpoint_url"] = "http://changed.test"
        config.save_config(cfg)
        return result

    monkeypatch.setattr(moto_s3, "delete_objects", delete_and_change)
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: moto_s3)
    result = registry.cleanup(job.id, user)
    assert result["removed"] == 1
    assert result["remaining"] == 1
    assert result["stopped_reason"] == "ROLE_CHANGED"
    assert result["failures"][0]["code"] == "ROLE_CHANGED"
    assert moto_s3.get_object(Bucket="pinned-cleanup", Key="second")["Body"].read() == b"keep"
