import uuid

import pytest
from botocore.exceptions import ClientError

from another_s3_manager import move_jobs as moves
from another_s3_manager.errors import MoveError


@pytest.fixture
def storage(moto_s3):
    from another_s3_manager import users

    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="move-bucket")
    yield moto_s3, user
    for job in list(moves.registry.jobs.values()):
        if job.future:
            job.future.result(timeout=10)
    moves.registry.jobs.clear()


def request(items=None, destination="dest", **kwargs):
    return moves.MoveRequest(
        items=items or [{"path": "source/file", "kind": "file"}], destination=destination, **kwargs
    )


def start(user, req):
    return moves.registry.start(user, "Default", "move-bucket", req, str(uuid.uuid4()))


def test_move_file_and_parent_marker(storage):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "done"
    assert s3.get_object(Bucket="move-bucket", Key="dest/file")["Body"].read() == b"abc"
    assert {x["Key"] for x in s3.list_objects_v2(Bucket="move-bucket")["Contents"]} == {"source/", "dest/file"}


@pytest.mark.parametrize(
    "items",
    [
        [{"path": "a/x", "kind": "file"}, {"path": "b/x", "kind": "file"}],
        [{"path": "a", "kind": "folder"}, {"path": "a/x", "kind": "file"}],
        [{"path": "a/x", "kind": "file"}, {"path": "b/x", "kind": "folder"}],
        [{"path": "a/x", "kind": "file"}, {"path": "a/x", "kind": "file"}],
    ],
)
def test_plan_conflicts_before_storage(storage, items):
    _, user = storage
    with pytest.raises(MoveError) as error:
        moves.build_plan(user, "Default", "move-bucket", request(items))
    assert error.value.code == "PLAN_CONFLICT"


def test_existing_destination_and_same_location(storage):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    s3.put_object(Bucket="move-bucket", Key="dest/file/child", Body=b"abc")
    with pytest.raises(MoveError, match="destination"):
        moves.build_plan(user, "Default", "move-bucket", request())
    with pytest.raises(MoveError) as error:
        moves.build_plan(user, "Default", "move-bucket", request(destination="source"))
    assert error.value.code == "SAME_LOCATION"


def test_copy_failure_never_deletes(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")

    def fail(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "arn:aws:iam::123456789012 secret foreign-key"}}, "CopyObject"
        )

    monkeypatch.setattr(moves, "copy_entry", fail)
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "failed_copy"
    assert s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"abc"
    assert "arn:" not in str(job.snapshot())
    assert "foreign-key" not in str(job.snapshot())


def test_cap_stops_enumeration(storage, monkeypatch):
    s3, user = storage
    for name in ["a", "b", "c"]:
        s3.put_object(Bucket="move-bucket", Key="source/" + name, Body=b"x")
    monkeypatch.setattr(moves.config, "resolve_move_max_objects", lambda config=None: 1)
    with pytest.raises(MoveError) as error:
        moves.build_plan(user, "Default", "move-bucket", request([{"path": "source", "kind": "folder"}]))
    assert error.value.code == "TOO_MANY_OBJECTS"


@pytest.mark.parametrize(
    "change,code", [("changed", "SOURCE_CHANGED"), ("new", "NEW_IN_SOURCE"), ("gone", "SOURCE_CHANGED")]
)
def test_source_recheck(storage, monkeypatch, change, code):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.copy_entry

    def copy_then_change(*args):
        etag = original(*args)
        if change == "gone":
            s3.delete_object(Bucket="move-bucket", Key="source/file")
        else:
            s3.put_object(Bucket="move-bucket", Key="source/" + ("new" if change == "new" else "file"), Body=b"new")
        return etag

    monkeypatch.setattr(moves, "copy_entry", copy_then_change)
    job = start(user, request([{"path": "source", "kind": "folder"}]))
    job.future.result(timeout=10)
    assert job.state == "done_with_warnings"
    assert job.failures[0]["code"] == code
    assert s3.get_object(Bucket="move-bucket", Key="dest/source/file")["Body"].read() == b"abc"
    if change == "changed":
        assert s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"new"


def test_destination_appeared(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.copy_entry

    def appeared(*args):
        s3.put_object(Bucket="move-bucket", Key="dest/file", Body=b"foreign")
        return original(*args)

    monkeypatch.setattr(moves, "copy_entry", appeared)
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "failed_copy"
    assert job.failures[0]["code"] == "DESTINATION_APPEARED"
    assert s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"abc"


def test_per_key_delete_errors(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.s3_unit

    class Denied:
        def delete_objects(self, **kwargs):
            return {"Errors": [{"Key": "source/file", "Code": "AccessDenied", "Message": "private"}]}

    def unit(role, operation, callback):
        return callback(Denied()) if operation == "delete" else original(role, operation, callback)

    monkeypatch.setattr(moves, "s3_unit", unit)
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "failed_delete"
    assert job.removed == 0
    assert s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"abc"
    with pytest.raises(MoveError) as error:
        moves.registry.cleanup(job.id, user)
    assert error.value.code == "CLEANUP_UNSAFE"


@pytest.mark.parametrize(
    "size,expected",
    [
        (moves.MULTIPART_THRESHOLD, {}),
        (
            moves.MULTIPART_THRESHOLD + 1,
            {
                "ContentType": "text/plain",
                "ContentEncoding": "gzip",
                "Metadata": {"a": "b"},
                "StorageClass": "STANDARD_IA",
            },
        ),
    ],
)
def test_multipart_metadata(monkeypatch, size, expected):
    class Client:
        def __init__(self):
            self.copied = False

        def head_object(self, Bucket, Key):
            if Key == "dest" and not self.copied:
                raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
            return {
                "ETag": "etag",
                "ContentType": "text/plain",
                "ContentEncoding": "gzip",
                "Metadata": {"a": "b"},
                "StorageClass": "STANDARD_IA",
            }

        def copy(self, source, bucket, key, **kwargs):
            assert source == {"Bucket": "bucket", "Key": "source"}
            assert kwargs["ExtraArgs"] == expected
            self.copied = True

    client = Client()
    monkeypatch.setattr(moves.s3_client, "execute_with_s3_retry", lambda r, o, cb: cb(client))
    assert moves.copy_entry("Default", "bucket", moves.Entry("source", "dest", "old", size, None)) == "etag"


def test_cleanup_only_copied_unchanged_keys(storage, monkeypatch):
    s3, user = storage
    for name in ["a", "b", "c"]:
        s3.put_object(Bucket="move-bucket", Key="source/" + name, Body=b"abc")
    original = moves.copy_entry

    def copy_or_fail(role, bucket, entry):
        if entry.source.endswith("/c"):
            raise MoveError("AccessDenied", 403)
        return original(role, bucket, entry)

    monkeypatch.setattr(moves, "copy_entry", copy_or_fail)
    job = start(user, request([{"path": "source", "kind": "folder"}]))
    job.future.result(timeout=10)
    s3.put_object(Bucket="move-bucket", Key="dest/source/b", Body=b"changed")
    s3.put_object(Bucket="move-bucket", Key="dest/unrelated", Body=b"other")
    result = moves.registry.cleanup(job.id, user)
    assert result["removed"] == 1
    assert result["failures"][0]["code"] == "CLEANUP_CHANGED"
    assert s3.get_object(Bucket="move-bucket", Key="dest/source/b")["Body"].read() == b"changed"
    assert s3.get_object(Bucket="move-bucket", Key="dest/unrelated")["Body"].read() == b"other"


def test_access_revoked_before_delete(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.copy_entry

    def copy_revoke(*args):
        etag = original(*args)
        monkeypatch.setenv("DISABLE_DELETION", "true")
        return etag

    monkeypatch.setattr(moves, "copy_entry", copy_revoke)
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "cancelled_access"
    assert job.removed == 0


def test_parent_marker_failed(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.s3_unit

    def unit(role, op, callback):
        if op == "put":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")
        return original(role, op, callback)

    original_copy = moves.copy_entry

    def copy_then_break_marker(*args):
        result = original_copy(*args)
        monkeypatch.setattr(moves, "s3_unit", unit)
        return result

    monkeypatch.setattr(moves, "copy_entry", copy_then_break_marker)
    job = start(user, request())
    job.future.result(timeout=10)
    assert job.state == "done_with_warnings"
    assert job.failures[0]["code"] == "parent_marker_failed"


def test_retry_logs_do_not_expose_storage_messages(monkeypatch, caplog):
    class Client:
        def head_object(self, **kwargs):
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "arn:aws:iam::123456789012:role/secret token=RAW_TOKEN foreign-key",
                    }
                },
                "HeadObject",
            )

    monkeypatch.setattr(moves.s3_client, "get_s3_client", lambda role: Client())
    with pytest.raises(ClientError):
        moves.copy_entry("Default", "bucket", moves.Entry("source", "dest", "etag", 1, None))
    assert "RAW_TOKEN" not in caplog.text
    assert "arn:" not in caplog.text
    assert "foreign-key" not in caplog.text


def test_nested_file_folder_collision(storage):
    s3, user = storage
    for key in ["source/x", "source/x/y"]:
        s3.put_object(Bucket="move-bucket", Key=key, Body=b"x")
    with pytest.raises(MoveError) as error:
        moves.build_plan(user, "Default", "move-bucket", request([{"path": "source", "kind": "folder"}]))
    assert error.value.code == "PLAN_CONFLICT"


def test_retry_after_copy_head_expiry_redoes_key(storage, monkeypatch):
    from another_s3_manager import s3_client

    s3, _ = storage
    s3.put_object(Bucket="move-bucket", Key="source", Body=b"abc")
    calls = []

    class Client:
        def head_object(self, **kwargs):
            if kwargs["Key"] == "dest" and calls == ["copy"]:
                calls.append("expired")
                raise ClientError({"Error": {"Code": "ExpiredToken"}}, "HeadObject")
            return s3.head_object(**kwargs)

        def copy(self, *args, **kwargs):
            calls.append("copy")
            return s3.copy(*args, **kwargs)

    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: Client())
    monkeypatch.setattr(s3_client, "invalidate_s3_client", lambda role: None)
    monkeypatch.setattr(s3_client, "_clear_boto3_cached_credentials", lambda: None)
    assert moves.copy_entry("Default", "move-bucket", moves.Entry("source", "dest", "old", 3, None))
    assert calls == ["copy", "expired", "copy"]


def test_concurrent_idempotency(storage, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    entered, proceed = threading.Event(), threading.Event()
    original = moves.build_plan

    def blocked(*args):
        entered.set()
        assert proceed.wait(5)
        return original(*args)

    monkeypatch.setattr(moves, "build_plan", blocked)
    operation = str(uuid.uuid4())
    with ThreadPoolExecutor(2) as executor:
        first = executor.submit(moves.registry.start, user, "Default", "move-bucket", request(), operation)
        assert entered.wait(5)
        second = executor.submit(moves.registry.start, user, "Default", "move-bucket", request(), operation)
        proceed.set()
        assert first.result().id == second.result().id


def test_owner_and_idempotency_hash(storage):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    operation = str(uuid.uuid4())
    job = moves.registry.start(user, "Default", "move-bucket", request(), operation)
    job.future.result(timeout=10)
    assert moves.registry.start(user, "Default", "move-bucket", request(), operation).id == job.id
    with pytest.raises(MoveError) as error:
        moves.registry.start(user, "Default", "move-bucket", request(destination="other"), operation)
    assert error.value.code == "OPERATION_CONFLICT"
    with pytest.raises(MoveError) as error:
        moves.registry.get(job.id, {**user, "id": user["id"] + 1})
    assert error.value.http_status == 404


def test_registry_quotas_and_retention(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    for _ in range(10):
        moves.registry.preflight(user, "Default", "move-bucket", request())
    with pytest.raises(MoveError) as error:
        moves.registry.preflight(user, "Default", "move-bucket", request())
    assert error.value.code == "PREFLIGHT_LIMIT"
    registry = moves.MoveRegistry()
    for index in range(4):
        owner = user["id"] if index < 2 else user["id"] + 1
        job = moves.Job(str(index), owner, "Default", "move-bucket", str(index), "hash")
        registry.jobs[job.id] = job
    with pytest.raises(MoveError) as error:
        registry.start(user, "Default", "move-bucket", request(), "new")
    assert error.value.code == "TOO_MANY_JOBS"
    registry.jobs.clear()
    for index in range(202):
        job = moves.Job(
            str(index), user["id"], "Default", "move-bucket", str(index), "hash", state="done", finished_at=100 + index
        )
        registry.jobs[job.id] = job
    monkeypatch.setattr(moves.time, "monotonic", lambda: 3500)
    registry.prune()
    assert len(registry.jobs) == 200
    assert "0" not in registry.jobs
    monkeypatch.setattr(moves.time, "monotonic", lambda: 4000)
    registry.prune()
    assert not registry.jobs


def test_failure_storage_and_pagination():
    job = moves.Job("id", 1, "Default", "bucket", "op", "hash")
    for _ in range(1005):
        job.fail(MoveError("SOURCE_CHANGED"), "verify")
    assert len(job.failures) == 1000
    assert job.snapshot()["failures_total"] == 1005
    assert len(job.snapshot(900)["failures"]) == 100
    assert job.snapshot(900)["next_failures_offset"] is None


def test_access_rechecked_after_100_copies(storage, monkeypatch):
    _, user = storage
    entries = tuple(moves.Entry("source/" + str(i), "dest/" + str(i), "etag", 1, None) for i in range(101))
    job = moves.Job(
        "batch-check",
        user["id"],
        "Default",
        "move-bucket",
        "op",
        "hash",
        plan=moves.Plan(entries, (("source/", "dest/"),), ()),
    )
    original = moves.users.get_user_by_id
    checks = []

    def owner(user_id):
        checks.append(user_id)
        return original(user_id) if len(checks) == 1 else None

    monkeypatch.setattr(moves.users, "get_user_by_id", owner)
    monkeypatch.setattr(moves, "copy_entry", lambda *args: "copied-etag")
    moves.run_job(job)
    assert job.state == "cancelled_access"
    assert job.done == 100
    assert job.removed == 0


def test_failed_verification_listing_never_deletes(storage, monkeypatch):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    original = moves.enumerate_sources

    def listing(*args, **kwargs):
        if kwargs.get("allow_missing"):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "private"}}, "ListObjectsV2")
        return original(*args, **kwargs)

    monkeypatch.setattr(moves, "enumerate_sources", listing)
    job = start(user, request())
    job.future.result(timeout=10)
    assert not job.delete_started
    assert job.state == "failed_copy"
    assert s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"abc"


def test_only_request_parent_is_preserved(storage):
    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/dir/deeper/file", Body=b"abc")
    job = start(user, request([{"path": "source/dir", "kind": "folder"}]))
    job.future.result(timeout=10)
    assert job.state == "done"
    assert {obj["Key"] for obj in s3.list_objects_v2(Bucket="move-bucket")["Contents"]} == {
        "source/",
        "dest/dir/deeper/file",
    }


def test_success_metrics_count_objects_once(storage):
    from another_s3_manager.metrics import REGISTRY

    s3, user = storage
    s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"abc")
    job_labels = {"outcome": "done"}
    copy_labels = {"role": "Default", "bucket": "move-bucket", "operation": "copy"}
    delete_labels = {**copy_labels, "operation": "delete"}
    job_before = REGISTRY.get_sample_value("as3m_move_jobs_total", job_labels) or 0
    copy_before = REGISTRY.get_sample_value("as3m_s3_objects_total", copy_labels) or 0
    delete_before = REGISTRY.get_sample_value("as3m_s3_objects_total", delete_labels) or 0
    job = start(user, request())
    job.future.result(timeout=10)
    assert REGISTRY.get_sample_value("as3m_move_jobs_total", job_labels) == job_before + 1
    assert REGISTRY.get_sample_value("as3m_s3_objects_total", copy_labels) == copy_before + 1
    assert REGISTRY.get_sample_value("as3m_s3_objects_total", delete_labels) == delete_before + 1


def test_truncated_listing_without_token_is_rejected(storage, monkeypatch):
    _, user = storage

    class Client:
        def get_paginator(self, name):
            return self

        def paginate(self, **kwargs):
            yield {"IsTruncated": True, "Contents": [{"Key": "source/file", "Size": 3, "ETag": "etag"}]}

    monkeypatch.setattr(moves.s3_client, "execute_with_s3_retry", lambda role, op, callback: callback(Client()))
    with pytest.raises(MoveError) as error:
        moves.build_plan(user, "Default", "move-bucket", request([{"path": "source", "kind": "folder"}]))
    assert error.value.code == "LISTING_INCOMPLETE"
