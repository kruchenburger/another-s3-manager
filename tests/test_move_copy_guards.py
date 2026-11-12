"""Copy side of a move: the confirmed plan and every copy attempt stay on one target and fresh access."""

import io
import uuid
from unittest.mock import Mock

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config

from another_s3_manager import access, config, move_jobs, s3_client, users
from another_s3_manager.errors import MoveError


class Raw:
    def __init__(self, body):
        self.body = io.BytesIO(body)

    def stream(self, amt=None, decode_content=False):
        yield self.body.read()


def _client():
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://s3.test",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"mode": "standard", "total_max_attempts": 3}),
    )
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())
    s3_client._register_delete_handlers(client)
    return client


def _revoke_delete():
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = False
    config.save_config(cfg)


def _drop_bucket(bucket):
    cfg = config.load_config()
    cfg["roles"][0]["allowed_buckets"] = [bucket]
    config.save_config(cfg)


def test_plan_fingerprint_binds_storage_target():
    req = move_jobs.MoveRequest(items=[{"path": "source/file", "kind": "file"}], destination="dest")
    entry = move_jobs.Entry("source/file", "dest/file", '"e"', 1, None)
    on_a = move_jobs.Plan((entry,), (), (), "target-a").fingerprint("Default", "bucket", req)
    on_b = move_jobs.Plan((entry,), (), (), "target-b").fingerprint("Default", "bucket", req)
    assert on_a != on_b


def test_confirmed_plan_does_not_start_on_another_target(moto_s3, monkeypatch):
    user = users.load_users()["users"][0]
    moto_s3.create_bucket(Bucket="move-bucket")
    moto_s3.put_object(Bucket="move-bucket", Key="source/file", Body=b"keep")
    req = move_jobs.MoveRequest(items=[{"path": "source/file", "kind": "file"}], destination="dest")
    plan = move_jobs.build_plan(user, "Default", "move-bucket", req)
    confirmed = plan.fingerprint("Default", "move-bucket", req)

    # Same role, bucket and listing, but the role now points at another storage.
    cfg = config.load_config()
    cfg["roles"][0]["endpoint_url"] = "http://other-storage.test"
    config.save_config(cfg)
    # The emulator stands in for the new endpoint; only the target identity differs.
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: moto_s3)

    with pytest.raises(MoveError) as caught:
        move_jobs.registry.start(user, "Default", "move-bucket", req, str(uuid.uuid4()), confirmed)
    assert caught.value.code == "PLAN_CHANGED"
    assert moto_s3.get_object(Bucket="move-bucket", Key="source/file")["Body"].read() == b"keep"
    assert "Contents" not in moto_s3.list_objects_v2(Bucket="move-bucket", Prefix="dest/")
    move_jobs.registry.jobs.clear()


@pytest.mark.parametrize("revoke", [False, True])
def test_job_copy_sdk_retry_rechecks_access(monkeypatch, revoke):
    user = users.load_users()["users"][0]
    client = _client()
    copies = []
    destination_heads = []

    def send(request):
        if request.method == "HEAD":
            if request.url.endswith("/dest/file"):
                destination_heads.append(request)
                if len(destination_heads) == 1:
                    return AWSResponse(request.url, 404, {}, Raw(b""))
            return AWSResponse(request.url, 200, {"Content-Length": "3", "ETag": '"e"'}, Raw(b""))
        copies.append(request)
        if len(copies) == 1:
            return AWSResponse(request.url, 500, {}, Raw(b"<Error><Code>InternalError</Code></Error>"))
        return AWSResponse(request.url, 200, {}, Raw(b'<CopyObjectResult><ETag>"e"</ETag></CopyObjectResult>'))

    def on_retry(attempts, **kwargs):
        if attempts == 1 and revoke:
            _revoke_delete()

    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda seconds: None)
    client.meta.events.register("needs-retry.s3.CopyObject", on_retry)
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)

    job = move_jobs.Job("copy-job", move_jobs.owner_identity(user), "Default", "bucket", "op", "hash")
    entry = move_jobs.Entry("source/file", "dest/file", '"e"', 3, None)
    token = move_jobs._active_job.set(job)
    try:
        if revoke:
            with pytest.raises(MoveError) as caught:
                move_jobs.copy_entry("Default", "bucket", entry)
            assert caught.value.code == "DELETION_DISABLED_FOR_ROLE"
            assert len(copies) == 1
        else:
            assert move_jobs.copy_entry("Default", "bucket", entry) == '"e"'
            assert len(copies) == 2
    finally:
        move_jobs._active_job.reset(token)
        client.close()


def test_job_copy_guard_covers_multipart_stages():
    client = _client()
    for operation in ("CopyObject", "CreateMultipartUpload", "UploadPartCopy", "CompleteMultipartUpload"):
        seen = []
        with s3_client.destructive_delete_guard(client, lambda: seen.append(1)):
            seen.clear()
            client.meta.events.emit(f"before-sign.s3.{operation}", request=Mock())
        assert seen == [1], operation
    # Verification reads stay unguarded so a confirmed copy is always recorded.
    seen = []
    with s3_client.destructive_delete_guard(client, lambda: seen.append(1)):
        seen.clear()
        client.meta.events.emit("before-sign.s3.HeadObject", request=Mock())
    assert seen == []
    client.close()


def test_move_copy_retry_rechecks_destination_bucket(monkeypatch):
    user = users.load_users()["users"][0]
    cfg = config.load_config()
    cfg["roles"][0]["allowed_buckets"] = ["source-bucket", "dest-bucket"]
    config.save_config(cfg)
    client = _client()
    copies = []

    def send(request):
        copies.append(request)
        if len(copies) == 1:
            return AWSResponse(request.url, 500, {}, Raw(b"<Error><Code>InternalError</Code></Error>"))
        return AWSResponse(request.url, 200, {}, Raw(b'<CopyObjectResult><ETag>"e"</ETag></CopyObjectResult>'))

    def on_retry(attempts, **kwargs):
        if attempts == 1:
            _drop_bucket("source-bucket")

    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda seconds: None)
    client.meta.events.register("needs-retry.s3.CopyObject", on_retry)
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
    fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())

    with pytest.raises(access.AccessDenied) as caught:
        s3_client._copy_object(
            "Default",
            "source-bucket",
            "file",
            "dest-bucket",
            "file",
            user,
            etag='"e"',
            storage_fingerprint=fingerprint,
        )
    assert caught.value.code == "bucket_not_allowed"
    assert len(copies) == 1
    client.close()
