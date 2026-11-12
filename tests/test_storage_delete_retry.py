"""Exercise actual botocore HTTP retries, not Stubber's before-call shortcut."""

import io
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


@pytest.mark.parametrize("path", ["exact", "conditional", "single", "directory", "job", "cleanup"])
@pytest.mark.parametrize("revoke", [False, True])
def test_sdk_retry_refreshes_access(monkeypatch, path, revoke):
    user = users.load_users()["users"][0]
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://s3.test",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"mode": "standard", "total_max_attempts": 3}),
    )
    sent = []
    retries = []

    def send(request):
        sent.append(request)
        if len(sent) == 1:
            return AWSResponse(request.url, 500, {}, Raw(b"<Error><Code>InternalError</Code></Error>"))
        body = (
            b'<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dir/file</Key></Deleted></DeleteResult>'
            if path in {"directory", "job", "cleanup"}
            else b""
        )
        return AWSResponse(request.url, 200 if path in {"directory", "job", "cleanup"} else 204, {}, Raw(body))

    def on_retry(attempts, **kwargs):
        retries.append(attempts)
        if attempts == 1 and revoke:
            cfg = config.load_config()
            cfg["roles"][0]["allow_delete"] = False
            config.save_config(cfg)

    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda seconds: None)
    monkeypatch.setattr(client, "list_objects_v2", lambda **kwargs: {"Contents": [{"Key": "dir/file"}]})
    client.meta.events.register("needs-retry.s3", on_retry)
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)

    def delete():
        if path in {"job", "cleanup"}:
            job = move_jobs.Job("retry-job", move_jobs.owner_identity(user), "Default", "bucket", "op", "hash")
            if path == "job":
                return {"count": len(move_jobs.delete_batch(job, ["dir/file"]))}
            registry = move_jobs.MoveRegistry()
            job.state = "failed_copy"
            job.copied = {"dir/file": '"etag"'}
            registry.jobs[job.id] = job
            monkeypatch.setattr(client, "head_object", lambda **kwargs: {"ETag": '"etag"'})
            return {"count": registry.cleanup(job.id, user)["removed"]}
        if path in {"exact", "conditional"}:
            if path == "conditional":
                monkeypatch.setattr(s3_client, "_head_move_source", lambda *args: {"ETag": '"etag"'})
            return s3_client._delete_exact_key(
                "Default", "bucket", "dir/file", user, etag='"etag"' if path == "conditional" else None
            )
        return s3_client.delete_object_for_role(
            "Default", "bucket", "dir/" if path == "directory" else "dir/file", user
        )

    if revoke:
        with pytest.raises(MoveError if path in {"job", "cleanup"} else access.AccessDenied) as caught:
            delete()
        assert caught.value.code == "DELETION_DISABLED_FOR_ROLE"
        assert len(sent) == 1
        assert retries == [1]
    else:
        assert delete()["count"] == 1
        assert len(sent) == 2
        assert retries == [1, 2]
    if path == "conditional":
        assert all(request.headers["If-Match"] == b'"etag"' for request in sent)
    # A later call on this shared client must not run a previous call's guard.
    before = len(sent)
    client.delete_object(Bucket="bucket", Key="independent")
    assert len(sent) == before + 1
    client.close()


def test_guard_unregisters_on_exception(monkeypatch):
    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
    check = Mock(side_effect=access.AccessDenied("role_not_allowed", "revoked"))
    with pytest.raises(access.AccessDenied):
        with s3_client.destructive_delete_guard(client, check):
            client.delete_object(Bucket="bucket", Key="file")
    check.reset_mock()
    client.meta.events.emit("before-sign.s3.DeleteObject", request=Mock())
    check.assert_not_called()
    client.close()


def test_guard_isolates_threads_on_shared_client(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://s3.test",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    barrier = threading.Barrier(2)
    checks = {"allowed": 0, "denied": 0}
    sent = []

    def send(request):
        sent.append(request.url)
        return AWSResponse(request.url, 204, {}, Raw(b""))

    monkeypatch.setattr(client._endpoint.http_session, "send", send)

    def delete(name):
        def check():
            checks[name] += 1
            if name == "denied" and checks[name] > 1:
                raise access.AccessDenied("role_not_allowed", "revoked")

        with s3_client.destructive_delete_guard(client, check):
            barrier.wait(timeout=5)
            client.delete_object(Bucket="bucket", Key=name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        allowed = pool.submit(delete, "allowed")
        denied = pool.submit(delete, "denied")
        allowed.result(timeout=10)
        with pytest.raises(access.AccessDenied):
            denied.result(timeout=10)
    assert checks == {"allowed": 2, "denied": 2}
    assert len(sent) == 1 and sent[0].endswith("/allowed")
    client.delete_object(Bucket="bucket", Key="after")
    assert checks == {"allowed": 2, "denied": 2}
    assert len(sent) == 2
    client.close()
