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
@pytest.mark.parametrize("revoke", [False, True, "disabled", "replacement"])
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
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())
    s3_client._register_delete_handlers(client)
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
        if attempts == 1 and revoke == "disabled":
            users.update_user(user["username"], is_disabled=True)
        elif attempts == 1 and revoke == "replacement":
            from another_s3_manager.database import session_scope
            from another_s3_manager.models import User

            users.delete_user(user["username"])
            with session_scope() as session:
                session.add(User(id=user["id"], username=user["username"], password_hash="new"))
        elif attempts == 1 and revoke is True:
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
        with pytest.raises(
            MoveError if path in {"job", "cleanup"} or isinstance(revoke, str) else access.AccessDenied
        ) as caught:
            delete()
        assert caught.value.code == ("ACCESS_DENIED" if isinstance(revoke, str) else "DELETION_DISABLED_FOR_ROLE")
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
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())
    s3_client._register_delete_handlers(client)
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
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())
    s3_client._register_delete_handlers(client)
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


@pytest.mark.parametrize("conditional", [False, True])
def test_shared_client_retry_has_permanent_isolated_handlers(monkeypatch, conditional):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import nullcontext

    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://s3.test",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"mode": "standard", "total_max_attempts": 2}),
    )
    monkeypatch.setattr(s3_client, "_create_s3_client_from_role", lambda role: client)
    monkeypatch.setattr(client, "list_buckets", lambda: {})
    assert s3_client.get_s3_client("Default") is client
    entered = threading.Event()
    retry_check = threading.Event()
    left = threading.Event()
    counts = {"a": 0, "b": 0}
    sent = []

    def check(name):
        assert threading.current_thread().name.endswith(name)
        counts[name] += 1
        if name == "a" and counts[name] == 3:
            retry_check.set()
            assert left.wait(5)

    def send(request):
        name = request.url.rsplit("/", 1)[-1]
        sent.append((name, request.headers.get("If-Match")))
        status = 500 if name == "a" and sum(key == "a" for key, _ in sent) == 1 else 204
        return AWSResponse(
            request.url, status, {}, Raw(b"<Error><Code>InternalError</Code></Error>" if status == 500 else b"")
        )

    def retry(attempts, **kwargs):
        if threading.current_thread().name.endswith("a") and attempts == 1:
            assert entered.wait(5)

    client.meta.events.register("needs-retry.s3.DeleteObject", retry)
    register = Mock(wraps=client.meta.events.register)
    unregister = Mock(wraps=client.meta.events.unregister)
    monkeypatch.setattr(client.meta.events, "register", register)
    monkeypatch.setattr(client.meta.events, "unregister", unregister)
    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda _: None)

    def delete(name):
        threading.current_thread().name = "delete-" + name
        condition = s3_client._conditional_delete(client, '"etag-' + name + '"') if conditional else nullcontext()
        with s3_client.destructive_delete_guard(client, lambda: check(name)), condition:
            if name == "b":
                entered.set()
            client.delete_object(Bucket="bucket", Key=name)
            if name == "b":
                assert retry_check.wait(5)
        if name == "b":
            left.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(delete, "a")
        b = pool.submit(delete, "b")
        a.result(timeout=15)
        b.result(timeout=15)
    assert counts == {"a": 3, "b": 2}
    assert sum(name == "a" for name, _ in sent) == 2
    if conditional:
        assert all(etag == ('"etag-' + name + '"').encode() for name, etag in sent)
    register.assert_not_called()
    unregister.assert_not_called()
    client.delete_object(Bucket="bucket", Key="after")
    assert counts == {"a": 3, "b": 2}
    client.close()


def test_nested_guard_restores_callback_and_client_scope():
    outer = Mock()
    inner = Mock()
    first = Mock()
    second = Mock()
    s3_client._register_delete_handlers(first)
    s3_client._register_delete_handlers(second)
    first_handler = first.meta.events.register.call_args_list[0].args[1]
    second_handler = second.meta.events.register.call_args_list[0].args[1]
    with s3_client.destructive_delete_guard(first, outer):
        outer.reset_mock()
        first_handler()
        outer.assert_called_once_with()
        with pytest.raises(ValueError, match="inner failure"):
            with s3_client.destructive_delete_guard(second, inner):
                inner.reset_mock()
                first_handler()
                second_handler()
                inner.assert_called_once_with()
                raise ValueError("inner failure")
        outer.reset_mock()
        first_handler()
        second_handler()
        outer.assert_called_once_with()
    outer.reset_mock()
    inner.reset_mock()
    first_handler()
    second_handler()
    outer.assert_not_called()
    inner.assert_not_called()


@pytest.mark.parametrize("path", ["single", "job"])
@pytest.mark.parametrize("changed", ["config", "client"])
def test_sdk_retry_refuses_changed_storage_target(monkeypatch, path, changed):
    from copy import deepcopy

    user = users.load_users()["users"][0]
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url="http://a.test",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"mode": "standard", "total_max_attempts": 2}),
    )
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", config.load_config())
    s3_client._register_delete_handlers(client)
    sent = []
    retries = []

    def send(request):
        sent.append(request.url)
        return AWSResponse(request.url, 500, {}, Raw(b"<Error><Code>InternalError</Code></Error>"))

    def change(attempts, **kwargs):
        retries.append(attempts)
        if changed == "client":
            client._asm_storage_fingerprint = "different-client-target"
        else:
            cfg = deepcopy(config.load_config())
            cfg["roles"][0]["endpoint_url"] = "http://b.test"
            config.save_config(cfg)

    client.meta.events.register("needs-retry.s3", change)
    monkeypatch.setattr(client._endpoint.http_session, "send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", lambda _: None)
    monkeypatch.setattr(client, "list_objects_v2", lambda **kwargs: {"Contents": [{"Key": "file"}]})
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
    try:
        with pytest.raises(MoveError) as caught:
            if path == "job":
                job = move_jobs.Job("retry-job", move_jobs.owner_identity(user), "Default", "bucket", "op", "hash")
                move_jobs.delete_batch(job, ["file"])
            else:
                s3_client.delete_object_for_role("Default", "bucket", "file", user)
        assert caught.value.code == "ROLE_CHANGED"
        assert len(sent) == 1
        assert retries == [1]
    finally:
        client.close()
