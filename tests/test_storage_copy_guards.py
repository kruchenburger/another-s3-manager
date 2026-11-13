"""Plain copies stay on one target and recheck access on every write attempt."""

import io
from contextlib import ExitStack, closing

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.config import Config

from another_s3_manager import access, config, s3_client, users
from another_s3_manager.errors import MoveError


class Raw:
    def __init__(self, body):
        self.body = io.BytesIO(body)

    def stream(self, amt=None, decode_content=False):
        yield self.body.read()


def client_for(stack, cfg):
    client = stack.enter_context(
        closing(
            boto3.client(
                "s3",
                region_name="us-east-1",
                endpoint_url=cfg["roles"][0].get("endpoint_url", "http://a.test"),
                aws_access_key_id="test",
                aws_secret_access_key="test",
                config=Config(retries={"mode": "standard", "total_max_attempts": 2}),
            )
        )
    )
    client._asm_storage_fingerprint = s3_client.role_storage_fingerprint("Default", cfg)
    s3_client._register_delete_handlers(client)
    return client


def copy(user):
    return s3_client.copy_object_for_role("Default", "source-bucket", "file", "dest-bucket", "file", user)


@pytest.mark.parametrize(
    "change,code",
    [
        ("endpoint", "ROLE_CHANGED"),
        ("destination", "bucket_not_allowed"),
        ("source", "bucket_not_allowed"),
        ("grant", "role_not_allowed"),
        # A replaced or vanished account is a current-account refusal since ASM-131 PR 2.
        ("account", "ACCESS_DENIED"),
        ("missing", "ACCESS_DENIED"),
        ("client", "ROLE_CHANGED"),
        ("unrelated", None),
    ],
)
def test_plain_copy_sdk_retry_rechecks_target_and_access(monkeypatch, change, code):
    user = users.load_users()["users"][0]
    cfg = config.load_config()
    cfg["roles"][0]["allowed_buckets"] = ["source-bucket", "dest-bucket"]
    config.save_config(cfg)
    sent = []
    with ExitStack() as stack:
        client = client_for(stack, cfg)

        def send(request):
            sent.append(request.url)
            if len(sent) == 1:
                return AWSResponse(request.url, 500, {}, Raw(b"<Error><Code>InternalError</Code></Error>"))
            return AWSResponse(request.url, 200, {}, Raw(b'<CopyObjectResult><ETag>"e"</ETag></CopyObjectResult>'))

        def on_retry(attempts, **kwargs):
            if attempts != 1:
                return
            fresh = config.load_config()
            if change == "endpoint":
                fresh["roles"][0]["endpoint_url"] = "http://b.test"
            elif change in {"source", "destination"}:
                fresh["roles"][0]["allowed_buckets"] = ["source-bucket" if change == "destination" else "dest-bucket"]
            elif change in {"grant", "account", "missing"}:
                current = dict(user)
                if change == "grant":
                    current.update(is_admin=False, allowed_roles=[])
                else:
                    # Identity is (id, auth_generation); a new generation means a replaced account.
                    current["auth_generation"] = "replaced-generation"
                monkeypatch.setattr(users, "get_user_by_id", lambda uid: None if change == "missing" else current)
            elif change == "client":
                client._asm_storage_fingerprint = "different-target"
            else:
                fresh["roles"].append({"name": "Other", "type": "default", "endpoint_url": "http://b.test"})
            config.save_config(fresh)

        monkeypatch.setattr(client._endpoint.http_session, "send", send)
        monkeypatch.setattr("botocore.endpoint.time.sleep", lambda _: None)
        client.meta.events.register("needs-retry.s3.CopyObject", on_retry)
        monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
        if code:
            with pytest.raises((MoveError, access.AccessDenied)) as caught:
                copy(user)
            assert caught.value.code == code
            assert len(sent) == 1
        else:
            copy(user)
            assert len(sent) == 2


def test_plain_copy_credential_retry_keeps_first_target(monkeypatch):
    user = users.load_users()["users"][0]
    sent_a, sent_b = [], []
    with ExitStack() as stack:
        client_a = client_for(stack, config.load_config())
        fresh = config.load_config()
        fresh["roles"][0]["endpoint_url"] = "http://b.test"
        client_b = client_for(stack, fresh)

        def send_a(request):
            sent_a.append(request.url)
            config.save_config(fresh)
            return AWSResponse(request.url, 400, {}, Raw(b"<Error><Code>ExpiredToken</Code></Error>"))

        def send_b(request):
            sent_b.append(request.url)
            return AWSResponse(request.url, 200, {}, Raw(b'<CopyObjectResult><ETag>"e"</ETag></CopyObjectResult>'))

        monkeypatch.setattr(client_a._endpoint.http_session, "send", send_a)
        monkeypatch.setattr(client_b._endpoint.http_session, "send", send_b)
        clients = iter([client_a, client_b])
        monkeypatch.setattr(s3_client, "get_s3_client", lambda role: next(clients))
        monkeypatch.setattr(s3_client, "_clear_boto3_cached_credentials", lambda: None)
        with pytest.raises(MoveError) as caught:
            copy(user)
        assert caught.value.code == "ROLE_CHANGED"
        assert len(sent_a) == 1
        assert sent_b == []


def test_plain_copy_ignores_delete_permission(monkeypatch):
    user = users.load_users()["users"][0]
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = False
    cfg["disable_deletion"] = True
    config.save_config(cfg)
    monkeypatch.setenv("DISABLE_DELETION", "true")
    sent = []
    with ExitStack() as stack:
        client = client_for(stack, cfg)

        def send(request):
            sent.append(request.url)
            return AWSResponse(request.url, 200, {}, Raw(b'<CopyObjectResult><ETag>"e"</ETag></CopyObjectResult>'))

        monkeypatch.setattr(client._endpoint.http_session, "send", send)
        monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
        copy(user)
        assert len(sent) == 1


def test_plain_copy_refuses_stale_client_before_first_write(monkeypatch):
    user = users.load_users()["users"][0]
    with ExitStack() as stack:
        client = client_for(stack, config.load_config())
        cfg = config.load_config()
        cfg["roles"][0]["endpoint_url"] = "http://b.test"
        config.save_config(cfg)
        sent = []
        monkeypatch.setattr(client._endpoint.http_session, "send", lambda request: sent.append(request))
        monkeypatch.setattr(s3_client, "get_s3_client", lambda role: client)
        with pytest.raises(MoveError) as caught:
            copy(user)
        assert caught.value.code == "ROLE_CHANGED"
        assert sent == []
