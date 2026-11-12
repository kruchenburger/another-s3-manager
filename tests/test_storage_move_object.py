"""Storage owns the conditional single-object move and its reservation."""

import ast
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from another_s3_manager import config, move_reservations, s3_client
from another_s3_manager.errors import MoveError, S3AccessDeniedError

USER = {"is_admin": True, "allowed_roles": ["Default"]}


@pytest.fixture
def source(moto_s3, monkeypatch):
    from another_s3_manager import users

    USER.clear()
    USER.update(users.load_users()["users"][0])
    moto_s3.create_bucket(Bucket="move-source")
    moto_s3.create_bucket(Bucket="move-dest")
    moto_s3.put_object(Bucket="move-source", Key="file", Body=b"old")
    monkeypatch.setattr(s3_client, "get_s3_client", lambda role: moto_s3)
    return moto_s3


def move():
    return s3_client.move_object_for_role("Default", "move-source", "file", "move-dest", "copy", USER)


def body(client, bucket, key):
    return client.get_object(Bucket=bucket, Key=key)["Body"].read()


def precondition(operation):
    return ClientError(
        {"Error": {"Code": "PreconditionFailed"}, "ResponseMetadata": {"HTTPStatusCode": 412}}, operation
    )


def test_move_happy_path(source):
    result = move()
    assert result == {
        "ok": True,
        "copied": True,
        "moved": True,
        "source_kept_reason": None,
        "message": "Copy complete",
    }
    assert body(source, "move-dest", "copy") == b"old"
    with pytest.raises(ClientError) as caught:
        source.head_object(Bucket="move-source", Key="file")
    assert caught.value.response["Error"]["Code"] == "404"


@pytest.mark.parametrize("change", ["overwrite", "remove"])
def test_changed_source_is_kept(source, monkeypatch, change):
    original = source.copy_object

    def copy_and_change(**kwargs):
        result = original(**kwargs)
        if change == "overwrite":
            source.put_object(Bucket="move-source", Key="file", Body=b"new")
        else:
            source.delete_object(Bucket="move-source", Key="file")
        return result

    monkeypatch.setattr(source, "copy_object", copy_and_change)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert result["message"] == "Copied, source changed after the copy — source kept"
    assert body(source, "move-dest", "copy") == b"old"
    if change == "overwrite":
        assert body(source, "move-source", "file") == b"new"
        delete.assert_not_called()
    else:
        assert delete.call_count == 1  # Only the injected external deletion.


@pytest.mark.parametrize("global_flag", [False, True])
def test_permission_revoked_after_copy(source, monkeypatch, global_flag):
    original = source.copy_object

    def copy_and_revoke(**kwargs):
        result = original(**kwargs)
        cfg = config.load_config()
        if global_flag:
            cfg["disable_deletion"] = True
        else:
            cfg["roles"][0]["allow_delete"] = False
        config.save_config(cfg)
        return result

    monkeypatch.setattr(source, "copy_object", copy_and_revoke)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == ("DELETION_DISABLED" if global_flag else "DELETION_DISABLED_FOR_ROLE")
    assert result["message"] == (
        "Deletion is disabled in server config" if global_flag else "Deleting is turned off for role 'Default'"
    )
    delete.assert_not_called()
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("operation", ["copy_object", "delete_object"])
def test_precondition_failure_never_reports_move(source, monkeypatch, operation):
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    monkeypatch.setattr(source, operation, Mock(side_effect=precondition(operation)))
    result = move()
    assert result["copied"] is (operation == "delete_object")
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert body(source, "move-source", "file") == b"old"
    if operation == "copy_object":
        delete.assert_not_called()
        assert source.list_objects_v2(Bucket="move-dest").get("Contents", []) == []
    else:
        assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("same_body", [False, True])
def test_new_version_before_second_head_prevents_delete(source, monkeypatch, same_body):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"old")
    original = source.copy_object

    def copy_and_replace(**kwargs):
        result = original(**kwargs)
        source.put_object(Bucket="move-source", Key="file", Body=b"old" if same_body else b"new")
        return result

    monkeypatch.setattr(source, "copy_object", copy_and_replace)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert result["moved"] is False
    delete.assert_not_called()
    assert body(source, "move-source", "file") == (b"old" if same_body else b"new")
    assert body(source, "move-dest", "copy") == b"old"


def test_versioned_delete_targets_only_copied_version(source, monkeypatch):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    version = source.put_object(Bucket="move-source", Key="file", Body=b"old")["VersionId"]
    etag = source.head_object(Bucket="move-source", Key="file")["ETag"]
    copy = Mock(wraps=source.copy_object)
    monkeypatch.setattr(source, "copy_object", copy)
    original = source.delete_object
    calls = []
    newer_versions = []

    def replace_then_delete(**kwargs):
        calls.append(kwargs)
        newer_versions.append(source.put_object(Bucket="move-source", Key="file", Body=b"new")["VersionId"])
        return original(**kwargs)

    monkeypatch.setattr(source, "delete_object", replace_then_delete)
    assert move()["moved"] is True
    assert calls == [{"Bucket": "move-source", "Key": "file"}]
    assert copy.call_args.kwargs["CopySource"] == {"Bucket": "move-source", "Key": "file", "VersionId": version}
    assert copy.call_args.kwargs["CopySourceIfMatch"] == etag
    with pytest.raises(ClientError):
        source.head_object(Bucket="move-source", Key="file")
    assert body(source, "move-dest", "copy") == b"old"
    assert source.get_object(Bucket="move-source", Key="file", VersionId=version)["Body"].read() == b"old"
    assert source.get_object(Bucket="move-source", Key="file", VersionId=newer_versions[0])["Body"].read() == b"new"


def test_if_match_is_signed_and_does_not_leak_between_threads(source):
    source.put_object(Bucket="move-source", Key="other", Body=b"unrelated")
    source.put_object(Bucket="move-source", Key="later", Body=b"later")
    etag = source.head_object(Bucket="move-source", Key="file")["ETag"]
    barrier = threading.Barrier(2)
    observed = {}

    def observe(request, **kwargs):
        key = request.url.rsplit("/", 1)[-1]
        observed[key] = request.headers.get("If-Match")
        if key in {"file", "other"}:
            barrier.wait(timeout=5)

    source.meta.events.register("before-send.s3.DeleteObject", observe)
    with ThreadPoolExecutor(max_workers=2) as pool:
        guarded = pool.submit(move)
        unrelated = pool.submit(source.delete_object, Bucket="move-source", Key="other")
        assert guarded.result(timeout=10)["moved"] is True
        unrelated.result(timeout=10)
    source.delete_object(Bucket="move-source", Key="later")
    assert observed == {"file": etag.encode(), "other": None, "later": None}


def test_header_context_resets_after_delete_failure(source):
    observed = []

    def reject_once(request, **kwargs):
        observed.append(request.headers.get("If-Match"))
        if len(observed) == 1:
            raise precondition("DeleteObject")

    source.meta.events.register("before-send.s3.DeleteObject", reject_once)
    assert move()["source_kept_reason"] == "SOURCE_CHANGED"
    source.delete_object(Bucket="move-source", Key="file")
    assert observed[0] is not None
    assert observed[1] is None


def test_reservations_cover_copy_and_delete_and_are_released(source, monkeypatch):
    original_copy = source.copy_object
    original_delete = source.delete_object
    phases = []

    def check():
        for bucket, key in [("move-source", "file"), ("move-dest", "copy")]:
            with pytest.raises(MoveError) as caught:
                s3_client.put_object_for_role("Default", bucket, key, b"new", USER)
            assert caught.value.code == "BUSY"

    def copy(**kwargs):
        check()
        phases.append("copy")
        return original_copy(**kwargs)

    def delete(**kwargs):
        check()
        phases.append("delete")
        return original_delete(**kwargs)

    monkeypatch.setattr(source, "copy_object", copy)
    monkeypatch.setattr(source, "delete_object", delete)
    assert move()["moved"] is True
    assert phases == ["copy", "delete"]
    with move_reservations.reserve("after", [("Default", "move-source", "file"), ("Default", "move-dest", "copy")]):
        pass


def test_mcp_copy_has_no_delete_sequencing():
    tree = ast.parse((Path(__file__).parents[1] / "src/another_s3_manager/mcp_server.py").read_bytes())
    tool = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "copy_object")
    names = {node.attr for node in ast.walk(tool) if isinstance(node, ast.Attribute)}
    assert "move_object_for_role" in names
    assert names.isdisjoint({"delete_exact_key_for_role", "delete_object_for_role"})


@pytest.mark.parametrize("change", ["none", "source", "permission"])
def test_delete_credential_retry_rechecks_without_recopying(source, monkeypatch, change):
    original = source.delete_object
    copies = Mock(wraps=source.copy_object)
    attempts = []

    def expire_once(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            if change == "source":
                source.put_object(Bucket="move-source", Key="file", Body=b"new")
            elif change == "permission":
                cfg = config.load_config()
                cfg["roles"][0]["allow_delete"] = False
                config.save_config(cfg)
            raise ClientError({"Error": {"Code": "ExpiredToken"}}, "DeleteObject")
        return original(**kwargs)

    monkeypatch.setattr(source, "delete_object", expire_once)
    monkeypatch.setattr(source, "copy_object", copies)
    monkeypatch.setattr(s3_client, "invalidate_s3_client", lambda role: None)
    monkeypatch.setattr(s3_client, "_clear_boto3_cached_credentials", lambda: None)
    result = move()
    copies.assert_called_once()
    assert body(source, "move-dest", "copy") == b"old"
    if change == "none":
        assert result["moved"] is True
        assert len(attempts) == 2
    else:
        assert result["moved"] is False
        assert len(attempts) == 1
        assert result["source_kept_reason"] == (
            "SOURCE_CHANGED" if change == "source" else "DELETION_DISABLED_FOR_ROLE"
        )
        assert body(source, "move-source", "file") == (b"new" if change == "source" else b"old")


def test_conditional_handler_is_registered_once_per_client(source, monkeypatch):
    register = Mock(wraps=source.meta.events.register)
    monkeypatch.setattr(source.meta.events, "register", register)
    assert move()["moved"] is True
    source.put_object(Bucket="move-source", Key="file", Body=b"second")
    assert move()["moved"] is True
    events = [
        call.args[0]
        for call in register.call_args_list
        if call.kwargs.get("unique_id", "").startswith("asm-delete-if-match")
    ]
    assert events.count("before-sign.s3.DeleteObject") == 1
    assert events.count("before-parameter-build.s3.DeleteObject") == 1


def test_external_change_after_head_is_protected_by_conditional_delete(source):
    def external_writer(request, **kwargs):
        expected = request.headers.get("If-Match")
        assert expected is not None
        source.put_object(Bucket="move-source", Key="file", Body=b"new")
        actual = source.head_object(Bucket="move-source", Key="file")["ETag"].encode()
        if actual != expected:
            # Emulate the backend's conditional DELETE, which moto may ignore.
            raise precondition("DeleteObject")

    source.meta.events.register("before-send.s3.DeleteObject", external_writer)
    result = move()
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert body(source, "move-source", "file") == b"new"
    assert body(source, "move-dest", "copy") == b"old"


def test_failed_move_releases_both_reservations(source, monkeypatch):
    monkeypatch.setattr(
        source, "copy_object", Mock(side_effect=ClientError({"Error": {"Code": "AccessDenied"}}, "CopyObject"))
    )
    with pytest.raises(S3AccessDeniedError, match="CopyObject"):
        move()
    with move_reservations.reserve(
        "after-failure", [("Default", "move-source", "file"), ("Default", "move-dest", "copy")]
    ):
        pass


def test_early_delete_denial_does_not_read_or_copy_source(source, monkeypatch):
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = False
    config.save_config(cfg)
    head = Mock(wraps=source.head_object)
    copy = Mock(wraps=source.copy_object)
    monkeypatch.setattr(source, "head_object", head)
    monkeypatch.setattr(source, "copy_object", copy)
    with pytest.raises(PermissionError):
        move()
    head.assert_not_called()
    copy.assert_not_called()


def test_missing_initial_source_does_not_copy_or_delete(source, monkeypatch):
    source.delete_object(Bucket="move-source", Key="file")
    copy = Mock(wraps=source.copy_object)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "copy_object", copy)
    monkeypatch.setattr(source, "delete_object", delete)
    with pytest.raises(FileNotFoundError):
        move()
    copy.assert_not_called()
    delete.assert_not_called()


def test_null_version_uses_conditional_delete_not_version_delete(source, monkeypatch):
    # Suspended versioning reports VersionId "null", which the next PUT overwrites:
    # deleting by that id would remove newer data, so the If-Match guard must apply.
    etag = source.head_object(Bucket="move-source", Key="file")["ETag"]
    original_head = source.head_object
    monkeypatch.setattr(source, "head_object", lambda **kw: {**original_head(**kw), "VersionId": "null"})
    original_delete = source.delete_object
    calls = []
    monkeypatch.setattr(source, "delete_object", lambda **kw: (calls.append(kw), original_delete(**kw))[1])
    headers = []
    source.meta.events.register(
        "before-send.s3.DeleteObject", lambda request, **kw: headers.append(request.headers.get("If-Match"))
    )
    assert move()["moved"] is True
    assert calls == [{"Bucket": "move-source", "Key": "file"}]
    assert headers == [etag.encode()]


def test_versioned_move_hides_key_and_preserves_history(source):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    v1 = source.put_object(Bucket="move-source", Key="file", Body=b"v1")["VersionId"]
    v2 = source.put_object(Bucket="move-source", Key="file", Body=b"v2")["VersionId"]
    assert move()["moved"] is True
    assert body(source, "move-dest", "copy") == b"v2"
    with pytest.raises(ClientError) as caught:
        source.head_object(Bucket="move-source", Key="file")
    assert caught.value.response["Error"]["Code"] == "404"
    versions = source.list_object_versions(Bucket="move-source", Prefix="file")
    assert any(marker["IsLatest"] for marker in versions["DeleteMarkers"])
    for version, expected in [(v1, b"v1"), (v2, b"v2")]:
        assert source.get_object(Bucket="move-source", Key="file", VersionId=version)["Body"].read() == expected


@pytest.mark.parametrize("global_flag", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_permission_revoked_during_final_head(source, monkeypatch, global_flag, retry):
    original_head = source.head_object
    original_delete = source.delete_object
    heads = 0

    def head_and_revoke(**kwargs):
        nonlocal heads
        result = original_head(**kwargs)
        heads += 1
        if heads == (3 if retry else 2):
            cfg = config.load_config()
            if global_flag:
                cfg["disable_deletion"] = True
            else:
                cfg["roles"][0]["allow_delete"] = False
            config.save_config(cfg)
        return result

    def expire_once(**kwargs):
        if delete.call_count == 1:
            raise ClientError({"Error": {"Code": "ExpiredToken"}}, "DeleteObject")
        return original_delete(**kwargs)

    delete = Mock(side_effect=expire_once if retry else original_delete)
    copies = Mock(wraps=source.copy_object)
    monkeypatch.setattr(source, "head_object", head_and_revoke)
    monkeypatch.setattr(source, "delete_object", delete)
    monkeypatch.setattr(source, "copy_object", copies)
    monkeypatch.setattr(s3_client, "invalidate_s3_client", lambda role: None)
    monkeypatch.setattr(s3_client, "_clear_boto3_cached_credentials", lambda: None)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == ("DELETION_DISABLED" if global_flag else "DELETION_DISABLED_FOR_ROLE")
    assert delete.call_count == (1 if retry else 0)
    copies.assert_called_once()
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("code", ["404", "NoSuchKey", "NotFound", "UnknownMissing"])
@pytest.mark.parametrize("kind", ["conditional", "versioned", "plain"])
def test_missing_delete_is_source_changed_only_for_conditional_move(source, monkeypatch, code, kind):
    if kind == "versioned":
        source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
        source.put_object(Bucket="move-source", Key="file", Body=b"old")
    error = ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "DeleteObject")
    monkeypatch.setattr(source, "delete_object", Mock(side_effect=error))
    if kind in ("conditional", "versioned"):
        result = move()
        assert result["copied"] is True
        assert result["moved"] is False
        assert result["source_kept_reason"] == "SOURCE_CHANGED"
        assert body(source, "move-dest", "copy") == b"old"
    else:
        with pytest.raises(ClientError) as caught:
            if kind == "plain":
                s3_client.delete_exact_key_for_role("Default", "move-source", "file", USER)
            else:
                move()
        assert caught.value is error
    assert body(source, "move-source", "file") == b"old"


@pytest.mark.parametrize("field", ["Metadata", "ContentType"])
def test_same_bytes_metadata_overwrite_keeps_source(source, monkeypatch, field):
    original_copy = source.copy_object
    original_etag = source.head_object(Bucket="move-source", Key="file")["ETag"]

    def copy_and_overwrite(**kwargs):
        result = original_copy(**kwargs)
        extra = {"Metadata": {"owner": "new"}} if field == "Metadata" else {"ContentType": "text/plain"}
        source.put_object(Bucket="move-source", Key="file", Body=b"old", **extra)
        return result

    monkeypatch.setattr(source, "copy_object", copy_and_overwrite)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    delete.assert_not_called()
    current = source.head_object(Bucket="move-source", Key="file")
    assert current["ETag"] == original_etag
    assert current[field] == ({"owner": "new"} if field == "Metadata" else "text/plain")
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("field", ["LastModified", "ContentLength"])
def test_other_source_head_changes_prevent_delete(source, monkeypatch, field):
    from datetime import timedelta

    original_head = source.head_object
    heads = 0

    def changed_head(**kwargs):
        nonlocal heads
        result = original_head(**kwargs)
        heads += 1
        if heads == 2:
            # Model a backend state change without relying on moto's timestamp precision.
            result[field] += timedelta(seconds=1) if field == "LastModified" else 1
        return result

    monkeypatch.setattr(source, "head_object", changed_head)
    delete = Mock(wraps=source.delete_object)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    delete.assert_not_called()
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


def test_suspended_versioning_real_version_still_sends_if_match(source):
    # Versioning suspended after a real version was written: a later PUT creates a
    # new "null" version, so the delete must stay conditional even for a real id.
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"old")
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Suspended"})
    etag = source.head_object(Bucket="move-source", Key="file")["ETag"]
    headers = []
    source.meta.events.register(
        "before-send.s3.DeleteObject", lambda request, **kw: headers.append(request.headers.get("If-Match"))
    )
    assert move()["moved"] is True
    assert headers == [etag.encode()]


def test_copy_precondition_failure_message_says_not_copied(source, monkeypatch):
    monkeypatch.setattr(source, "copy_object", Mock(side_effect=precondition("CopyObject")))
    result = move()
    assert result["copied"] is False
    assert result["moved"] is False
    assert result["message"].startswith("Not copied")
    assert body(source, "move-source", "file") == b"old"


@pytest.mark.parametrize(
    "denial,expected",
    [
        ("bucket_not_allowed", "bucket_not_allowed"),
        ("role_not_allowed", "role_not_allowed"),
        ("writes_disabled", "writes_disabled"),
        ("read_only_token", "read_only_token"),
    ],
)
def test_any_access_denial_after_copy_preserves_result(source, monkeypatch, denial, expected):
    from another_s3_manager.access import AccessDenied

    def denied(*args, **kwargs):
        raise AccessDenied(denial, "revoked")

    monkeypatch.setattr(s3_client, "_delete_exact_key", denied)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == expected
    assert result["message"] == "revoked"
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


def test_bucket_revoked_after_successful_copy(source, monkeypatch):
    original = source.copy_object

    def copy_and_revoke(**kwargs):
        result = original(**kwargs)
        cfg = config.load_config()
        cfg["roles"][0]["allowed_buckets"] = ["other-bucket"]
        config.save_config(cfg)
        return result

    monkeypatch.setattr(source, "copy_object", copy_and_revoke)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "bucket_not_allowed"
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("code", ["bucket_not_allowed", "role_not_allowed", "writes_disabled", "read_only_token"])
def test_access_denial_before_copy_still_raises(source, monkeypatch, code):
    from another_s3_manager.access import AccessDenied

    monkeypatch.setattr(s3_client, "_copy_object", Mock(side_effect=AccessDenied(code, "denied")))
    with pytest.raises(AccessDenied) as caught:
        move()
    assert caught.value.code == code
    assert body(source, "move-source", "file") == b"old"
    with pytest.raises(ClientError) as missing:
        source.head_object(Bucket="move-dest", Key="copy")
    assert missing.value.response["Error"]["Code"] == "404"


@pytest.mark.parametrize("operation,method", [("HeadObject", "head_object"), ("DeleteObject", "delete_object")])
@pytest.mark.parametrize("code,status", [("AccessDenied", 403), ("403", 403), ("AccessDenied", 400), ("Unknown", 403)])
def test_s3_denial_after_copy_preserves_both_objects(source, monkeypatch, operation, method, code, status):
    original_head = source.head_object
    heads = 0

    def head(**kwargs):
        nonlocal heads
        heads += 1
        if method == "head_object" and heads == 2:
            raise ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, operation)
        return original_head(**kwargs)

    delete = Mock(
        side_effect=ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, operation)
    )
    monkeypatch.setattr(source, "head_object", head)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["ok"] is True
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "S3_ACCESS_DENIED"
    assert result["message"] == f"Copied, source kept. Access denied by S3 during {operation}."
    assert heads == 2
    if method == "head_object":
        delete.assert_not_called()
    else:
        delete.assert_called_once()
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


def test_typed_s3_denial_after_copy_preserves_both_objects(source, monkeypatch):
    # A client rebuilt after ExpiredToken can be refused with an already-typed S3AccessDeniedError.
    delete = Mock(side_effect=S3AccessDeniedError("AccessDenied", "Access denied by S3."))
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["ok"] is True
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "S3_ACCESS_DENIED"
    assert result["message"] == "Copied, source kept. Access denied by S3 before the source could be deleted."
    delete.assert_called_once()
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


@pytest.mark.parametrize("method", ["head_object", "delete_object"])
@pytest.mark.parametrize(
    "failure",
    [
        ClientError({"Error": {"Code": "InternalError"}, "ResponseMetadata": {"HTTPStatusCode": 500}}, "Op"),
        ConnectionError("network down"),
    ],
)
def test_other_failure_after_copy_keeps_copy_result(source, monkeypatch, method, failure):
    original_head = source.head_object
    heads = 0

    def head(**kwargs):
        nonlocal heads
        heads += 1
        if method == "head_object" and heads == 2:
            raise failure
        return original_head(**kwargs)

    delete = Mock(side_effect=failure)
    monkeypatch.setattr(source, "head_object", head)
    monkeypatch.setattr(source, "delete_object", delete)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_DELETE_FAILED"
    assert "may still exist" in result["message"]
    assert body(source, "move-source", "file") == b"old"
    assert body(source, "move-dest", "copy") == b"old"


def test_failure_before_copy_still_raises(source, monkeypatch):
    def head(**kwargs):
        raise ConnectionError("network down")

    monkeypatch.setattr(source, "head_object", head)
    with pytest.raises(ConnectionError):
        move()
    monkeypatch.undo()
    with pytest.raises(ClientError):
        source.head_object(Bucket="move-dest", Key="copy")


def _deny_pinned_copy(source, monkeypatch):
    """Simulate an IAM role without s3:GetObjectVersion: pinned copies are refused."""
    original_copy = source.copy_object
    calls = []

    def copy_object(**kwargs):
        calls.append(dict(kwargs["CopySource"]))
        if "VersionId" in kwargs["CopySource"]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "CopyObject"
            )
        return original_copy(**kwargs)

    monkeypatch.setattr(source, "copy_object", copy_object)
    return calls


def test_versioned_move_without_get_object_version_falls_back_to_unpinned_copy(source, monkeypatch):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"v2")
    calls = _deny_pinned_copy(source, monkeypatch)
    result = move()
    assert result["moved"] is True
    assert [("VersionId" in call) for call in calls] == [True, False]
    assert body(source, "move-dest", "copy") == b"v2"


def test_unversioned_move_never_pins_a_version(source, monkeypatch):
    calls = _deny_pinned_copy(source, monkeypatch)
    assert move()["moved"] is True
    assert all("VersionId" not in call for call in calls) and len(calls) == 1


def test_unpinned_fallback_still_refuses_a_changed_source(source, monkeypatch):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"v2")
    original_copy = source.copy_object

    def copy_object(**kwargs):
        if "VersionId" in kwargs["CopySource"]:
            # A writer replaces the source while the pinned copy is being refused.
            source.put_object(Bucket="move-source", Key="file", Body=b"v3")
            raise ClientError(
                {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "CopyObject"
            )
        # moto ignores CopySourceIfMatch; enforce it like S3 does.
        if kwargs["CopySourceIfMatch"] != source.head_object(Bucket="move-source", Key="file")["ETag"]:
            raise precondition("CopyObject")
        return original_copy(**kwargs)

    monkeypatch.setattr(source, "copy_object", copy_object)
    result = move()
    assert result["copied"] is False
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert body(source, "move-source", "file") == b"v3"


def test_unpinned_fallback_that_copied_another_version_keeps_source(source, monkeypatch):
    # A -> pinned copy denied -> B written with the same bytes -> unpinned copy takes B ->
    # B deleted (A current again): the second HEAD matches A, so only CopySourceVersionId
    # shows that the destination holds B.
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"same")
    original_copy = source.copy_object

    def copy_object(**kwargs):
        if "VersionId" in kwargs["CopySource"]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "CopyObject"
            )
        newer = source.put_object(Bucket="move-source", Key="file", Body=b"same", ContentType="text/b")
        response = original_copy(**kwargs)
        source.delete_object(Bucket="move-source", Key="file", VersionId=newer["VersionId"])
        return response

    monkeypatch.setattr(source, "copy_object", copy_object)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert body(source, "move-source", "file") == b"same"


def test_unpinned_fallback_without_copied_version_keeps_source(source, monkeypatch):
    source.put_bucket_versioning(Bucket="move-source", VersioningConfiguration={"Status": "Enabled"})
    source.put_object(Bucket="move-source", Key="file", Body=b"v2")
    original_copy = source.copy_object

    def copy_object(**kwargs):
        if "VersionId" in kwargs["CopySource"]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 403}}, "CopyObject"
            )
        response = original_copy(**kwargs)
        response.pop("CopySourceVersionId", None)  # backend that does not report it
        return response

    monkeypatch.setattr(source, "copy_object", copy_object)
    result = move()
    assert result["copied"] is True
    assert result["moved"] is False
    assert result["source_kept_reason"] == "SOURCE_CHANGED"
    assert body(source, "move-source", "file") == b"v2"


def test_unversioned_copy_reporting_a_version_still_moves(source, monkeypatch):
    original_copy = source.copy_object

    def copy_object(**kwargs):
        response = original_copy(**kwargs)
        response["CopySourceVersionId"] = "null"  # some S3-compatible backends report one
        return response

    monkeypatch.setattr(source, "copy_object", copy_object)
    assert move()["moved"] is True
