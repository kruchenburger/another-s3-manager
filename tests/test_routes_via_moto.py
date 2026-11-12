"""Reference patterns for testing web routes against an in-memory S3 backend.

These tests are intentionally minimal — one per HTTP verb that the refactored
/api/buckets/* web routes use. Future contributors writing similar tests should
start here.

See `tests/conftest.py::moto_s3` for the fixture definition. The fixture wraps
the test in a `mock_aws()` context, so boto3.client('s3', ...) calls (including
the ones inside `s3_client._for_role` helpers) hit the mock backend without any
extra wiring.

The pattern is:
  1. Log in via `tests/test_main.py::login` (re-exported here)
  2. Pre-create buckets/objects via the moto_s3 fixture
  3. Make the HTTP request through the app_client
  4. Assert response shape + side effects via moto_s3 reads
"""

import pytest

from tests.test_main import login


def test_get_buckets_lists_moto_buckets(app_client, moto_s3):
    """GET → list_buckets_for_role → boto3 → moto returns real bucket names."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="reference-alpha")
    moto_s3.create_bucket(Bucket="reference-beta")

    response = app_client.get("/api/buckets?role=Default", headers=headers)

    assert response.status_code == 200
    names = response.json()
    assert "reference-alpha" in names
    assert "reference-beta" in names


def test_post_upload_writes_to_moto_bucket(app_client, moto_s3):
    """POST → put_object_for_role → boto3 → moto stores body + ContentType."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="reference-up")
    payload = b"reference-payload"

    response = app_client.post(
        "/api/buckets/reference-up/upload",
        data={"role": "Default", "key": "ref.txt"},
        files={"file": ("ref.txt", payload, "text/plain")},
        headers=headers,
    )

    assert response.status_code == 200
    stored = moto_s3.get_object(Bucket="reference-up", Key="ref.txt")
    assert stored["Body"].read() == payload


def test_delete_removes_from_moto_bucket(app_client, moto_s3):
    """DELETE → delete_object_for_role → boto3 → moto removes the object."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="reference-del")
    moto_s3.put_object(Bucket="reference-del", Key="goodbye.txt", Body=b"bye")

    response = app_client.delete(
        "/api/buckets/reference-del/files?path=goodbye.txt&role=Default",
        headers=headers,
    )

    assert response.status_code == 200

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="reference-del").get("Contents", [])}
    assert "goodbye.txt" not in remaining


def test_moto_fixture_smoke(moto_s3):
    """Verify mock_aws intercepts boto3 globally so helpers see fake S3.

    This is the lowest-level sanity check — exercises `list_buckets_for_role`
    directly (not via HTTP) so future debugging of moto/boto3 interception
    issues has a clear starting point.
    """
    moto_s3.create_bucket(Bucket="smoke-bucket")

    from another_s3_manager.s3_client import list_buckets_for_role

    buckets = list_buckets_for_role(
        "Default",
        {"username": "admin", "is_admin": True, "allowed_roles": []},
    )
    assert "smoke-bucket" in buckets


def test_web_folder_delete_refused_for_role_keeps_objects(app_client, moto_s3):
    from another_s3_manager import config

    _, headers = login(app_client)
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = False
    config.save_config(cfg)
    moto_s3.create_bucket(Bucket="blocked-delete")
    for key in ["folder/", "folder/a", "folder/b"]:
        moto_s3.put_object(Bucket="blocked-delete", Key=key, Body=b"keep")
    response = app_client.delete("/api/buckets/blocked-delete/files?path=folder/&role=Default", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "code": "DELETION_DISABLED_FOR_ROLE",
        "message": "Deleting is turned off for role 'Default'",
    }
    assert {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="blocked-delete")["Contents"]} == {
        "folder/",
        "folder/a",
        "folder/b",
    }


def test_web_delete_calls_access_policy(app_client, moto_s3, monkeypatch):
    from unittest.mock import Mock

    from another_s3_manager.access import AccessDenied, service

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="guarded")
    moto_s3.put_object(Bucket="guarded", Key="x", Body=b"keep")
    guard = Mock(side_effect=AccessDenied("DELETION_DISABLED_FOR_ROLE", "Deleting is turned off for role 'Default'"))
    monkeypatch.setattr(service, "require_delete", guard)
    response = app_client.delete("/api/buckets/guarded/files?path=x&role=Default", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "DELETION_DISABLED_FOR_ROLE"
    assert guard.call_args.args[0] == "Default"
    assert moto_s3.get_object(Bucket="guarded", Key="x")["Body"].read() == b"keep"


def test_no_delete_role_config_round_trip_and_upload_overwrite(app_client, moto_s3):
    from another_s3_manager import config

    _, headers = login(app_client)
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = False
    config.save_config(cfg)
    assert app_client.get("/api/config", headers=headers).json()["roles"][0]["allow_delete"] is False
    moto_s3.create_bucket(Bucket="overwrite-allowed")
    moto_s3.put_object(Bucket="overwrite-allowed", Key="same.txt", Body=b"old")
    response = app_client.post(
        "/api/buckets/overwrite-allowed/upload",
        data={"role": "Default", "key": "same.txt"},
        files={"file": ("same.txt", b"new", "text/plain")},
        headers=headers,
    )
    assert response.status_code == 200
    assert moto_s3.get_object(Bucket="overwrite-allowed", Key="same.txt")["Body"].read() == b"new"


@pytest.mark.parametrize("denial", ["role", "bucket"])
def test_web_delete_hides_inaccessible_role_policy(app_client, denial):
    from another_s3_manager import config
    from tests.test_main import create_user

    cfg = config.load_config()
    cfg["roles"][0].update(allow_delete=False, allowed_buckets=["allowed-bucket"])
    config.save_config(cfg)
    create_user("limited", allowed_roles=[] if denial == "role" else ["Default"])
    _, headers = login(app_client, "limited", "password")
    response = app_client.delete("/api/buckets/secret-bucket/files?path=file&role=Default", headers=headers)
    assert response.status_code == 403
    assert "DELETION_DISABLED_FOR_ROLE" not in response.text
    assert ("permission to use role" if denial == "role" else "allowed_buckets") in response.text


def test_web_delete_maps_storage_policy_revocation(app_client, monkeypatch):
    from another_s3_manager import main
    from another_s3_manager.access import AccessDenied

    _, headers = login(app_client)

    def denied(*args):
        raise AccessDenied("DELETION_DISABLED_FOR_ROLE", "revoked")

    monkeypatch.setattr(main, "delete_object_for_role", denied)
    response = app_client.delete("/api/buckets/unused/files?path=x&role=Default", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == {"code": "DELETION_DISABLED_FOR_ROLE", "message": "revoked"}


def test_web_delete_reports_objects_deleted_before_revocation(app_client, monkeypatch):
    from another_s3_manager import main
    from another_s3_manager.access import AccessDenied

    _, headers = login(app_client)

    def revoked_after_first_batch(*args):
        raise AccessDenied("DELETION_DISABLED_FOR_ROLE", "Deleting is turned off for role 'Default'", {"count": 1000})

    monkeypatch.setattr(main, "delete_object_for_role", revoked_after_first_batch)
    response = app_client.delete("/api/buckets/unused/files?path=folder/&role=Default", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "code": "DELETION_DISABLED_FOR_ROLE",
        "message": "Deleting is turned off for role 'Default'. 1000 object(s) were deleted before the change.",
        "count": 1000,
    }


def test_config_post_rejects_inherited_invalid_delete_permission(app_client):
    from another_s3_manager import config

    _, headers = login(app_client)
    cfg = config.load_config()
    cfg["roles"][0]["allow_delete"] = "false"
    config.save_config(cfg)
    response = app_client.post("/api/config", json={"roles": [{"name": "Default", "type": "default"}]}, headers=headers)
    assert response.status_code == 422
    assert response.json()["detail"] == "allow_delete must be boolean"
    assert config.load_config(force_reload=True)["roles"][0]["allow_delete"] == "false"
