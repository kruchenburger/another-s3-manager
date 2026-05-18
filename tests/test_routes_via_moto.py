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

from tests.test_main import login


def test_get_buckets_lists_moto_buckets(app_client, moto_s3):
    """GET → list_buckets_for_role → boto3 → moto returns real bucket names."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="reference-alpha")
    moto_s3.create_bucket(Bucket="reference-beta")

    response = app_client.get("/api/buckets", headers=headers)

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
        data={"key": "ref.txt"},
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
        "/api/buckets/reference-del/files?path=goodbye.txt",
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
        None,
        {"username": "admin", "is_admin": True, "allowed_roles": []},
    )
    assert "smoke-bucket" in buckets
