"""Role validation at the REST bucket boundary."""

import pytest

from tests.test_main import create_user, login

ENDPOINTS = ["buckets", "files", "upload", "download", "presigned", "delete"]


def bucket_request(client, endpoint, role, headers):
    params = {"path": "file.txt"}
    if role is not None:
        params["role"] = role
    if endpoint == "upload":
        data = {"key": "file.txt"}
        if role is not None:
            data["role"] = role
        return client.post(
            "/api/buckets/test-bucket/upload",
            data=data,
            files={"file": ("file.txt", b"hello", "text/plain")},
            headers=headers,
        )
    url = "/api/buckets" if endpoint == "buckets" else f"/api/buckets/test-bucket/{endpoint}"
    if endpoint == "delete":
        return client.delete("/api/buckets/test-bucket/files", params=params, headers=headers)
    return client.get(url, params=params, headers=headers)


@pytest.mark.parametrize("endpoint", ENDPOINTS)
@pytest.mark.parametrize(
    "role,actor,expected",
    [
        (None, "member", 400),
        ("", "member", 400),
        (" \t ", "member", 400),
        ("Unknown", "admin", 400),
        ("Unknown", "member", 400),
        ("Default", "denied", 403),
    ],
)
def test_bucket_role_validation(app_client, mocker, endpoint, role, actor, expected):
    if actor != "admin":
        create_user(actor, password="password123", allowed_roles=[] if actor == "denied" else ["Default", "Unknown"])
    _, headers = login(app_client, actor, "admin123" if actor == "admin" else "password123")
    factory = mocker.patch(
        "another_s3_manager.s3_client.get_s3_client", side_effect=AssertionError("Unexpected S3 client")
    )
    response = bucket_request(app_client, endpoint, role, headers)
    factory.assert_not_called()
    assert response.status_code == expected, response.text
    if role is None or not role.strip():
        assert response.json() == {
            "detail": {"code": "ROLE_REQUIRED", "message": "A role is required for this request."}
        }


def test_explicit_role_lists_configured_buckets(app_client, mocker):
    from another_s3_manager.config import load_config, save_config

    config = load_config()
    config["roles"][0]["allowed_buckets"] = ["test-bucket"]
    save_config(config)
    create_user("member", password="password123", allowed_roles=["Default"])
    _, headers = login(app_client, "member", "password123")
    factory = mocker.patch("another_s3_manager.s3_client.get_s3_client")
    response = bucket_request(app_client, "buckets", "Default", headers)
    assert response.status_code == 200
    assert response.json() == ["test-bucket"]
    factory.assert_not_called()


@pytest.mark.parametrize("endpoint", [e for e in ENDPOINTS if e != "buckets"])
def test_bucket_scope_is_enforced(app_client, mocker, endpoint):
    from another_s3_manager.config import load_config, save_config

    config = load_config()
    config["roles"][0]["allowed_buckets"] = ["other-bucket"]
    save_config(config)
    _, headers = login(app_client)
    factory = mocker.patch("another_s3_manager.s3_client.get_s3_client")
    response = bucket_request(app_client, endpoint, "Default", headers)
    factory.assert_not_called()
    assert response.status_code == 403, response.text
