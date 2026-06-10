"""Backend tests for server-side prefix search (the `name_prefix` extension of
the /v2 client-load listing). See the 2026-06-10 prefix-search design (out-of-repo)."""

import pytest

from another_s3_manager.s3_client import list_objects_client_load_for_role
from another_s3_manager.utils import sanitize_search_prefix

ADMIN = {"username": "admin", "is_admin": True, "allowed_roles": []}


def _seed(moto_s3, bucket, *, files, directories):
    moto_s3.create_bucket(Bucket=bucket)
    for f in files:
        moto_s3.put_object(Bucket=bucket, Key=f, Body=b"")
    for d in directories:
        moto_s3.put_object(Bucket=bucket, Key=f"{d}/", Body=b"")


def test_name_prefix_filters_current_level_dirs_and_files(moto_s3):
    """name_prefix returns only current-level dirs+files whose NAME starts with it."""
    _seed(
        moto_s3,
        "ps-level",
        files=["4f2a-note.txt", "other.txt"],
        directories=["4f2a1c", "4f2a9b", "99zz"],
    )

    result = list_objects_client_load_for_role(
        role=None,
        bucket="ps-level",
        path="",
        user_dict=ADMIN,
        max_client_load=100,
        name_prefix="4f2a",
    )

    assert [d["name"] for d in result["directories"]] == ["4f2a1c", "4f2a9b"]
    assert [f["name"] for f in result["files"]] == ["4f2a-note.txt"]
    assert "99zz" not in [d["name"] for d in result["directories"]]
    assert "other.txt" not in [f["name"] for f in result["files"]]


def test_empty_name_prefix_is_unchanged_listing(moto_s3):
    """name_prefix='' (default) is byte-for-byte the normal folder listing."""
    _seed(
        moto_s3,
        "ps-empty",
        files=["a.txt", "b.txt"],
        directories=["d1", "d2"],
    )

    plain = list_objects_client_load_for_role(
        role=None,
        bucket="ps-empty",
        path="",
        user_dict=ADMIN,
        max_client_load=100,
    )
    explicit_empty = list_objects_client_load_for_role(
        role=None,
        bucket="ps-empty",
        path="",
        user_dict=ADMIN,
        max_client_load=100,
        name_prefix="",
    )
    assert plain == explicit_empty
    assert [d["name"] for d in plain["directories"]] == ["d1", "d2"]
    assert [f["name"] for f in plain["files"]] == ["a.txt", "b.txt"]


def test_name_prefix_within_subfolder_strips_to_child_name(moto_s3):
    """Under a non-root path, child names are stripped relative to the folder,
    not the search prefix (so 'logs/app2026/' shows as 'app2026')."""
    _seed(
        moto_s3,
        "ps-sub",
        files=[],
        directories=["logs/app2026", "logs/app2025", "logs/other"],
    )

    result = list_objects_client_load_for_role(
        role=None,
        bucket="ps-sub",
        path="logs",
        user_dict=ADMIN,
        max_client_load=100,
        name_prefix="app",
    )
    assert [d["name"] for d in result["directories"]] == ["app2025", "app2026"]


def test_name_prefix_truncation_and_continuation(moto_s3):
    """A prefix matching more than one chunk truncates and continues correctly."""
    _seed(
        moto_s3,
        "ps-trunc",
        files=[f"p-{i:03d}.txt" for i in range(12)] + ["zzz.txt"],
        directories=[],
    )

    page1 = list_objects_client_load_for_role(
        role=None,
        bucket="ps-trunc",
        path="",
        user_dict=ADMIN,
        max_client_load=5,
        name_prefix="p-",
    )
    assert page1["truncated"] is True
    assert page1["next_token"] is not None
    assert [f["name"] for f in page1["files"]] == [f"p-{i:03d}.txt" for i in range(5)]

    page2 = list_objects_client_load_for_role(
        role=None,
        bucket="ps-trunc",
        path="",
        user_dict=ADMIN,
        max_client_load=5,
        name_prefix="p-",
        continuation_token=page1["next_token"],
    )
    assert [f["name"] for f in page2["files"]] == [f"p-{i:03d}.txt" for i in range(5, 10)]
    assert all(f["name"].startswith("p-") for f in page2["files"])


def test_name_prefix_exact_file_match(moto_s3):
    """A name_prefix equal to an exact filename still returns that file."""
    _seed(moto_s3, "ps-exact", files=["match.csv", "other.txt"], directories=[])
    result = list_objects_client_load_for_role(
        role=None,
        bucket="ps-exact",
        path="",
        user_dict=ADMIN,
        max_client_load=100,
        name_prefix="match.csv",
    )
    assert [f["name"] for f in result["files"]] == ["match.csv"]


def test_name_prefix_no_match_returns_empty(moto_s3):
    """A name_prefix that matches nothing returns empty dirs+files, not truncated."""
    _seed(moto_s3, "ps-none", files=["a.txt"], directories=["dir1"])
    result = list_objects_client_load_for_role(
        role=None,
        bucket="ps-none",
        path="",
        user_dict=ADMIN,
        max_client_load=100,
        name_prefix="zzz",
    )
    assert result["directories"] == []
    assert result["files"] == []
    assert result["truncated"] is False
    assert result["next_token"] is None


def test_sanitize_search_prefix_trims_and_passes_literals():
    assert sanitize_search_prefix("  4f2a  ") == "4f2a"
    # `..` and `/` are legal literal S3 key bytes — they pass through.
    assert sanitize_search_prefix("a/b") == "a/b"
    assert sanitize_search_prefix("..x") == "..x"


def test_sanitize_search_prefix_empty_is_empty():
    assert sanitize_search_prefix("") == ""
    assert sanitize_search_prefix("   ") == ""


def test_sanitize_search_prefix_rejects_control_chars():
    with pytest.raises(ValueError):
        sanitize_search_prefix("a\x00b")
    with pytest.raises(ValueError):
        sanitize_search_prefix("a\x1fb")


def test_route_search_filters_current_level(app_client, moto_s3):
    """client_load=1&search=<prefix> returns only matching current-level items."""
    from tests.test_main import login

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="ps-route")
    for d in ["4f2a1c", "4f2a9b", "99zz"]:
        moto_s3.put_object(Bucket="ps-route", Key=f"{d}/", Body=b"")
    moto_s3.put_object(Bucket="ps-route", Key="4f2a-note.txt", Body=b"")
    moto_s3.put_object(Bucket="ps-route", Key="other.txt", Body=b"")

    response = app_client.get(
        "/api/buckets/ps-route/files?client_load=1&search=4f2a",
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert {d["name"] for d in body["directories"]} == {"4f2a1c", "4f2a9b"}
    assert {f["name"] for f in body["files"]} == {"4f2a-note.txt"}


def test_route_search_without_client_load_is_400(app_client, moto_s3):
    from tests.test_main import login

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="ps-guard")

    response = app_client.get(
        "/api/buckets/ps-guard/files?search=abc",
        headers=headers,
    )
    assert response.status_code == 400
    assert "client_load" in response.json()["detail"]


def test_route_blank_search_is_noop(app_client, moto_s3):
    """A whitespace-only search is treated as absent (full folder listing)."""
    from tests.test_main import login

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="ps-blank")
    moto_s3.put_object(Bucket="ps-blank", Key="a.txt", Body=b"")
    moto_s3.put_object(Bucket="ps-blank", Key="b.txt", Body=b"")

    response = app_client.get(
        "/api/buckets/ps-blank/files?client_load=1&search=%20%20",
        headers=headers,
    )
    assert response.status_code == 200
    assert {f["name"] for f in response.json()["files"]} == {"a.txt", "b.txt"}


def test_route_overlong_search_is_422(app_client, moto_s3):
    from tests.test_main import login

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="ps-long")

    response = app_client.get(
        f"/api/buckets/ps-long/files?client_load=1&search={'x' * 1025}",
        headers=headers,
    )
    assert response.status_code == 422  # FastAPI Query max_length


def test_route_control_char_search_is_400(app_client, moto_s3):
    """A control char in search trips the route's ValueError → 400 path."""
    from tests.test_main import login

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="ps-ctrl")

    response = app_client.get(
        "/api/buckets/ps-ctrl/files?client_load=1&search=a%00b",
        headers=headers,
    )
    assert response.status_code == 400
