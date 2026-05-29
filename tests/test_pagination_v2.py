"""Backend tests for the paginated /v2 file listing.

See spec: spec dated 2026-05-29 (pagination-v2 design).
"""


def _seed(moto_s3, bucket: str, *, files: list[str], directories: list[str]) -> None:
    """Pre-populate a bucket with empty-body files plus directory markers."""
    moto_s3.create_bucket(Bucket=bucket)
    for f in files:
        moto_s3.put_object(Bucket=bucket, Key=f, Body=b"")
    for d in directories:
        # CommonPrefix detection in S3 requires at least one object UNDER the
        # prefix. We seed a hidden sentinel so list_objects_v2 surfaces the
        # directory in CommonPrefixes.
        moto_s3.put_object(Bucket=bucket, Key=f"{d}/.keep", Body=b"")


def test_paginated_first_page_returns_directories_and_first_files(moto_s3):
    """First call (no continuation_token) returns CommonPrefixes as
    `directories` plus the first `max_keys` files."""
    from another_s3_manager.s3_client import list_objects_paginated_for_role

    _seed(
        moto_s3,
        "paginated-alpha",
        files=["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"],
        directories=["dir1", "dir2"],
    )

    result = list_objects_paginated_for_role(
        role=None,
        bucket="paginated-alpha",
        path="",
        user_dict={"username": "admin", "is_admin": True, "allowed_roles": []},
        max_keys=2,
    )

    # CommonPrefixes from this bucket should land in `directories`, both of them.
    dir_names = [d["name"] for d in result["directories"]]
    assert dir_names == ["dir1", "dir2"]
    assert all(d["is_directory"] is True for d in result["directories"])

    # max_keys=2 means at most 2 file entries on this page.
    assert len(result["files"]) == 2
    assert result["files"][0]["name"] == "a.txt"
    assert result["files"][1]["name"] == "b.txt"
    assert all(f["is_directory"] is False for f in result["files"])

    # IsTruncated → next_token + has_more=True.
    assert result["has_more"] is True
    assert result["next_token"] is not None
    assert isinstance(result["next_token"], str) and len(result["next_token"]) > 0
