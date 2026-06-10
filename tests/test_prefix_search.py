"""Backend tests for server-side prefix search (the `name_prefix` extension of
the /v2 client-load listing). See the 2026-06-10 prefix-search design (out-of-repo)."""

from another_s3_manager.s3_client import list_objects_client_load_for_role

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
