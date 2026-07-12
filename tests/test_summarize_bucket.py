"""Unit tests for s3_client.summarize_bucket_for_role via the moto in-memory S3 backend.

Pattern reference: tests/test_routes_via_moto.py + tests/conftest.py::moto_s3.
The isolated_environment autouse fixture provides a config with a single
"Default" role (type "default"), so get_s3_client("Default") builds a plain
boto3 client that mock_aws intercepts.

NOTE: two tests seed ~1000+ objects to cross the helper's hard floor of
max_keys >= 1000 — they take a few seconds each under moto. That is expected.
"""

import json

import pytest

import another_s3_manager.s3_client as mod


def _user(allowed=("Default",), admin=False):
    return {"username": "tester", "is_admin": admin, "allowed_roles": list(allowed)}


def _seed(moto_s3, bucket, keys_sizes):
    moto_s3.create_bucket(Bucket=bucket)
    for key, size in keys_sizes:
        moto_s3.put_object(Bucket=bucket, Key=key, Body=b"x" * size)


# ---------------------------------------------------------------------------
# _human_bytes
# ---------------------------------------------------------------------------


def test_human_bytes_formats():
    assert mod._human_bytes(0) == "0 B"
    assert mod._human_bytes(150) == "150 B"
    assert mod._human_bytes(1536) == "1.5 KB"
    assert mod._human_bytes(52_428_800) == "50.0 MB"


# ---------------------------------------------------------------------------
# Complete walk — aggregation math
# ---------------------------------------------------------------------------


def test_summary_complete_small_bucket(moto_s3):
    """Counts, bytes, extension histogram, per-prefix stats, root objects — all exact."""
    _seed(
        moto_s3,
        "summary-small",
        [
            ("a.txt", 10),
            ("b.log", 20),
            ("logs/x.log", 30),
            ("logs/y.log", 40),
            ("img/photo.jpg", 50),
        ],
    )
    # Zero-byte directory marker must be skipped.
    moto_s3.put_object(Bucket="summary-small", Key="img/", Body=b"")

    result = mod.summarize_bucket_for_role("Default", "summary-small", "", _user(), max_keys=50_000)

    assert result["bucket"] == "summary-small"
    assert result["path"] == ""
    assert result["complete"] is True
    assert result["scanned_objects"] == 5
    assert result["scanned_bytes"] == 150
    assert result["scanned_bytes_human"] == "150 B"
    assert result["total_objects"] == 5
    assert result["total_bytes"] == 150
    assert result["total_bytes_human"] == "150 B"
    assert result["scan_stopped_at"] is None
    assert result["root_objects"] == 2

    assert result["prefix_count"] == 2
    assert result["prefix_list_complete"] is True
    assert result["prefixes_truncated"] is False
    by_prefix = {p["prefix"]: p for p in result["prefixes"]}
    assert by_prefix["logs/"] == {"prefix": "logs/", "objects": 2, "bytes": 70, "coverage": "complete"}
    assert by_prefix["img/"] == {"prefix": "img/", "objects": 1, "bytes": 50, "coverage": "complete"}
    # Final list is presented in key (lexicographic) order.
    assert [p["prefix"] for p in result["prefixes"]] == sorted(p["prefix"] for p in result["prefixes"])

    by_ext = {e["ext"]: e for e in result["extensions"]}
    assert by_ext["log"] == {"ext": "log", "objects": 3, "bytes": 90}
    assert by_ext["txt"] == {"ext": "txt", "objects": 1, "bytes": 10}
    assert by_ext["jpg"] == {"ext": "jpg", "objects": 1, "bytes": 50}
    assert result["extension_count"] == 3
    assert result["extensions_truncated"] is False

    assert result["largest_objects"][0]["key"] == "img/photo.jpg"
    assert result["largest_objects"][0]["size"] == 50
    assert result["oldest_modified"] is not None
    assert result["newest_modified"] is not None


def test_summary_empty_bucket(moto_s3):
    moto_s3.create_bucket(Bucket="summary-empty")

    result = mod.summarize_bucket_for_role("Default", "summary-empty", "", _user(), max_keys=50_000)

    assert result["complete"] is True
    assert result["scanned_objects"] == 0
    assert result["scanned_bytes"] == 0
    assert result["total_objects"] == 0
    assert result["total_bytes"] == 0
    assert result["root_objects"] == 0
    assert result["prefixes"] == []
    assert result["prefix_count"] == 0
    assert result["extensions"] == []
    assert result["largest_objects"] == []
    assert result["oldest_modified"] is None
    assert result["newest_modified"] is None


def test_summary_flat_bucket_no_prefixes(moto_s3):
    _seed(moto_s3, "summary-flat", [(f"file{i}.txt", 1) for i in range(5)])

    result = mod.summarize_bucket_for_role("Default", "summary-flat", "", _user(), max_keys=50_000)

    assert result["complete"] is True
    assert result["prefix_count"] == 0
    assert result["prefixes"] == []
    assert result["root_objects"] == 5


def test_summary_no_extension_goes_to_none_bucket(moto_s3):
    _seed(moto_s3, "summary-noext", [("README", 5), ("Makefile", 5), ("notes.txt", 5)])

    result = mod.summarize_bucket_for_role("Default", "summary-noext", "", _user(), max_keys=50_000)

    by_ext = {e["ext"]: e for e in result["extensions"]}
    assert by_ext["(none)"]["objects"] == 2
    assert by_ext["txt"]["objects"] == 1


def test_summary_scoped_to_prefix(moto_s3):
    """path scoping: only keys under the prefix are aggregated; child prefixes are full keys."""
    _seed(
        moto_s3,
        "summary-scoped",
        [("logs/2025/a.log", 1), ("logs/2026/b.log", 2), ("other/c.txt", 4)],
    )

    result = mod.summarize_bucket_for_role("Default", "summary-scoped", "logs/", _user(), max_keys=50_000)

    assert result["path"] == "logs/"
    assert result["scanned_objects"] == 2
    assert result["scanned_bytes"] == 3
    assert result["prefix_count"] == 2
    assert {p["prefix"] for p in result["prefixes"]} == {"logs/2025/", "logs/2026/"}
    assert result["root_objects"] == 0


def test_summary_largest_objects_top10(moto_s3):
    _seed(moto_s3, "summary-largest", [(f"f{i:02d}.bin", i + 1) for i in range(12)])

    result = mod.summarize_bucket_for_role("Default", "summary-largest", "", _user(), max_keys=50_000)

    sizes = [o["size"] for o in result["largest_objects"]]
    assert len(sizes) == 10
    assert sizes == sorted(sizes, reverse=True)
    assert sizes[0] == 12
    assert min(sizes) == 3  # sizes 1 and 2 fell off the top-10


# ---------------------------------------------------------------------------
# Cap behaviour + coverage classification (needs >1000 keys — floor is 1000)
# ---------------------------------------------------------------------------


def test_summary_cap_and_coverage_classification(moto_s3):
    """Cap hit mid-walk: exact scanned count, complete/partial/not_scanned, total_* null."""
    keys = [(f"archive/f{i:04d}.bin", 1) for i in range(300)]
    keys += [(f"logs/f{i:04d}.log", 1) for i in range(800)]
    keys += [(f"uploads/f{i:04d}.dat", 1) for i in range(5)]
    _seed(moto_s3, "summary-capped", keys)

    result = mod.summarize_bucket_for_role("Default", "summary-capped", "", _user(), max_keys=1000)

    assert result["complete"] is False
    assert result["scanned_objects"] == 1000  # cap honoured exactly
    assert result["total_objects"] is None
    assert result["total_bytes"] is None
    assert result["total_bytes_human"] is None
    assert result["scan_stopped_at"] is not None
    assert result["scan_stopped_at"].startswith("logs/")

    by_prefix = {p["prefix"]: p for p in result["prefixes"]}
    assert by_prefix["archive/"]["coverage"] == "complete"
    assert by_prefix["archive/"]["objects"] == 300
    assert by_prefix["logs/"]["coverage"] == "partial"
    assert by_prefix["logs/"]["objects"] == 700  # only what was walked
    assert by_prefix["uploads/"]["coverage"] == "not_scanned"
    assert by_prefix["uploads/"]["objects"] is None
    assert by_prefix["uploads/"]["bytes"] is None


def test_summary_root_objects_from_walk_and_step1_budget_honesty(moto_s3):
    """Two honesty guarantees in one seed:

    1. root_objects comes from the WALK, not from Step 1 — with 1050 loose
       objects (more than one Step-1 page) it must still be exactly 1050.
       (The Step-1-derived version would silently under-report at <=1000.)
    2. Step 1's own budget: with prefix_scan_pages=1 the delimiter listing
       cannot finish, so prefix_list_complete must be False — the "zzz/"
       prefix that sorts after the loose objects is NOT silently dropped
       as if it did not exist (here the walk even finds it and reports it).
    """
    keys = [(f"loose-{i:05d}.txt", 1) for i in range(1050)]
    keys.append(("zzz/late.txt", 1))
    _seed(moto_s3, "summary-budget", keys)

    result = mod.summarize_bucket_for_role(
        "Default", "summary-budget", "", _user(), max_keys=50_000, prefix_scan_pages=1
    )

    assert result["complete"] is True  # the walk itself finished (1051 < 50000)
    assert result["root_objects"] == 1050
    assert result["prefix_list_complete"] is False  # Step 1 ran out of budget
    # Walk-discovered prefix is unioned into the display list, coverage exact.
    by_prefix = {p["prefix"]: p for p in result["prefixes"]}
    assert by_prefix["zzz/"]["objects"] == 1
    assert by_prefix["zzz/"]["coverage"] == "complete"


def test_summary_step1_single_call_for_folder_shaped_bucket(moto_s3):
    """A folder-shaped bucket enumerates all prefixes in ONE delimiter request."""
    import boto3

    keys = [(f"p{i}/f{j}.txt", 1) for i in range(3) for j in range(2)]
    _seed(moto_s3, "summary-folders", keys)

    class _CountingS3:
        """Delegating proxy that counts Delimiter="/" list calls."""

        def __init__(self, inner):
            self._inner = inner
            self.delimiter_calls = 0

        def list_objects_v2(self, **kwargs):
            if kwargs.get("Delimiter") == "/":
                self.delimiter_calls += 1
            return self._inner.list_objects_v2(**kwargs)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    proxy = _CountingS3(boto3.client("s3", region_name="us-east-1"))
    original = mod.get_s3_client
    mod.get_s3_client = lambda role_name=None: proxy
    try:
        result = mod.summarize_bucket_for_role("Default", "summary-folders", "", _user(), max_keys=50_000)
    finally:
        mod.get_s3_client = original

    assert proxy.delimiter_calls == 1
    assert result["prefix_list_complete"] is True
    assert result["prefix_count"] == 3


def test_summary_prefixes_truncated_independent_of_list_complete(moto_s3):
    """25 prefixes, all enumerated: prefix_list_complete=True AND prefixes_truncated=True."""
    _seed(moto_s3, "summary-25p", [(f"p{i:02d}/only.txt", 1) for i in range(25)])

    result = mod.summarize_bucket_for_role("Default", "summary-25p", "", _user(), max_keys=50_000)

    assert result["prefix_list_complete"] is True
    assert result["prefixes_truncated"] is True
    assert result["prefix_count"] == 25
    assert len(result["prefixes"]) == 20


# ---------------------------------------------------------------------------
# THE bounded-response test — the whole point of the feature
# ---------------------------------------------------------------------------


def test_summary_response_stays_small(moto_s3):
    """300 distinct prefixes x 60 distinct extensions must NOT re-create the flood:
    the serialized response stays in the low single-digit KB and the truncation
    flags are set. If this test fails, we fixed one firehose by building another."""
    keys = [(f"p{i:03d}/file.e{i % 60:02d}", 1) for i in range(300)]
    _seed(moto_s3, "summary-huge", keys)

    result = mod.summarize_bucket_for_role("Default", "summary-huge", "", _user(), max_keys=50_000)

    assert len(result["prefixes"]) == 20
    assert len(result["extensions"]) == 20
    assert len(result["largest_objects"]) == 10
    assert result["prefixes_truncated"] is True
    assert result["extensions_truncated"] is True
    assert result["prefix_count"] == 300
    assert result["extension_count"] == 60

    serialized = json.dumps(result, default=str).encode("utf-8")
    assert len(serialized) < 5 * 1024, f"response is {len(serialized)} bytes — must stay in low single-digit KB"


# ---------------------------------------------------------------------------
# Permission denials
# ---------------------------------------------------------------------------


def test_summary_permission_denied_role(moto_s3):
    with pytest.raises(PermissionError):
        mod.summarize_bucket_for_role("NoSuchRole", "any-bucket", "", _user(allowed=("Default",)), max_keys=50_000)


def test_summary_permission_denied_bucket(mocker):
    """Bucket outside the role's allowed_buckets → PermissionError mentioning 'bucket'."""
    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["ok-bucket"]}]},
    )
    with pytest.raises(PermissionError, match="bucket"):
        mod.summarize_bucket_for_role("RoleA", "forbidden-bucket", "", _user(allowed=("RoleA",)), max_keys=50_000)
