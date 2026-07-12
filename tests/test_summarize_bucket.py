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


def test_summary_extension_edge_cases(moto_s3):
    """The brief's own extension-parsing edge cases, pinned so a future
    refactor can't silently change the rule: a dotfile IS its own extension
    ('.env' -> 'env'), a trailing dot has no extension ('(none)'), a bare
    extensionless basename also falls into '(none)', and an oversized
    "extension" is truncated to _MAX_EXTENSION_LENGTH chars rather than
    rendered verbatim (the fix for the response-size honesty gap)."""
    long_ext = "x" * 900
    _seed(
        moto_s3,
        "summary-ext-edge",
        [
            (".env", 1),
            ("trailing.", 1),
            ("README", 1),
            (f"huge.{long_ext}", 1),
        ],
    )

    result = mod.summarize_bucket_for_role("Default", "summary-ext-edge", "", _user(), max_keys=50_000)

    by_ext = {e["ext"]: e for e in result["extensions"]}
    assert by_ext["env"]["objects"] == 1
    assert by_ext["(none)"]["objects"] == 2  # "trailing." and "README"

    truncated = long_ext[: mod._MAX_EXTENSION_LENGTH]
    assert len(truncated) == mod._MAX_EXTENSION_LENGTH
    assert truncated in by_ext
    assert by_ext[truncated]["objects"] == 1
    # The full 900-char string must never appear as an ext key.
    assert long_ext not in by_ext


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


def test_summary_cap_hits_mid_page(moto_s3):
    """max_keys that is NOT a multiple of the 1000-key S3 page size must hit
    the cap INSIDE a page's Contents loop, not on an IsTruncated page
    boundary. Every other cap test in this file uses a max_keys value that is
    a multiple of 1000, so the walk always exits via the page-boundary
    branch — the mid-page break (checked before the increment, per the
    reviewed-as-correct cap placement) was previously untested even though
    it is the trickiest branch in the function and the one production
    actually exercises whenever mcp_summary_max_keys isn't a multiple of
    1000."""
    keys = [(f"f{i:05d}.txt", 1) for i in range(1600)]
    _seed(moto_s3, "summary-midpage", keys)

    result = mod.summarize_bucket_for_role("Default", "summary-midpage", "", _user(), max_keys=1500)

    assert result["scanned_objects"] == 1500
    assert result["complete"] is False
    # scan_stopped_at is the LAST key AGGREGATED, not the next one: with keys
    # f00000.txt .. f01599.txt in sort order, the 1500th aggregated key
    # (0-indexed 1499) is f01499.txt.
    expected_stop_key = sorted(key for key, _ in keys)[1499]
    assert result["scan_stopped_at"] == expected_stop_key


def test_summary_max_keys_floor_enforced(moto_s3):
    """A pathological max_keys (0, negative) must not disable the walk — the
    server-side floor (_MIN_SUMMARY_MAX_KEYS) keeps it running."""
    _seed(moto_s3, "summary-floor-maxkeys", [(f"file{i}.txt", 1) for i in range(5)])

    result = mod.summarize_bucket_for_role("Default", "summary-floor-maxkeys", "", _user(), max_keys=0)

    assert result["complete"] is True
    assert result["scanned_objects"] == 5
    assert result["total_objects"] == 5


def test_summary_prefix_scan_pages_floor_enforced(moto_s3):
    """prefix_scan_pages=0 must behave identically to 1 — Step 1 is not
    skipped entirely, and prefix_list_complete is still reported correctly."""
    _seed(moto_s3, "summary-floor-pages", [("a/f.txt", 1), ("b/f.txt", 1)])

    result_zero = mod.summarize_bucket_for_role(
        "Default", "summary-floor-pages", "", _user(), max_keys=50_000, prefix_scan_pages=0
    )
    result_one = mod.summarize_bucket_for_role(
        "Default", "summary-floor-pages", "", _user(), max_keys=50_000, prefix_scan_pages=1
    )

    assert result_zero["prefix_list_complete"] is True
    assert result_zero["prefix_count"] == 2
    assert result_zero["prefix_list_complete"] == result_one["prefix_list_complete"]
    assert result_zero["prefix_count"] == result_one["prefix_count"]


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
    # prefix_count must equal len(all_prefixes) (the union), never the raw
    # Step-1 count: Step 1 exhausted its 1-page budget on 1000 loose-object
    # keys before it ever saw a CommonPrefix, so step1_prefixes is empty here
    # — a prefix_count of 0 next to a non-empty `prefixes` list (["zzz/"])
    # would be exactly the contradiction this feature exists to eliminate.
    assert result["prefix_count"] == 1


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
    """300 distinct prefixes x 60 distinct extensions, with REALISTIC (not
    toy) key lengths, must NOT re-create the flood: the serialized response
    stays bounded and the truncation flags are set. If this test fails, we
    fixed one firehose by building another.

    Response size is dominated by KEY LENGTH, not object count: ~30 rendered
    entries carry a full key verbatim (_TOP_PREFIXES=20 prefixes +
    _TOP_LARGEST=10 largest_objects — extensions are capped to
    _MAX_EXTENSION_LENGTH chars regardless of key length, and largest_objects
    keys are intentionally NOT truncated so an agent can pass them straight
    into read_file). So the real bound is ~30 * max_key_length, not something
    that scales with how many objects exist in the bucket.

    The original version of this test seeded 13-character keys, which passed
    the old "< 5 KB" assertion with enormous headroom without ever exercising
    the failure mode it claims to guard against. This seed uses data-lake
    style ~120-char keys for the bulk of the bucket, plus the 10 largest
    objects (by construction, monotonically increasing size) padded to
    within a byte of S3's 1024-byte key ceiling — the actual worst case.
    """
    keys = []
    for i in range(300):
        prefix_part = f"p{i:03d}/raw/partition-date=2026-07-{(i % 28) + 1:02d}/region=eu-central-1/"
        filename_part = f"some-realistically-long-descriptive-object-key-segment-{i:04d}"
        ext_part = f".e{i % 60:02d}"
        if i >= 290:  # top 10 by size (see below) — also push key length near S3's cap
            base_len = len(prefix_part) + len(filename_part) + len(ext_part)
            pad_len = max(0, 1024 - base_len - 1)  # 1-byte safety margin under the 1024-byte cap
            filename_part += "k" * pad_len
        key = prefix_part + filename_part + ext_part
        size = i + 1  # monotonically increasing so i in [290, 299] are the top-10 largest
        keys.append((key, size))
    _seed(moto_s3, "summary-huge", keys)

    result = mod.summarize_bucket_for_role("Default", "summary-huge", "", _user(), max_keys=50_000)

    assert len(result["prefixes"]) == 20
    assert len(result["extensions"]) == 20
    assert len(result["largest_objects"]) == 10
    assert result["prefixes_truncated"] is True
    assert result["extensions_truncated"] is True
    assert result["prefix_count"] == 300
    assert result["extension_count"] == 60
    # The near-1024-byte keys (i in [290, 299]) are guaranteed to be exactly
    # the largest_objects entries by construction (monotonic sizes) — assert
    # the worst case is actually present, not just that the byte count is low.
    assert all(len(o["key"]) > 900 for o in result["largest_objects"])

    serialized = json.dumps(result, default=str).encode("utf-8")
    assert len(serialized) < 40 * 1024, f"response is {len(serialized)} bytes — must stay bounded"


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
