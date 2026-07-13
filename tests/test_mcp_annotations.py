"""Pins the readOnlyHint/destructiveHint/idempotentHint annotations set on
each of the 10 MCP tools (Fix 3, 2026-07-13 MCP best-practices pass).

Per mcp.types.ToolAnnotations: destructiveHint/idempotentHint are documented
as "meaningful only when readOnlyHint == false" — so the 7 read-only tools
intentionally leave them unset (None) rather than set a value that isn't
meaningful for a read-only tool. Where a write tool's real behavior isn't
uniformly idempotent across its whole argument space, idempotentHint is also
left unset rather than guessed — see the per-tool tests below for the s3_client
behavior that backs each decision.
"""

import pytest

from another_s3_manager.mcp_server import mcp

READ_ONLY_TOOLS = [
    "list_roles",
    "list_buckets",
    "list_files",
    "bucket_summary",
    "read_file",
    "get_object_metadata",
    "presigned_url",
]

WRITE_TOOLS = ["upload_file", "delete_file", "copy_object"]


def _annotations(name: str):
    tool = mcp._tool_manager._tools[name]
    assert tool.annotations is not None, f"{name} has no annotations set"
    return tool.annotations


# ---------------------------------------------------------------------------
# Read-only tools (7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", READ_ONLY_TOOLS)
def test_read_only_tool_is_annotated_read_only(name):
    assert _annotations(name).readOnlyHint is True


@pytest.mark.parametrize("name", READ_ONLY_TOOLS)
def test_read_only_tool_leaves_destructive_and_idempotent_unset(name):
    ann = _annotations(name)
    assert ann.destructiveHint is None
    assert ann.idempotentHint is None


# ---------------------------------------------------------------------------
# Write tools (3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", WRITE_TOOLS)
def test_write_tool_is_annotated_not_read_only(name):
    assert _annotations(name).readOnlyHint is False


def test_delete_file_is_annotated_destructive():
    """The one write tool explicitly called out as destructive."""
    assert _annotations("delete_file").destructiveHint is True


def test_delete_file_idempotent_hint_left_unset():
    """A repeat delete_file on a SINGLE KEY actually SUCCEEDS: when the
    target is already gone, delete_object_for_role's prefix listing comes
    back empty, so the non-directory branch falls through to a plain S3
    DeleteObject on that key — and AWS S3's DeleteObject returns 204 (no
    error) for a key that doesn't exist, so deleted_count is 1 and the tool
    reports success again on every repeat call. A repeat delete_file on a
    DIRECTORY path (`path` ending in "/") behaves differently: an empty
    prefix listing there leaves deleted_count at 0, which
    delete_object_for_role turns into FileNotFoundError. Same tool, same
    "target already gone" starting state, two different outcomes depending
    on whether `path` names a file or a directory — not uniformly idempotent
    across its argument space, so the hint stays unset."""
    assert _annotations("delete_file").idempotentHint is None


def test_upload_file_is_annotated_destructive():
    """put_object_for_role (s3_client.py) issues a plain S3 PutObject with no
    existence check first — it silently OVERWRITES whatever is already at
    `path`, discarding the previous object body. That is not "only additive
    updates" (the false-case definition in mcp.types.ToolAnnotations); it
    matches the official MCP filesystem server's write_file tool, which is
    annotated destructiveHint: true for the identical reason (create-or-
    overwrite at a caller-chosen path)."""
    assert _annotations("upload_file").destructiveHint is True


def test_upload_file_idempotent_hint_left_unset():
    """put_object_for_role issues a plain S3 PutObject to a fixed key — on a
    bucket WITHOUT versioning that repeat is a true no-additional-effect
    no-op, but another-s3-manager is a GENERIC S3 manager (AWS/R2/MinIO/
    Wasabi) and on any bucket WITH versioning enabled, a repeat PutObject
    mints a brand new object version — extra storage, a changed version
    history, different behavior for a later version-aware delete/restore.
    That is an additional effect the MCP idempotentHint definition
    (mcp/types.py: "calling the tool repeatedly with the same arguments will
    have no additional effect on its environment") explicitly rules out, so
    the hint stays unset rather than being true only for some configurations
    this tool can run against."""
    assert _annotations("upload_file").idempotentHint is None


def test_copy_object_is_annotated_destructive():
    """copy_object_for_role (s3_client.py) issues S3 CopyObject with no
    existence check on the destination — a pre-existing object at
    `dest_path` is silently overwritten. Same overwrite-without-checking
    shape as upload_file, so the same destructiveHint=true applies."""
    assert _annotations("copy_object").destructiveHint is True


def test_copy_object_idempotent_hint_left_unset():
    """copy_object(delete_source=True) deletes the source after copying —
    s3_client.copy_object_for_role raises FileNotFoundError for the source on
    a repeat call, so the tool is not uniformly idempotent across its
    argument space (delete_source=False alone would be, delete_source=True
    is not)."""
    assert _annotations("copy_object").idempotentHint is None
