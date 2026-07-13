"""Pins the Fix-1 docstring contract (2026-07-13 MCP best-practices pass).

Anthropic's tool-design guidance, verbatim: "Write detailed descriptions —
Claude uses these to decide when to use the tool. Be prescriptive about
*when* to call it, not just what it does." read_file used to be pure
"what it does" — this file pins that it now names its alternatives (
get_object_metadata, presigned_url) in the docstring itself, not just inside
the BINARY_CONTENT/FILE_TOO_LARGE error bodies the agent only sees after
wasting a call. It also pins that list_buckets' docstring names list_roles
as its prerequisite.

Deliberately narrow: every assertion here pins a NAMED alternative or a
concrete warning word actually present in the docstring — not a loose
keyword sniff like `"first" in doc.lower()`, which can't fail for the right
reason (the word can appear anywhere in any rewrite and proves nothing about
whether the redirect survived).
"""

from another_s3_manager.mcp_server import mcp


def _doc(name: str) -> str:
    tool = mcp._tool_manager._tools[name]
    return tool.description or ""


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


def test_read_file_docstring_names_get_object_metadata_alternative():
    """When the agent only needs size/type/content-type, the docstring must
    redirect to get_object_metadata — not just the error body."""
    assert "get_object_metadata" in _doc("read_file")


def test_read_file_docstring_names_presigned_url_alternative():
    """For binary or oversized files, the docstring must redirect to
    presigned_url — not just the BINARY_CONTENT/FILE_TOO_LARGE error body."""
    assert "presigned_url" in _doc("read_file")


def test_read_file_docstring_names_its_own_error_codes():
    """Pin the actual McpError codes read_file raises (FILE_TOO_LARGE,
    BINARY_CONTENT), not generic words like "binary" or "large"/"size" —
    those can appear anywhere in any rewrite and prove nothing (e.g. "size"
    is a substring of "oversized", so a loose `"size" in doc` check is
    near-unfalsifiable). The codes are the concrete, machine-checkable
    contract: they're what the agent actually sees in the error message
    (McpError.__str__ always keeps "{code}: " first), so the docstring
    naming them is what lets the agent correlate a future error with the
    redirect it already read up front."""
    doc = _doc("read_file")
    assert "FILE_TOO_LARGE" in doc
    assert "BINARY_CONTENT" in doc


# ---------------------------------------------------------------------------
# list_buckets — names list_roles as its prerequisite
# ---------------------------------------------------------------------------


def test_list_buckets_docstring_names_list_roles_prerequisite():
    """list_buckets needs a role name, which only list_roles supplies — the
    docstring must name list_roles, not just gesture at "call something
    first" (a claim no rewrite could ever fail to satisfy)."""
    assert "list_roles" in _doc("list_buckets")
