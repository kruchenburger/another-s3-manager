"""Tests for the read_file MCP tool with AppFlow-aware text detection.

Covers spec §7: resolution pipeline, classification constants, sniff logic,
force_text, BOM stripping, and FILE_TOO_LARGE short-circuit.

Test isolation: tool bodies are called directly by setting the _current_request
contextvar to a fake HTTP request — same pattern as test_mcp_tools.py.
S3 helpers are monkeypatched so no real S3 is needed.
"""

from unittest.mock import MagicMock, patch

import pytest

from another_s3_manager import api_tokens as svc
from another_s3_manager.database import session_scope
from another_s3_manager.mcp_server import (
    McpError,
    _current_request,
)
from another_s3_manager.models import User, UserRole

# ---------------------------------------------------------------------------
# Shared fixtures (mirrors test_mcp_tools.py style)
# ---------------------------------------------------------------------------


@pytest.fixture
def alice_user():
    """Insert alice_rf with the 'Default' role; return (user_id, plaintext_token)."""
    with session_scope() as session:
        user = User(username="alice_rf", password_hash="x", is_admin=False)
        session.add(user)
        session.flush()
        role = UserRole(user_id=user.id, role_name="Default")
        session.add(role)
        session.flush()
        uid = user.id

    _, plaintext = svc.create_token(uid, "rf-test", is_read_only=False, max_read_bytes=10_485_760)
    return uid, plaintext


class _FakeRequest:
    """Minimal stub satisfying authenticate_mcp_request's .headers interface."""

    def __init__(self, headers: dict):
        self.headers = headers


def _fake_request(plaintext: str) -> _FakeRequest:
    return _FakeRequest({"authorization": f"Bearer {plaintext}"})


# ---------------------------------------------------------------------------
# Tool registry: build get_mcp_app() once, extract callables by name
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tool_registry():
    """Extract MCP tool callables from the module-level FastMCP instance.

    See tests/test_mcp_tools.py for full rationale (Phase 5 lifespan refactor).
    """
    from another_s3_manager.mcp_server import mcp

    return {tool.name: tool.fn for tool in mcp._tool_manager._tools.values()}


async def _call(tool_registry, name: str, request: _FakeRequest, **kwargs):
    """Set the contextvar to `request` and invoke the named tool."""
    token = _current_request.set(request)
    try:
        fn = tool_registry[name]
        return await fn(**kwargs)
    finally:
        _current_request.reset(token)


# ---------------------------------------------------------------------------
# Helper: build common monkeypatches for head+read
# ---------------------------------------------------------------------------


def _patch_head(size: int):
    return patch("another_s3_manager.s3_client.head_object_for_role", return_value=size)


def _patch_read(data: bytes):
    return patch("another_s3_manager.s3_client.read_object_for_role", return_value=data)


def _patch_read_range(data: bytes):
    return patch("another_s3_manager.s3_client.read_object_range_for_role", return_value=data)


# ---------------------------------------------------------------------------
# Test 1: Extension whitelist — json file returns text via "extension" decision
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extension_whitelist_json(alice_user, tool_registry):
    """data.json with valid UTF-8 content → detection='extension', content matches."""
    _, plaintext = alice_user
    content = b'{"key": "value", "num": 42}'

    with _patch_head(len(content)), _patch_read(content):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="my-bucket",
            path="data.json",
        )

    assert result["detection"] == "extension"
    assert result["content"] == content.decode("utf-8")
    assert result["size"] == len(content)
    assert result["bucket"] == "my-bucket"
    assert result["path"] == "data.json"
    assert result["encoding"] == "utf-8"


# ---------------------------------------------------------------------------
# Test 2: AppFlow regression — timestamped JSON key always goes through whitelist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_appflow_timestamped_json_key(alice_user, tool_registry):
    """1234-2026-04-29.json with size 100 → returns text content, detection='extension'.

    AppFlow/Glue/Lambda often set Content-Type: application/octet-stream on JSON
    exports. Our pipeline ignores Content-Type — extension whitelist always wins.
    """
    _, plaintext = alice_user
    content = b'{"records": []}'

    with _patch_head(len(content)), _patch_read(content):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="appflow-bucket",
            path="prefix/1234-2026-04-29.json",
        )

    assert result["detection"] == "extension"
    assert result["content"] == content.decode("utf-8")


# ---------------------------------------------------------------------------
# Test 3: Known binary extension raises BINARY_CONTENT without downloading
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_binary_extension_raises_without_download(alice_user, tool_registry):
    """image.png with PNG header bytes → BINARY_CONTENT error; read_object not called."""
    _, plaintext = alice_user
    png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 92

    mock_read = MagicMock()
    with _patch_head(len(png_header)), patch("another_s3_manager.s3_client.read_object_for_role", mock_read):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "read_file",
                _fake_request(plaintext),
                role="Default",
                bucket="imgs",
                path="photo/image.png",
            )

    assert exc_info.value.code == "BINARY_CONTENT"
    assert exc_info.value.details.get("ext") == "png"
    # Download must NOT have been called — no wasted bandwidth.
    mock_read.assert_not_called()


# ---------------------------------------------------------------------------
# Test 4: force_text=True on binary content — succeeds with replacement chars
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_force_text_on_binary(alice_user, tool_registry):
    """image.png with binary bytes + force_text=True → succeeds, detection='forced'."""
    _, plaintext = alice_user
    # Bytes with invalid UTF-8 sequences to ensure replacement chars appear.
    binary_data = b"\x89PNG\r\n\x1a\n\xff\xfe\xfd"

    with _patch_head(len(binary_data)), _patch_read(binary_data):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="imgs",
            path="image.png",
            force_text=True,
        )

    assert result["detection"] == "forced"
    # Replacement character U+FFFD should appear for invalid sequences.
    assert "�" in result["content"]
    assert result["size"] == len(binary_data)


# ---------------------------------------------------------------------------
# Test 5: FILE_TOO_LARGE — returns error before download
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_too_large_no_download(alice_user, tool_registry):
    """Token has max_read_bytes=1024, file is 2KB → FILE_TOO_LARGE, no download called."""
    uid, _ = alice_user
    # Create a token with a small cap.
    _, small_plaintext = svc.create_token(uid, "small-cap", is_read_only=False, max_read_bytes=1024)

    mock_read = MagicMock()
    with _patch_head(2048), patch("another_s3_manager.s3_client.read_object_for_role", mock_read):
        with pytest.raises(McpError) as exc_info:
            await _call(
                tool_registry,
                "read_file",
                _fake_request(small_plaintext),
                role="Default",
                bucket="big-bucket",
                path="large-file.txt",
            )

    assert exc_info.value.code == "FILE_TOO_LARGE"
    assert exc_info.value.details["size"] == 2048
    assert exc_info.value.details["max_read_bytes"] == 1024
    mock_read.assert_not_called()


# ---------------------------------------------------------------------------
# Test 6: Extensionless file with valid UTF-8 → sniffed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extensionless_file_sniffed(alice_user, tool_registry):
    """File 'noext' (no extension) with b'hello world\\n' → detection='sniffed'."""
    _, plaintext = alice_user
    content = b"hello world\n"

    with _patch_head(len(content)), _patch_read_range(content), _patch_read(content):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="bucket",
            path="some/path/noext",
        )

    assert result["detection"] == "sniffed"
    assert result["content"] == "hello world\n"


# ---------------------------------------------------------------------------
# Test 7: Empty file (size=0) → content="", size=0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_file(alice_user, tool_registry):
    """Empty file returns content='' and size=0 without errors."""
    _, plaintext = alice_user

    with _patch_head(0), _patch_read_range(b""), _patch_read(b""):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="bucket",
            path="empty.txt",
        )

    assert result["content"] == ""
    assert result["size"] == 0
    assert result["detection"] == "extension"


# ---------------------------------------------------------------------------
# Test 8: UTF-8 BOM stripped silently
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_utf8_bom_stripped(alice_user, tool_registry):
    """bom.txt with BOM prefix → BOM is stripped from content."""
    _, plaintext = alice_user
    bom_content = b"\xef\xbb\xbfhello world"

    with _patch_head(len(bom_content)), _patch_read(bom_content):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="bucket",
            path="docs/bom.txt",
        )

    assert result["content"] == "hello world"
    assert not result["content"].startswith("﻿"), "BOM must be stripped"


# ---------------------------------------------------------------------------
# Test 9: EXTENSIONLESS_TEXT_BASENAMES — README → detection='extensionless'
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extensionless_text_basenames_readme(alice_user, tool_registry):
    """File named 'README' (no extension) → detection='extensionless', not sniffed."""
    _, plaintext = alice_user
    content = b"# My Project\n\nDescription here.\n"

    mock_range = MagicMock()
    with (
        _patch_head(len(content)),
        patch("another_s3_manager.s3_client.read_object_range_for_role", mock_range),
        _patch_read(content),
    ):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="bucket",
            path="repo/README",
        )

    assert result["detection"] == "extensionless"
    # Sniff must NOT be called — basename match short-circuits.
    mock_range.assert_not_called()


# ---------------------------------------------------------------------------
# Test 10: Custom mcp_text_extensions from config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_custom_mcp_text_extensions(alice_user, tool_registry, monkeypatch):
    """Config has mcp_text_extensions=['mdx'] → doc.mdx detected as extension."""
    _, plaintext = alice_user
    content = b"# MDX Doc\n\nSome content.\n"

    import another_s3_manager.config as config_mod

    original_load = config_mod.load_config

    def _config_with_mdx(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        return {**cfg, "mcp_text_extensions": ["mdx"]}

    monkeypatch.setattr("another_s3_manager.mcp_server._config_module.load_config", _config_with_mdx)

    with _patch_head(len(content)), _patch_read(content):
        result = await _call(
            tool_registry,
            "read_file",
            _fake_request(plaintext),
            role="Default",
            bucket="bucket",
            path="docs/doc.mdx",
        )

    assert result["detection"] == "extension"
    assert result["content"] == content.decode("utf-8")
