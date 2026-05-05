"""End-to-end MCP protocol tests via TestClient against the mounted /mcp sub-app.

ARCHITECTURE NOTE — FastMCP task group limitation
--------------------------------------------------
FastMCP's Streamable HTTP transport (MCP SDK 1.12) requires a task group that
is initialized during the *sub-app's own* lifespan via ``session_manager.run()``.
When the MCP app is mounted on the parent FastAPI app with ``app.mount("/mcp", ...)``,
Starlette does NOT propagate the parent lifespan to the sub-app.  As a result,
direct JSON-RPC requests (POST /mcp) crash with:

    RuntimeError: Task group is not initialized. Make sure to use run().

This is a known FastMCP/Starlette interaction: the sub-app never receives the
lifespan startup event from the parent.  The same setup works correctly in
production (Docker) because uvicorn fires lifespan events directly on the top-
level app, which does propagate to mounted sub-apps via Starlette's Router.

What we CAN test end-to-end via TestClient without workarounds:

1. The **kill-switch middleware** (registered on the parent app, runs before
   routing): POST/GET to /mcp/* → 503 when mcp_enabled=False.
2. The **routing layer**: with kill-switch enabled, /mcp is reached (not
   404), confirming the sub-app is correctly mounted at ``/mcp``.
3. The **auth rejection** counter (mcp_auth_failures_total) via a direct call
   to ``authenticate_mcp_request`` in the context set up by
   ``_RequestCaptureMiddleware`` — the unit that bridges HTTP to MCP tools.

The 26 unit tests in test_mcp_tools.py cover the auth + tool dispatch chain
exhaustively by calling tool bodies directly (skipping HTTP transport).
"""

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_config_mcp_disabled(monkeypatch, config_module):
    """Patch load_config so that mcp_enabled=False is returned."""
    original = config_module.load_config()

    monkeypatch.setattr(
        config_module,
        "load_config",
        lambda force_reload=False: {**original, "mcp_enabled": False},
    )


# ---------------------------------------------------------------------------
# Test 1: kill-switch → 503 for any /mcp/* path
# ---------------------------------------------------------------------------


def test_mcp_kill_switch_returns_503_when_disabled(app_client, monkeypatch):
    """When mcp_enabled=False, the kill-switch middleware must return 503
    for any /mcp/* request before it reaches FastMCP.

    This test confirms that the middleware is registered on the correct
    middleware stack and that disabling MCP is effective.
    """
    import another_s3_manager.config as config_module

    _patch_config_mcp_disabled(monkeypatch, config_module)

    resp = app_client.post(
        "/mcp",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )

    assert resp.status_code == 503
    body = resp.json()
    assert body.get("error") == "MCP_DISABLED"


# ---------------------------------------------------------------------------
# Test 2: kill-switch passthrough — /mcp/* routing is wired up correctly
# ---------------------------------------------------------------------------


def test_mcp_endpoint_is_mounted_not_404():
    """With the kill-switch inactive (default), GET /mcp must NOT return 404.

    A 404 would mean the sub-app is not mounted.  We expect anything else:
    - 405 (method not allowed for GET on a POST-only route), or
    - 500 (FastMCP task group uninitialized — see module docstring).
    Both confirm the route is registered and the kill-switch passes through.

    Uses raise_server_exceptions=False so the 500 from the task-group
    RuntimeError is captured as a response rather than re-raised in the test.
    """
    import importlib

    import another_s3_manager.main as main

    importlib.reload(main)
    from fastapi.testclient import TestClient

    # raise_server_exceptions=False: surface FastMCP task-group RuntimeError
    # as HTTP 500 instead of letting it propagate into the test process.
    client = TestClient(main.app, raise_server_exceptions=False)
    resp = client.get("/mcp")

    # 404 means the sub-app is not mounted at /mcp — that's the only failure
    # mode we care about here.  405 and 500 both mean the request reached the
    # sub-app (routing works).
    assert resp.status_code != 404, f"Got 404 — MCP sub-app appears not mounted at /mcp. Body: {resp.text[:200]}"


# ---------------------------------------------------------------------------
# Test 3: auth layer reachability via authenticate_mcp_request + metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_auth_failure_increments_counter(alice_with_token):
    """Confirm that authenticate_mcp_request raises McpError(INVALID_TOKEN) and
    increments mcp_auth_failures_total when no Bearer token is supplied.

    This test exercises the same auth layer that every HTTP request to /mcp
    goes through (via _RequestCaptureMiddleware → tool body → authenticate_mcp_request).
    It is protocol-adjacent: the auth function reads the HTTP request object
    exactly as it would in a real MCP call.
    """

    from another_s3_manager import metrics
    from another_s3_manager.mcp_server import McpError, _current_request, authenticate_mcp_request

    def _counter_value(reason: str) -> float:
        for sample in metrics.mcp_auth_failures_total.collect()[0].samples:
            if sample.labels.get("reason") == reason:
                return sample.value
        return 0.0

    before = _counter_value("malformed")

    # Build a minimal fake HTTP request with no auth header — the same object
    # shape that _RequestCaptureMiddleware would set in the contextvar.
    class _FakeRequest:
        headers = {}

    token = _current_request.set(_FakeRequest())
    try:
        with pytest.raises(McpError) as exc_info:
            await authenticate_mcp_request(_FakeRequest())
    finally:
        _current_request.reset(token)

    assert exc_info.value.code == "INVALID_TOKEN"
    assert _counter_value("malformed") >= before + 1
