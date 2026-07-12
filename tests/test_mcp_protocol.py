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

import json

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


# ---------------------------------------------------------------------------
# Test 4: server-level instructions (2026-07-12 big-bucket ergonomics design)
# ---------------------------------------------------------------------------


def test_mcp_server_declares_instructions():
    """The FastMCP instance must carry server-level orientation for agents:
    the explore order (list_roles → list_buckets → bucket_summary), the
    list_files pagination contract, and — the sentence that closes the
    recorded incident's dead end — that the REST API is cookie-authenticated
    and NOT usable with the MCP Bearer token."""
    from another_s3_manager.mcp_server import mcp

    text = mcp.instructions or ""
    # Explore order
    assert "list_roles" in text
    assert "list_buckets" in text
    assert "bucket_summary" in text
    # list_files pagination contract
    assert "next_continuation_token" in text
    # The REST dead-end closer
    assert "session cookie" in text
    assert "Bearer" in text
    assert "/mcp" in text
    assert "/api/" in text


# ---------------------------------------------------------------------------
# Test 5: a REAL protocol round-trip (2026-07-13 final review, Finding 6)
#
# Every test above (and all 26+ in test_mcp_tools.py) reaches into
# mcp._tool_manager._tools and calls tool.fn directly — the suite would stay
# green even if FastMCP failed to serialize bucket_summary's signature, or if
# `instructions` never actually reached a connecting client.
# test_mcp_server_declares_instructions above only asserts the Python
# ATTRIBUTE, never that a client receives it over the wire.
#
# test_mcp_endpoint_is_mounted_not_404 above can't do this: FastAPI's
# app.mount() does not propagate the parent's lifespan to the MCP sub-app
# (see the module docstring), so FastMCP's session_manager task group is
# never started when the app is reached that way.
#
# TestClient does something different: it manages the lifespan of whatever
# ASGI app it wraps directly — so if we drive a Streamable HTTP ASGI app as
# TestClient's ROOT app, its `with` block correctly starts and stops
# FastMCP's session-manager task group, and a real
# initialize -> notifications/initialized -> tools/list exchange works
# without extra test infrastructure.
#
# One wrinkle: FastMCP's StreamableHTTPSessionManager can only .run() ONCE
# per instance, ever (a hard internal guard in the mcp SDK), and the
# production instance is memoized on the module-level `mcp` singleton the
# first time streamable_http_app() is called (at mcp_server.py import time,
# for mcp_asgi_app). test_main.py's startup-migration test already
# legitimately drives the real app lifespan once (`with TestClient(app) as
# _client:`) to observe alembic + JSON migration — which also runs, and
# permanently exhausts, that same shared session manager for the rest of the
# process. (Reloading mcp_server to dodge this was tried and reverted: other
# already-collected test modules bind `McpError` / `_current_request` from
# mcp_server at THEIR OWN import time, so a reload mid-suite hands the tool
# functions a different ContextVar/exception class than what those modules
# already imported — auth then fails everywhere downstream.)
#
# Instead, build a throwaway StreamableHTTPSessionManager bound to the REAL
# mcp._mcp_server (the actual registered tools + actual instructions — the
# same low-level server object streamable_http_app() would wrap) inside its
# own tiny Starlette app. This is genuinely the production tool registry
# over the real transport, isolated from the one-shot shared session
# manager other tests already consume — not a fake or a mock.
# ---------------------------------------------------------------------------


def _parse_sse_json(text: str) -> dict:
    """Extract the JSON-RPC payload from a Streamable HTTP SSE response body.

    FastMCP replies to POST / with one `event: message` / `data: {...}` SSE
    frame per JSON-RPC message rather than a bare JSON body.
    """
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    raise AssertionError(f"no SSE 'data:' line found in response body: {text!r}")


def test_mcp_protocol_round_trip_initialize_and_tools_list():
    """Real initialize + tools/list over Streamable HTTP: the initialize
    result must carry `instructions`, and bucket_summary must be
    discoverable via tools/list — proving FastMCP actually serializes it."""
    import contextlib

    from mcp.server.fastmcp.server import StreamableHTTPASGIApp
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from another_s3_manager.mcp_server import _RequestCaptureMiddleware, mcp

    # A fresh, never-run session manager wrapping the SAME real _mcp_server
    # (real tool registrations, real `instructions`) that the production
    # mcp_asgi_app wraps — see the module comment above for why this can't
    # just reuse mcp.session_manager directly.
    session_manager = StreamableHTTPSessionManager(
        app=mcp._mcp_server,
        json_response=mcp.settings.json_response,
        stateless=mcp.settings.stateless_http,
        security_settings=mcp.settings.transport_security,
    )

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        async with session_manager.run():
            yield

    test_asgi_app = Starlette(
        routes=[Route("/", endpoint=StreamableHTTPASGIApp(session_manager))],
        lifespan=_lifespan,
    )
    mcp_asgi_app = _RequestCaptureMiddleware(test_asgi_app)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    with TestClient(mcp_asgi_app) as client:
        init_resp = client.post(
            "/",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "0.0.1"},
                },
            },
        )
        assert init_resp.status_code == 200
        session_id = init_resp.headers["mcp-session-id"]
        instructions = _parse_sse_json(init_resp.text)["result"]["instructions"]
        assert "bucket_summary" in instructions
        assert "next_continuation_token" in instructions

        # Required handshake step before the session accepts further calls.
        notif_resp = client.post(
            "/",
            headers={**headers, "mcp-session-id": session_id},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notif_resp.status_code == 202

        list_resp = client.post(
            "/",
            headers={**headers, "mcp-session-id": session_id},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert list_resp.status_code == 200
        tool_names = {t["name"] for t in _parse_sse_json(list_resp.text)["result"]["tools"]}
        assert "bucket_summary" in tool_names
        assert "list_files" in tool_names
        assert "list_roles" in tool_names
