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


def _build_protocol_test_app():
    """Build a fresh, never-run Streamable HTTP ASGI app wrapping the SAME
    real _mcp_server (real tool registrations, real `instructions`) that the
    production mcp_asgi_app wraps — see the module comment above for why
    this can't just reuse mcp.session_manager directly.

    Each call constructs its own StreamableHTTPSessionManager instance, so
    multiple tests can each get one independent, never-run manager bound to
    the same underlying tool registry (the "run() only once per instance"
    constraint is per-manager, not per-_mcp_server).
    """
    import contextlib

    from mcp.server.fastmcp.server import StreamableHTTPASGIApp
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    from another_s3_manager.mcp_server import _RequestCaptureMiddleware, mcp

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
    return _RequestCaptureMiddleware(test_asgi_app)


def test_mcp_protocol_round_trip_initialize_and_tools_list():
    """Real initialize + tools/list over Streamable HTTP: the initialize
    result must carry `instructions`, and bucket_summary must be
    discoverable via tools/list — proving FastMCP actually serializes it."""
    from starlette.testclient import TestClient

    mcp_asgi_app = _build_protocol_test_app()

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


# ---------------------------------------------------------------------------
# Test 6: a REAL tools/call error round-trip (Fix round 1, Finding 4)
#
# Every test in this module and in test_mcp_tools.py that touches McpError
# asserts on `str(exc)` directly — none of them drives FastMCP's actual
# Tool.run -> isError: true text-content path. That leaves the load-bearing
# claim in McpError.__str__'s docstring (FastMCP only ever forwards
# str(exception) to the client, which is why actionable `details` —
# allowed_roles, hint — are folded into the message there) asserted only in
# a code comment, never proven end to end. If a future `mcp` SDK bump changed
# exception marshalling (e.g. started serializing `details` structurally, or
# wrapped exceptions with repr() instead of str()), every existing test would
# stay green while a real agent silently stopped seeing allowed_roles and the
# hints again — the exact bug this commit fixes, resurrected invisibly.
#
# Reuses _build_protocol_test_app() (Test 5's harness) instead of inventing
# a new one: same throwaway StreamableHTTPSessionManager bound to the real
# mcp._mcp_server, driven through TestClient as its own ASGI root so the
# session-manager task group actually starts.
# ---------------------------------------------------------------------------


def test_mcp_protocol_tools_call_surfaces_role_not_allowed_in_text_content(alice_with_token):
    """Real initialize -> notifications/initialized -> tools/call over
    Streamable HTTP, calling list_buckets with a role the token's user is
    NOT allowed to use (alice_with_token only has "Default"). Asserts on the
    actual isError text CONTENT the client receives — not on str(exc) — so
    this proves ROLE_NOT_ALLOWED and the "Roles you may use:" text the agent
    needs to self-correct actually survive FastMCP's real error-marshalling
    path end to end."""
    from starlette.testclient import TestClient

    _, plaintext_token = alice_with_token

    mcp_asgi_app = _build_protocol_test_app()

    # FastMCP's Streamable HTTP session runs its message-processing loop in a
    # single task spawned while handling the FIRST (`initialize`) POST — see
    # StreamableHTTPSessionManager._handle_stateful_request: the task group
    # is started (capturing a snapshot of the request-scoped contextvars,
    # including _current_request) BEFORE that request returns, and every
    # later message for this session (notifications/initialized, tools/call)
    # is processed inside that SAME long-lived task, not the task that
    # handles each individual POST. So _get_current_request() inside a tool
    # body resolves to whatever request was current when the session task
    # was spawned — the `initialize` call — not the request each subsequent
    # POST is made with. A real client sends the same Authorization header
    # on every request for a session; this test mirrors that by sending it
    # from the start rather than only on the tools/call POST.
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {plaintext_token}",
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

        # Required handshake step before the session accepts further calls.
        notif_resp = client.post(
            "/",
            headers={**headers, "mcp-session-id": session_id},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notif_resp.status_code == 202

        call_resp = client.post(
            "/",
            headers={**headers, "mcp-session-id": session_id},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "list_buckets", "arguments": {"role": "NotAllowedRole"}},
            },
        )
        assert call_resp.status_code == 200
        result = _parse_sse_json(call_resp.text)["result"]

        assert result["isError"] is True
        text = result["content"][0]["text"]
        assert "ROLE_NOT_ALLOWED" in text
        assert "Roles you may use:" in text


# ---------------------------------------------------------------------------
# Test 6: bare /mcp is canonical — no 307 (2026-07-13)
# ---------------------------------------------------------------------------


def _mount_client():
    """TestClient over the real mounted app.

    raise_server_exceptions=False for the same reason as Test 2: under
    TestClient the mounted sub-app never gets its lifespan, so FastMCP's task
    group is uninitialized and any request that actually reaches it surfaces as
    500. That is fine here — these tests are about ROUTING (which status the
    router picks), not about what the MCP app then does with the request.
    """
    import importlib

    from fastapi.testclient import TestClient

    import another_s3_manager.main as main

    importlib.reload(main)
    return TestClient(main.app, raise_server_exceptions=False)


def test_bare_mcp_path_does_not_redirect():
    """POST /mcp (no trailing slash) must reach the mount, not 307 to /mcp/.

    Starlette's Mount matches ^/mcp(?P<path>/.*)$, so a bare /mcp misses the
    mount and the router's redirect_slashes answers 307. An MCP client that
    does not follow redirects cannot connect at all — and a bare /mcp is both
    what every other MCP server uses and what MCP_SERVER_INSTRUCTIONS itself
    tells agents to use. _mcp_canonical_path rewrites the path before routing.

    Redirects are disabled so a non-following client is genuinely represented:
    /mcp and /mcp/ must land on the same handler and return the same status.
    """
    client = _mount_client()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    bare = client.post("/mcp", headers=headers, json=body, follow_redirects=False)
    slashed = client.post("/mcp/", headers=headers, json=body, follow_redirects=False)

    assert bare.status_code != 307, "bare /mcp still redirects — clients that don't follow it cannot connect"
    assert bare.status_code == slashed.status_code


def test_bare_mcp_rewrite_does_not_over_match():
    """The rewrite matches /mcp EXACTLY. A startswith("/mcp") version would
    swallow sibling paths like /mcpfoo into the MCP mount.

    Asserted against a control path rather than a hardcoded status: /mcpfoo
    must be routed exactly like any other unknown path (both fall through to
    the GET-only SPA catch-all, so a POST to either is a 405). What matters is
    that /mcpfoo is NOT treated as the MCP endpoint — it must not reach the
    mount, and it must not be redirected there.
    """
    client = _mount_client()

    sibling = client.post("/mcpfoo", follow_redirects=False)
    control = client.post("/notmcp", follow_redirects=False)

    assert sibling.status_code != 307, "/mcpfoo was redirected — the rewrite is over-matching"
    assert sibling.status_code == control.status_code


def test_bare_mcp_does_not_bypass_kill_switch(app_client, monkeypatch):
    """The rewrite runs in front of the router — prove it cannot be used to
    slip past the kill-switch. With mcp_enabled=False a bare /mcp must still
    503, exactly as /mcp/ does.

    (Bearer auth needs no equivalent test: it is enforced inside the tool
    bodies via authenticate_mcp_request reading the request from a contextvar,
    not by any path-matching middleware, so a path rewrite cannot reach it.)
    """
    import another_s3_manager.config as config_module

    _patch_config_mcp_disabled(monkeypatch, config_module)
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    bare = app_client.post("/mcp", headers=headers, json=body, follow_redirects=False)
    slashed = app_client.post("/mcp/", headers=headers, json=body, follow_redirects=False)

    assert bare.status_code == 503
    assert bare.json().get("error") == "MCP_DISABLED"
    assert slashed.status_code == 503
