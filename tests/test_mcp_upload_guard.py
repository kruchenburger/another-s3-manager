"""Tests for the MCP request body-guard middleware and its size ceiling.

Companion to test_upload_guard.py (the web /api/buckets/.../upload route):
this covers the equivalent transport-level protection for the MCP
upload_file tool, added because the JSON-RPC body (base64 content plus the
JSON-RPC envelope) is fully read and parsed into a Python str/dict by
FastMCP BEFORE any tool body (including upload_file's own FILE_TOO_LARGE
check in mcp_server.py) ever runs. Only a body bound checked before
call_next can prevent that RAM from being spent.

Most tests exercise `_mcp_body_guard` directly with a crafted ASGI
scope/headers and a stub call_next — the same pattern
test_upload_guard.py's test_negative_content_length_rejected_with_411 uses —
because driving a real /mcp POST through TestClient without disabling the
MCP kill-switch hits FastMCP's task-group limitation documented in
test_mcp_protocol.py's module docstring (the mounted sub-app never gets its
own lifespan under TestClient). Two tests additionally go through the real
app via `app_client` to prove the guard is actually wired into the live
middleware stack, mirroring test_upload_guard.py's app_client-based tests.
"""

import asyncio
import base64
import importlib
import json

from starlette.requests import Request


def reload_main():
    import another_s3_manager.main as main

    importlib.reload(main)
    return main


def _mount_client():
    """TestClient over the real mounted app, tolerant of the documented
    FastMCP task-group limitation (see test_mcp_protocol.py's module
    docstring) — used only to prove the guard does not interfere with a
    request that would otherwise reach the mount."""
    from fastapi.testclient import TestClient

    main = reload_main()
    return TestClient(main.app, raise_server_exceptions=False)


# --- resolve_mcp_body_max_bytes ---


def test_resolve_mcp_body_max_bytes_derives_from_base64_plus_envelope(mocker):
    """12 raw bytes base64-encode to EXACTLY 16 characters (12/3*4, no
    fractional padding) — the ceiling must be that plus the fixed envelope
    headroom, not the raw byte count itself."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.resolve_max_file_size", return_value=12)

    assert main.resolve_mcp_body_max_bytes() == 16 + main.MCP_JSON_ENVELOPE_OVERHEAD_BYTES


def test_resolve_mcp_body_max_bytes_exceeds_max_file_size_itself():
    """Regression guard for the exact bug this module fixes: the ceiling must
    be strictly larger than max_file_size. Base64 alone already inflates a
    payload to ~4/3x its raw size, so a ceiling equal to max_file_size would
    reject uploads that are entirely within the operator's own configured
    limit — see the DO-NOT-simplify comment on resolve_mcp_body_max_bytes."""
    import another_s3_manager.config as config_module

    main = reload_main()
    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 100 * 1024 * 1024
    config_module.save_config(cfg)

    assert main.resolve_mcp_body_max_bytes() > main.resolve_max_file_size()


# --- _mcp_body_guard: rejections (call_next must never run) ---


def test_mcp_body_guard_rejects_declared_length_over_ceiling(mocker):
    """Content-Length above the ceiling -> 413 BEFORE call_next runs, and the
    same upload_rejected_total{reason=size_limit} counter the web guard uses
    is incremented — proof the body is refused before any bytes are read."""
    from another_s3_manager.metrics import upload_rejected_total

    main = reload_main()
    ceiling = main.resolve_mcp_body_max_bytes()
    before = upload_rejected_total.labels(reason="size_limit")._value.get()

    async def _call_next(_request):
        raise AssertionError("call_next must not run for an over-ceiling /mcp body")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-length", str(ceiling + 1).encode())],
    }
    request = Request(scope)

    response = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert response.status_code == 413
    assert upload_rejected_total.labels(reason="size_limit")._value.get() == before + 1


def test_mcp_body_guard_missing_content_length_gets_411():
    """No Content-Length header (the chunked-transfer shape) -> 411 before
    call_next runs — closes the same bypass _upload_body_guard closes for
    the web route."""
    main = reload_main()

    async def _call_next(_request):
        raise AssertionError("call_next must not run without a Content-Length header")

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
    request = Request(scope)

    response = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert response.status_code == 411


def test_mcp_body_guard_negative_content_length_gets_411():
    """A negative declared Content-Length must not fall through to call_next —
    same reasoning as _upload_body_guard's equivalent test."""
    main = reload_main()

    async def _call_next(_request):
        raise AssertionError("call_next must not run for a negative Content-Length")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-length", b"-5")],
    }
    request = Request(scope)

    response = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert response.status_code == 411


def test_mcp_body_guard_malformed_content_length_gets_411():
    """A non-integer Content-Length is treated as missing, not as 0/ignored."""
    main = reload_main()

    async def _call_next(_request):
        raise AssertionError("call_next must not run for a malformed Content-Length")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-length", b"not-a-number")],
    }
    request = Request(scope)

    response = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert response.status_code == 411


# --- _mcp_body_guard: admits legitimate traffic ---


def test_mcp_body_guard_admits_realistic_upload_at_exact_max_file_size(mocker):
    """Build the REAL JSON-RPC body an agent would send for an upload_file
    call whose payload is exactly max_file_size bytes (base64 content plus
    the tools/call envelope), and prove the guard lets it through — the
    strongest possible proof that the base64 (4/3x) + envelope overhead
    baked into resolve_mcp_body_max_bytes does not reject an upload that is
    entirely within the operator's own configured limit.

    max_file_size is set small (100 KB) here purely so building and hashing
    the actual base64 string in a test stays cheap — the arithmetic is the
    same regardless of scale.
    """
    import another_s3_manager.config as config_module

    main = reload_main()
    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 100_000
    config_module.save_config(cfg)

    payload = b"x" * cfg["max_file_size"]
    encoded = base64.b64encode(payload).decode()
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "upload_file",
                "arguments": {
                    "role": "Default",
                    "bucket": "my-bucket",
                    "path": "some/reasonably/long/nested/path/for/the/file.bin",
                    "content_base64": encoded,
                },
            },
        }
    ).encode()

    ceiling = main.resolve_mcp_body_max_bytes()
    assert len(body) <= ceiling, (
        "a legitimate upload_file body at exactly max_file_size must fit under the guard's ceiling"
    )

    calls = {"n": 0}

    async def _call_next(_request):
        calls["n"] += 1
        return "ok-sentinel"

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"content-length", str(len(body)).encode())],
    }
    request = Request(scope)

    result = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert result == "ok-sentinel"
    assert calls["n"] == 1


def test_mcp_body_guard_ignores_get_requests():
    """LOAD-BEARING: the guard's `request.method == "POST"` scoping must
    never widen to cover GET.

    This is not merely "GET carries no JSON-RPC payload worth bounding" —
    the MCP streamable-HTTP transport's SSE event stream (and its resumption
    stream) IS a GET to /mcp. Session teardown is a DELETE. The SDK's only
    POST always sets Content-Length (verified independently during review).
    If a future change applies this guard's 411/413 rejections to GET, every
    MCP session for every agent breaks the moment its SSE stream opens —
    there is no smaller blast radius to discover this by, because the
    failure only shows up once a real client tries to hold a session open.
    Do not remove or generalize this exemption without re-verifying that
    invariant against the current MCP SDK transport.
    """
    main = reload_main()

    async def _call_next(_request):
        return "passthrough"

    scope = {"type": "http", "method": "GET", "path": "/mcp", "headers": []}
    request = Request(scope)

    result = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert result == "passthrough"


def test_mcp_body_guard_ignores_unrelated_paths():
    """A POST to an unrelated path must not be bound by the /mcp ceiling."""
    main = reload_main()

    async def _call_next(_request):
        return "passthrough"

    scope = {"type": "http", "method": "POST", "path": "/api/me", "headers": []}
    request = Request(scope)

    result = asyncio.run(main._mcp_body_guard(request, _call_next))

    assert result == "passthrough"


# --- End-to-end through the real middleware stack ---


def test_mcp_post_with_oversized_body_gets_413_via_http(app_client):
    """Same assertion as the unit tests above, but driven through the real
    app (kill-switch + canonical-path + http-metrics + this guard) via
    app_client, mirroring test_upload_guard.py's
    test_upload_content_length_over_limit_gets_413_and_metric for the web
    route."""
    import another_s3_manager.config as config_module
    from another_s3_manager.metrics import upload_rejected_total

    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 10
    config_module.save_config(cfg)
    before = upload_rejected_total.labels(reason="size_limit")._value.get()

    response = app_client.post(
        "/mcp",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        content=b"x" * 100_000,
    )

    assert response.status_code == 413
    assert upload_rejected_total.labels(reason="size_limit")._value.get() == before + 1


def test_mcp_post_without_content_length_gets_411_via_http(app_client):
    """httpx sends Transfer-Encoding: chunked (no Content-Length) for an
    iterator body — the exact shape the guard must refuse, mirroring
    test_upload_guard.py's test_upload_without_content_length_gets_411."""
    response = app_client.post(
        "/mcp",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        content=iter([b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}']),
    )

    assert response.status_code == 411


def test_mcp_guard_rejections_across_junk_suffixes_collapse_to_one_series(app_client):
    """Cardinality-bounding regression proof, mirroring
    test_upload_guard.py's test_guard_rejections_across_bucket_names_collapse_to_one_series
    for the /mcp guard. _mcp_body_guard rejects BEFORE routing ever runs, so
    without a guard-stamped request.scope["guard_path_template"],
    _http_metrics' route-less fallback would key on the concrete request
    path — an unauthenticated caller varying the /mcp/<suffix> would mint one
    unbounded label series per suffix in as3m_http_requests_total (and ~15
    per series in the duration histogram), held forever in the registry.
    Two guard-rejected (411) requests to DIFFERENT /mcp/<junk> paths must
    collapse into the SAME single template-labeled series ("/mcp", not the
    concrete path)."""
    from another_s3_manager.metrics import REGISTRY

    labels = {"method": "POST", "path_template": "/mcp", "status_code": "411"}
    before = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0

    for suffix in ("aaa", "bbb"):
        response = app_client.post(
            f"/mcp/{suffix}",
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            content=iter([b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}']),
        )
        assert response.status_code == 411

    after = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0
    assert after - before == 2


def test_mcp_body_guard_does_not_reject_small_tool_calls():
    """A normal, small MCP call (list_roles-shaped JSON-RPC body) must sail
    past the body guard untouched — it must not receive 411/413.

    The expected status here IS 500, not merely "anything but 411/413":
    under a bare TestClient the mounted FastMCP sub-app never gets its own
    lifespan, so its task group is uninitialized and any request that
    actually reaches it surfaces as 500 (documented in
    test_mcp_protocol.py's module docstring and its own `_mount_client`
    helper, mirrored here). Asserting the concrete value means this test
    would notice a regression it would otherwise miss — e.g. the kill-switch
    firing unexpectedly (503) or some other guard rejecting the call — both
    of which also satisfy "not in (411, 413)" but are not "the guard let a
    small call through untouched".
    """
    client = _mount_client()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_roles", "arguments": {}}}

    response = client.post("/mcp", headers=headers, json=body)

    assert response.status_code == 500
