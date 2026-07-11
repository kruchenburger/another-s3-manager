"""Tests for the upload size-limit resolver and the upload body-guard middleware.

The body-guard closes the unauthenticated upload DoS: FastAPI parses (and
Starlette spools to disk) the multipart body to satisfy `File(...)` BEFORE
route dependencies like get_current_user run, so without the guard an
unauthenticated 10 GB POST fills the temp dir and only then gets a 401.
"""

import asyncio
import importlib

from starlette.requests import Request

from tests.test_main import login  # noqa: F401 - reused by the middleware tests added in Task 3


def reload_main():
    import another_s3_manager.main as main

    importlib.reload(main)
    return main


def _login_headers(client):
    """Authenticate the client's cookie jar as admin; return CSRF headers."""
    _, headers = login(client)
    return headers


# --- resolve_max_file_size ---


def test_resolve_max_file_size_config_wins_over_env(monkeypatch):
    """The admin-editable config value beats the MAX_FILE_SIZE env var."""
    import another_s3_manager.config as config_module

    main = reload_main()
    monkeypatch.setenv("MAX_FILE_SIZE", "555")
    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 12345
    config_module.save_config(cfg)

    assert main.resolve_max_file_size() == 12345


def test_resolve_max_file_size_env_fallback_when_config_key_missing(monkeypatch, mocker):
    """Config without the key (bypassing migration) falls back to MAX_FILE_SIZE."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.load_config", return_value={})
    monkeypatch.setenv("MAX_FILE_SIZE", "777")

    assert main.resolve_max_file_size() == 777


def test_resolve_max_file_size_default_100mb(monkeypatch, mocker):
    """No config key, no env var → 100 MB default."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.load_config", return_value={})
    monkeypatch.delenv("MAX_FILE_SIZE", raising=False)

    assert main.resolve_max_file_size() == 100 * 1024 * 1024


# --- _upload_body_guard middleware ---


def test_unauth_upload_rejected_before_body_parse(app_client, mocker):
    """G1: no session cookie → 401 from the guard, WITHOUT the multipart body
    ever being parsed (MultiPartParser.parse is the spool-to-disk site) and
    without any S3 helper being invoked."""
    parse_spy = mocker.patch("starlette.formparsers.MultiPartParser.parse")
    stream_spy = mocker.patch("another_s3_manager.s3_client.upload_fileobj_for_role")
    legacy_spy = mocker.patch("another_s3_manager.s3_client.put_object_for_role")

    response = app_client.post(
        "/api/buckets/guard-bucket/upload",
        data={"key": "big.bin"},
        files={"file": ("big.bin", b"x" * (256 * 1024), "application/octet-stream")},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    parse_spy.assert_not_called()
    stream_spy.assert_not_called()
    legacy_spy.assert_not_called()


def test_upload_without_content_length_gets_411(app_client):
    """Strict Content-Length requirement closes the chunked-transfer bypass.
    httpx sends `Transfer-Encoding: chunked` (and NO Content-Length) for
    iterator bodies — exactly the request shape the guard must refuse.
    411 must NOT increment upload_rejected_total (protocol error, not a
    business reject — spec decision 2026-07-11)."""
    from another_s3_manager.metrics import upload_rejected_total

    headers = _login_headers(app_client)
    rejected_before = upload_rejected_total.labels(reason="size_limit")._value.get()

    response = app_client.post(
        "/api/buckets/guard-bucket/upload",
        content=iter([b"x" * 1024]),
        headers=headers,
    )

    assert response.status_code == 411
    assert upload_rejected_total.labels(reason="size_limit")._value.get() == rejected_before


def test_negative_content_length_rejected_with_411(mocker):
    """A negative declared Content-Length must not fall through to call_next.
    int("-5") == -5 is neither None (no 411 via the missing-header branch)
    nor > max_file_size (no 413), so without an explicit `< 0` check the
    request would reach the handler and the body would be spooled before the
    handler's own true-size check runs. Upstream uvicorn/h11 usually reject a
    negative Content-Length at the framing layer, but the guard's own logic
    must not rely on that.

    httpx (TestClient) recomputes Content-Length from the body it actually
    sends, so a negative value can't be forged over the wire — this exercises
    _upload_body_guard directly with a crafted ASGI scope/headers and a stub
    call_next, with auth stubbed out so the test isolates the Content-Length
    branch on an otherwise-authenticated request."""
    main = reload_main()
    mocker.patch("another_s3_manager.main.get_current_user", return_value={"username": "admin"})

    async def _call_next(_request):
        raise AssertionError("call_next must not run for a negative Content-Length")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/buckets/guard-bucket/upload",
        "headers": [(b"content-length", b"-5")],
    }
    request = Request(scope)

    response = asyncio.run(main._upload_body_guard(request, _call_next))

    assert response.status_code == 411


def test_upload_content_length_over_limit_gets_413_and_metric(app_client):
    """Declared Content-Length above max_file_size → 413 before the body is
    parsed, and upload_rejected_total{reason=size_limit} increments."""
    import another_s3_manager.config as config_module
    from another_s3_manager.metrics import upload_rejected_total

    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 10
    config_module.save_config(cfg)
    headers = _login_headers(app_client)
    before = upload_rejected_total.labels(reason="size_limit")._value.get()

    response = app_client.post(
        "/api/buckets/guard-bucket/upload",
        data={"key": "big.bin"},
        files={"file": ("big.bin", b"x" * 1024, "application/octet-stream")},
        headers=headers,
    )

    assert response.status_code == 413
    assert upload_rejected_total.labels(reason="size_limit")._value.get() - before == 1


def test_valid_small_upload_passes_guard(app_client, moto_s3):
    """A well-formed authenticated upload sails through the guard to the
    handler and lands in (moto) S3 — the guard must not break the happy path."""
    headers = _login_headers(app_client)
    moto_s3.create_bucket(Bucket="guard-bucket")

    response = app_client.post(
        "/api/buckets/guard-bucket/upload",
        data={"key": "ok.txt"},
        files={"file": ("ok.txt", b"hello", "text/plain")},
        headers=headers,
    )

    assert response.status_code == 200
    assert moto_s3.get_object(Bucket="guard-bucket", Key="ok.txt")["Body"].read() == b"hello"


def test_guard_rejections_still_counted_in_http_metrics(app_client):
    """G4 ordering: _http_metrics must wrap the guard (guard registered BEFORE
    _http_metrics in module order → Starlette add_middleware prepends → metrics
    outermost of the two), so a guard-rejected request still lands in
    as3m_http_requests_total. Routing never ran for a guard-rejected request,
    so scope has no `route` — but the guard stamps a BOUNDED template
    (`/api/buckets/{bucket_name}/upload`) into request.scope, so
    _http_metrics' route-less fallback keys on that template instead of the
    concrete (attacker-controlled) bucket-name path."""
    from another_s3_manager.metrics import REGISTRY

    labels = {
        "method": "POST",
        "path_template": "/api/buckets/{bucket_name}/upload",
        "status_code": "401",
    }
    before = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0

    response = app_client.post(
        "/api/buckets/guard-metrics/upload",
        files={"file": ("f.bin", b"x", "application/octet-stream")},
    )
    assert response.status_code == 401

    after = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0
    assert after - before == 1


def test_guard_rejections_across_bucket_names_collapse_to_one_series(app_client):
    """Cardinality-bounding regression proof. Without the guard-stamped path
    template, _http_metrics' route-less fallback (routing never ran for a
    guard-rejected request) uses the CONCRETE request path — an unauthenticated
    attacker varying the bucket name (`/api/buckets/<rand>/upload`) would mint
    one unbounded label series per bucket name in as3m_http_requests_total
    (and ~15 per series in the duration histogram), held forever in the
    registry: the same unauth resource-exhaustion class this branch closes,
    relocated from disk to metrics-registry RAM. Two guard-rejected (401)
    unauth uploads to DIFFERENT bucket names must collapse into the SAME
    single template-labeled series."""
    from another_s3_manager.metrics import REGISTRY

    labels = {
        "method": "POST",
        "path_template": "/api/buckets/{bucket_name}/upload",
        "status_code": "401",
    }
    before = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0

    for bucket in ("aaa", "bbb"):
        response = app_client.post(
            f"/api/buckets/{bucket}/upload",
            files={"file": ("f.bin", b"x", "application/octet-stream")},
        )
        assert response.status_code == 401

    after = REGISTRY.get_sample_value("as3m_http_requests_total", labels) or 0.0
    assert after - before == 2
