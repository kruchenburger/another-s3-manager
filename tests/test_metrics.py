"""Tests for Prometheus metrics endpoint and registry definitions."""

import os

import pytest


def test_metrics_endpoint_returns_prometheus_text(app_client):
    resp = app_client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Should contain at least one of our defined metrics
    assert "as3m_http_requests_total" in body


def test_metrics_endpoint_open_when_password_unset(app_client, monkeypatch):
    monkeypatch.delenv("METRICS_PASSWORD", raising=False)
    resp = app_client.get("/metrics")
    assert resp.status_code == 200


def test_metrics_endpoint_requires_basic_auth_when_password_set(app_client, monkeypatch):
    monkeypatch.setenv("METRICS_PASSWORD", "secret123")
    resp = app_client.get("/metrics")
    assert resp.status_code == 401
    resp_ok = app_client.get("/metrics", auth=("metrics", "secret123"))
    assert resp_ok.status_code == 200
    resp_bad = app_client.get("/metrics", auth=("metrics", "wrong"))
    assert resp_bad.status_code == 401


def test_http_request_counter_uses_path_template_not_concrete_url(app_client):
    """Bounded cardinality: hitting /api/me should label path_template='/api/me' (route pattern)."""
    app_client.get("/api/me")  # any known route
    resp = app_client.get("/metrics")
    body = resp.text
    # Look for a labeled path_template in the metric output
    assert 'path_template="/api/me"' in body or "/api/me" in body


def test_app_info_metric_present(app_client):
    resp = app_client.get("/metrics")
    assert "as3m_app_info" in resp.text


def _seed_user(username: str, password: str) -> None:
    from another_s3_manager.auth import hash_password
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as session:
        session.add(User(username=username, password_hash=hash_password(password), is_admin=False))


def _sample(name: str, labels: dict) -> float:
    from another_s3_manager.metrics import REGISTRY

    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_auth_login_metrics_count_success_and_failure(app_client):
    """auth_logins_total must increment on both login outcomes (was defined but unwired)."""
    ok_before = _sample("as3m_auth_logins_total", {"result": "success"})
    bad_before = _sample("as3m_auth_logins_total", {"result": "invalid_password"})

    resp = app_client.post("/api/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 401
    resp = app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200

    assert _sample("as3m_auth_logins_total", {"result": "success"}) == ok_before + 1
    assert _sample("as3m_auth_logins_total", {"result": "invalid_password"}) == bad_before + 1

    body = app_client.get("/metrics").text
    assert 'as3m_auth_logins_total{result="success"}' in body


def test_auth_banned_login_metric_and_active_bans_gauge(app_client):
    """A login attempt against a banned account counts as result=banned, and
    auth_bans_active reports the live number of active bans at scrape time."""
    banned_before = _sample("as3m_auth_logins_total", {"result": "banned"})

    _seed_user("metrics_bob", "Sup3rSecret1")
    for _ in range(3):
        resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "wrong"})
        assert resp.status_code == 401

    # 4th attempt hits the banned branch — even with the correct password
    resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "Sup3rSecret1"})
    assert resp.status_code == 403

    assert _sample("as3m_auth_logins_total", {"result": "banned"}) == banned_before + 1

    body = app_client.get("/metrics").text
    assert "as3m_auth_bans_active 1.0" in body  # fresh per-test DB → exactly one active ban


OLD_NAMES = [
    "http_requests_total",
    "http_request_duration_seconds",
    "auth_logins_total",
    "auth_bans_active",
    "s3_operations_total",
    "s3_operation_duration_seconds",
    "s3_bytes_uploaded_total",
    "s3_bytes_downloaded_total",
    "mcp_tool_calls_total",
    "mcp_tool_duration_seconds",
    "mcp_bytes_read_total",
    "mcp_tool_response_bytes",
    "mcp_auth_failures_total",
    "mcp_active_tokens",
    "app_info",
    "app_db_query_duration_seconds",
]


def test_every_app_metric_is_namespaced(app_client):
    """No metric we own may be exported under its old, unprefixed name."""
    body = app_client.get("/metrics").text
    for old in OLD_NAMES:
        # A bare old name at the start of a line is the exposition format's
        # own series/HELP/TYPE prefix. `as3m_<old>` must not trigger this.
        for line in body.splitlines():
            payload = line.removeprefix("# HELP ").removeprefix("# TYPE ")
            assert not payload.startswith(old + " "), f"{old} is still exported unprefixed"
            assert not payload.startswith(old + "{"), f"{old} is still exported unprefixed"


def test_namespaced_names_are_present(app_client):
    body = app_client.get("/metrics").text
    assert "as3m_http_requests_total" in body
    assert "as3m_app_info" in body
    assert "as3m_db_query_duration_seconds" in body


def test_platform_collector_registered(app_client):
    assert "python_info" in app_client.get("/metrics").text


@pytest.mark.skipif(not os.path.exists("/proc"), reason="ProcessCollector only exports on Linux")
def test_process_collector_registered(app_client):
    body = app_client.get("/metrics").text
    assert "process_cpu_seconds_total" in body
    assert "process_resident_memory_bytes" in body


def test_s3_operations_success_is_labelled_none(monkeypatch):
    from another_s3_manager import s3_client as sc

    monkeypatch.setattr(sc, "_execute_with_retry_inner", lambda _role, _cb: "ok")

    labels = {"role": "r1", "operation": "list", "error_code": "none"}
    before = _sample("as3m_s3_operations_total", labels)
    assert sc.execute_with_s3_retry("r1", "list", lambda _client: "ok") == "ok"
    assert _sample("as3m_s3_operations_total", labels) == before + 1


def test_s3_operations_failure_is_labelled_by_cause(monkeypatch):
    from another_s3_manager import s3_client as sc
    from another_s3_manager.errors import S3AccessDeniedError

    def _boom(_role, _callback):
        raise S3AccessDeniedError("AccessDenied", "nope")

    monkeypatch.setattr(sc, "_execute_with_retry_inner", _boom)

    labels = {"role": "r1", "operation": "get", "error_code": "access_denied"}
    before = _sample("as3m_s3_operations_total", labels)
    with pytest.raises(S3AccessDeniedError):
        sc.execute_with_s3_retry("r1", "get", lambda _c: None)
    assert _sample("as3m_s3_operations_total", labels) == before + 1


def test_bytes_counter_has_direction_label():
    from another_s3_manager.metrics import s3_bytes_total

    s3_bytes_total.labels(role="r1", bucket="b1", direction="upload").inc(10)
    s3_bytes_total.labels(role="r1", bucket="b1", direction="download").inc(4)
    assert _sample("as3m_s3_bytes_total", {"role": "r1", "bucket": "b1", "direction": "upload"}) >= 10
    assert _sample("as3m_s3_bytes_total", {"role": "r1", "bucket": "b1", "direction": "download"}) >= 4


def test_old_byte_counters_are_gone():
    from another_s3_manager import metrics

    assert not hasattr(metrics, "s3_bytes_uploaded_total")
    assert not hasattr(metrics, "s3_bytes_downloaded_total")


def test_folder_delete_counts_every_object_not_every_api_call(monkeypatch):
    """Deleting a prefix of N keys must add N, not the number of delete_objects batches."""
    import another_s3_manager.s3_client as sc

    labels = {"role": "r1", "bucket": "b1", "operation": "delete"}
    before = _sample("as3m_s3_objects_total", labels)

    # 2,500 keys => 3 batched delete_objects calls, but 2,500 objects.
    keys = [{"Key": f"folder/{i}"} for i in range(2500)]

    class _FakeClient:
        def get_paginator(self, _name):
            class _P:
                def paginate(self, **_kw):
                    return [{"Contents": keys}]

            return _P()

        def delete_objects(self, **_kw):
            return {}

    monkeypatch.setattr(sc, "_validate_bucket_access", lambda *a, **k: None)
    monkeypatch.setattr(sc, "validate_role_access", lambda role, _u: role)
    monkeypatch.setattr(sc, "execute_with_s3_retry", lambda _r, _op, cb: cb(_FakeClient()))

    result = sc.delete_object_for_role("r1", "b1", "folder/", {"username": "u"})

    assert result["count"] == 2500
    assert _sample("as3m_s3_objects_total", labels) == before + 2500


def test_upload_and_copy_count_one_object_each():
    from another_s3_manager.metrics import s3_objects_total

    for op in ("upload", "copy"):
        labels = {"role": "r1", "bucket": "b1", "operation": op}
        before = _sample("as3m_s3_objects_total", labels)
        s3_objects_total.labels(**labels).inc()
        assert _sample("as3m_s3_objects_total", labels) == before + 1


def test_expired_credentials_retry_is_counted(monkeypatch):
    """`_execute_with_retry_inner` calls `get_s3_client(role_name)` (s3_client.py:675).

    First call raises an expired-credential error, second succeeds — exactly one retry.
    """
    import another_s3_manager.s3_client as sc

    labels = {"reason": "credentials_expired"}
    before = _sample("as3m_s3_retries_total", labels)

    attempts = {"n": 0}

    def _get_client(_role_name):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("ExpiredToken")
        return object()

    monkeypatch.setattr(sc, "get_s3_client", _get_client)
    monkeypatch.setattr(sc, "_is_expired_credentials_error", lambda _e: True)

    assert sc._execute_with_retry_inner("r1", lambda _client: "ok") == "ok"
    assert attempts["n"] == 2
    assert _sample("as3m_s3_retries_total", labels) == before + 1


def test_sts_and_refresh_counters_exist_and_label_result():
    from another_s3_manager.metrics import credentials_refreshed_total, sts_assume_role_total

    for metric, name in (
        (sts_assume_role_total, "as3m_sts_assume_role_total"),
        (credentials_refreshed_total, "as3m_credentials_refreshed_total"),
    ):
        for result in ("ok", "error"):
            labels = {"role": "r1", "result": result}
            before = _sample(name, labels)
            metric.labels(**labels).inc()
            assert _sample(name, labels) == before + 1


def test_presigned_url_generation_is_counted(monkeypatch):
    import another_s3_manager.s3_client as sc

    labels = {"role": "r1", "bucket": "b1"}
    before = _sample("as3m_presigned_urls_total", labels)
    ttl_before = _sample("as3m_presigned_url_ttl_seconds_count", {})

    monkeypatch.setattr(sc, "_validate_bucket_access", lambda *a, **k: None)
    monkeypatch.setattr(sc, "validate_role_access", lambda role, _u: role)
    monkeypatch.setattr(sc, "execute_with_s3_retry", lambda _r, _op, cb: "https://signed")

    url = sc.generate_presigned_url_for_role("r1", "b1", "k.txt", {"username": "u"}, expires_in=900)

    assert url == "https://signed"
    assert _sample("as3m_presigned_urls_total", labels) == before + 1
    assert _sample("as3m_presigned_url_ttl_seconds_count", {}) == ttl_before + 1
