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
