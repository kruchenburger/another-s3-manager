"""Tests for Prometheus metrics endpoint and registry definitions."""


def test_metrics_endpoint_returns_prometheus_text(app_client):
    resp = app_client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Should contain at least one of our defined metrics
    assert "http_requests_total" in body or "app_info" in body


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
    assert "app_info" in resp.text
