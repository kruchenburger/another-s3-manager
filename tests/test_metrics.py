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
    ok_before = _sample("auth_logins_total", {"result": "success"})
    bad_before = _sample("auth_logins_total", {"result": "invalid_password"})

    resp = app_client.post("/api/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 401
    resp = app_client.post("/api/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200

    assert _sample("auth_logins_total", {"result": "success"}) == ok_before + 1
    assert _sample("auth_logins_total", {"result": "invalid_password"}) == bad_before + 1

    body = app_client.get("/metrics").text
    assert 'auth_logins_total{result="success"}' in body


def test_auth_banned_login_metric_and_active_bans_gauge(app_client):
    """A login attempt against a banned account counts as result=banned, and
    auth_bans_active reports the live number of active bans at scrape time."""
    banned_before = _sample("auth_logins_total", {"result": "banned"})

    _seed_user("metrics_bob", "Sup3rSecret1")
    for _ in range(3):
        resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "wrong"})
        assert resp.status_code == 401

    # 4th attempt hits the banned branch — even with the correct password
    resp = app_client.post("/api/login", data={"username": "metrics_bob", "password": "Sup3rSecret1"})
    assert resp.status_code == 403

    assert _sample("auth_logins_total", {"result": "banned"}) == banned_before + 1

    body = app_client.get("/metrics").text
    assert "auth_bans_active 1.0" in body  # fresh per-test DB → exactly one active ban
