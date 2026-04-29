"""Tests for slowapi rate limiting on critical endpoints.

These tests opt out of the default RATE_LIMIT_ENABLED=false set in conftest.py
by re-importing the rate_limit module with the env flipped to true. The shared
isolated_environment fixture handles app reload + DB setup.
"""

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def rate_limited_client(monkeypatch):
    """TestClient with rate limiting actually enabled (default in tests is disabled)."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")

    import another_s3_manager.constants as constants
    import another_s3_manager.main as main
    import another_s3_manager.rate_limit as rate_limit_module

    importlib.reload(constants)
    importlib.reload(rate_limit_module)
    importlib.reload(main)

    main.app.state.limiter.reset()

    return TestClient(main.app)


def test_login_rate_limit_blocks_after_5_requests(rate_limited_client):
    """6th request to /api/login within a minute returns 429."""
    # Wrong creds — we don't care about auth, just that the endpoint executes
    payload = {"username": "anyuser", "password": "wrong"}

    # First 5 should reach the endpoint (returning 401 for unknown user)
    for i in range(5):
        response = rate_limited_client.post("/api/login", data=payload)
        assert response.status_code != 429, f"request {i + 1} got 429 unexpectedly"

    # 6th must trip the limit
    response = rate_limited_client.post("/api/login", data=payload)
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]


def test_429_response_has_retry_after_header(rate_limited_client):
    """429 responses include Retry-After header so the client can back off."""
    payload = {"username": "anyuser", "password": "wrong"}
    for _ in range(5):
        rate_limited_client.post("/api/login", data=payload)

    response = rate_limited_client.post("/api/login", data=payload)
    assert response.status_code == 429
    # slowapi attaches Retry-After (seconds until window resets)
    assert "retry-after" in {h.lower() for h in response.headers}


def test_app_info_uses_default_read_limit(rate_limited_client):
    """Public read endpoints inherit the default 100/minute limit, not the login one."""
    # 6 requests must NOT trip the limit (default is 100/min, login is 5/min)
    for i in range(6):
        response = rate_limited_client.get("/api/app-info")
        assert response.status_code == 200, f"request {i + 1} unexpectedly limited"


def test_proxy_header_used_for_client_ip(monkeypatch):
    """When RATE_LIMIT_PROXY_HEADER is set, the limiter uses that header for the IP key."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PROXY_HEADER", "X-Forwarded-For")

    import another_s3_manager.constants as constants
    import another_s3_manager.main as main
    import another_s3_manager.rate_limit as rate_limit_module

    importlib.reload(constants)
    importlib.reload(rate_limit_module)
    importlib.reload(main)

    main.app.state.limiter.reset()
    client = TestClient(main.app)

    payload = {"username": "anyuser", "password": "wrong"}

    # Client A — first 5 requests reach the endpoint
    for _ in range(5):
        response = client.post("/api/login", data=payload, headers={"X-Forwarded-For": "203.0.113.1"})
        assert response.status_code != 429

    # Client A — 6th tripped
    response = client.post("/api/login", data=payload, headers={"X-Forwarded-For": "203.0.113.1"})
    assert response.status_code == 429

    # Client B — different IP, fresh quota
    response = client.post("/api/login", data=payload, headers={"X-Forwarded-For": "203.0.113.2"})
    assert response.status_code != 429


def test_x_forwarded_for_chain_uses_first_address(monkeypatch):
    """X-Forwarded-For: 'client, proxy1, proxy2' → first entry is the client."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PROXY_HEADER", "X-Forwarded-For")

    import another_s3_manager.constants as constants
    import another_s3_manager.main as main
    import another_s3_manager.rate_limit as rate_limit_module

    importlib.reload(constants)
    importlib.reload(rate_limit_module)
    importlib.reload(main)

    main.app.state.limiter.reset()
    client = TestClient(main.app)

    payload = {"username": "anyuser", "password": "wrong"}

    # Same first IP, different proxy chains — should share the quota
    for _ in range(5):
        response = client.post(
            "/api/login",
            data=payload,
            headers={"X-Forwarded-For": "203.0.113.99, 10.0.0.1"},
        )
        assert response.status_code != 429

    # 6th request from same client (different proxy IP, but client IP same) — limited
    response = client.post(
        "/api/login",
        data=payload,
        headers={"X-Forwarded-For": "203.0.113.99, 10.0.0.2"},
    )
    assert response.status_code == 429


def test_rate_limit_disabled_when_env_false(monkeypatch):
    """RATE_LIMIT_ENABLED=false → no 429 ever returned (test isolation)."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")

    import another_s3_manager.main as main
    import another_s3_manager.rate_limit as rate_limit_module

    importlib.reload(rate_limit_module)
    importlib.reload(main)

    client = TestClient(main.app)

    payload = {"username": "anyuser", "password": "wrong"}
    for _ in range(15):  # well over the 5/min login limit
        response = client.post("/api/login", data=payload)
        assert response.status_code != 429
