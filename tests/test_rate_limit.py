"""Tests for slowapi rate limiting via SlowAPIASGIMiddleware.

Single per-IP rate limit (RATE_LIMIT_DEFAULT) applied to all endpoints. Per-endpoint
@limiter.limit decorators are NOT used — they crash with FastAPI handlers that return
dicts. Login brute-force defense relies on the existing username-based ban logic.

These tests opt out of the default RATE_LIMIT_ENABLED=false set in conftest.py
by re-importing the rate_limit module with the env flipped to true.
"""

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def rate_limited_client(monkeypatch):
    """TestClient with rate limiting actually enabled."""
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")

    import another_s3_manager.constants as constants
    import another_s3_manager.main as main
    import another_s3_manager.rate_limit as rate_limit_module

    importlib.reload(constants)
    importlib.reload(rate_limit_module)
    importlib.reload(main)

    main.app.state.limiter.reset()

    return TestClient(main.app)


def test_successful_login_does_not_crash_with_limiter_enabled(rate_limited_client, monkeypatch):
    """REGRESSION: with rate limiter enabled, a successful login (handler returning dict)
    must not crash with 'parameter response must be an instance of starlette.responses.Response'.
    See backlog task 8 (fixed 2026-04-29). Caused by @limiter.limit decorators + dict
    handlers — fix was to drop decorators and use middleware-only rate limiting.
    """
    # Seed a real user we can authenticate as
    monkeypatch.setenv("ADMIN_PASSWORD", "test-pw-12345")
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import save_users

    save_users(
        {
            "users": [
                {
                    "username": "admin",
                    "password_hash": hash_password("test-pw-12345"),
                    "is_admin": True,
                    "allowed_roles": [],
                    "theme": "auto",
                }
            ]
        }
    )

    response = rate_limited_client.post(
        "/api/login",
        data={"username": "admin", "password": "test-pw-12345"},
    )
    assert response.status_code == 200, (
        f"login crashed with rate limiter enabled: {response.status_code} {response.text[:200]}"
    )
    body = response.json()
    assert "access_token" in body
    assert body["user"]["username"] == "admin"


def test_default_limit_blocks_after_100_requests(rate_limited_client):
    """101st request to any endpoint within a minute returns 429 (default 100/min)."""
    # Use /api/app-info — public, no auth needed, no DB writes
    for i in range(100):
        response = rate_limited_client.get("/api/app-info")
        assert response.status_code != 429, f"request {i + 1} got 429 unexpectedly"

    response = rate_limited_client.get("/api/app-info")
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]


def test_429_response_has_retry_after_header(rate_limited_client):
    """429 responses include Retry-After header so the client can back off."""
    for _ in range(100):
        rate_limited_client.get("/api/app-info")

    response = rate_limited_client.get("/api/app-info")
    assert response.status_code == 429
    assert "retry-after" in {h.lower() for h in response.headers}


def test_429_response_has_x_ratelimit_headers(rate_limited_client):
    """429 responses include X-RateLimit-* headers for client-side countdown UX."""
    for _ in range(100):
        rate_limited_client.get("/api/app-info")

    response = rate_limited_client.get("/api/app-info")
    assert response.status_code == 429
    header_names = {h.lower() for h in response.headers}
    # slowapi attaches X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
    assert any(h.startswith("x-ratelimit") for h in header_names)


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

    # Client A exhausts quota
    for _ in range(100):
        response = client.get("/api/app-info", headers={"X-Forwarded-For": "203.0.113.1"})
        assert response.status_code != 429

    # Client A — 101st tripped
    response = client.get("/api/app-info", headers={"X-Forwarded-For": "203.0.113.1"})
    assert response.status_code == 429

    # Client B — different IP, fresh quota
    response = client.get("/api/app-info", headers={"X-Forwarded-For": "203.0.113.2"})
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

    # Same first IP, different proxy chains — should share the quota
    for _ in range(100):
        response = client.get(
            "/api/app-info",
            headers={"X-Forwarded-For": "203.0.113.99, 10.0.0.1"},
        )
        assert response.status_code != 429

    # 101st request from same client (different proxy chain) — limited
    response = client.get(
        "/api/app-info",
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

    # Well over the 100/min default limit
    for _ in range(150):
        response = client.get("/api/app-info")
        assert response.status_code != 429
