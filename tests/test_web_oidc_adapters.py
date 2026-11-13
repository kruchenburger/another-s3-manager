from urllib.parse import urlencode

from another_s3_manager import access
from tests.test_oidc_login_integration import begin


def test_callback_ignores_forwarded_host(app_client, oidc):
    response = app_client.get(
        "/api/auth/oidc/login",
        headers={"Host": "attacker.example", "X-Forwarded-Host": "attacker.example"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "asm.example" in response.headers["location"]
    assert "attacker.example" not in response.headers["location"]


def test_oidc_success_error_and_login_headers_and_escaped_return_to(app_client, oidc):
    from unittest.mock import AsyncMock, patch

    from another_s3_manager.access.oidc.transactions import OidcCompletion

    completion = OidcCompletion('/files?q="<&', session="fixture", lifetime_minutes=5)
    with patch.object(access, "complete_oidc_login", AsyncMock(return_value=completion)):
        response = app_client.get("/api/auth/oidc/callback", follow_redirects=False)
    assert response.status_code == 200
    assert "q=&quot;&lt;&amp;" in response.text
    assert response.headers["content-security-policy"] == "default-src 'none'"
    assert "SameSite=strict" in response.headers["set-cookie"]
    for result in (
        response,
        app_client.get("/login", follow_redirects=False),
        app_client.get("/api/auth/oidc/callback", follow_redirects=False),
        app_client.get("/api/auth/oidc/login", follow_redirects=False),
    ):
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["referrer-policy"] == "no-referrer"


def test_http_full_flow_interstitial_to_me(app_client, oidc):
    query, cookies = begin(oidc)
    app_client.cookies.clear()
    for key, value in cookies.items():
        app_client.cookies.set(key, value)
    # TestClient's HTTP origin needs a non-secure cookie in this adapter test.
    from unittest.mock import patch

    import another_s3_manager.main as main

    with patch.object(main, "COOKIE_SECURE", False):
        response = app_client.get("/api/auth/oidc/callback?" + urlencode(query), follow_redirects=False)
    assert response.status_code == 200
    assert app_client.get("/api/me").json()["username"] == "reader"
