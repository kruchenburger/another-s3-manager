from urllib.parse import urlencode

import pytest

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
    # Tests run with COOKIE_SECURE=false: Access names are the plain-mode wire names.
    response = app_client.get("/api/auth/oidc/callback?" + urlencode(query), follow_redirects=False)
    assert response.status_code == 200
    assert app_client.get("/api/me").json()["username"] == "reader"


@pytest.mark.parametrize(
    "door,code,status",
    [
        ("login", "OIDC_DISABLED", 404),
        ("login", "OIDC_UNAVAILABLE", 503),
        ("login", "OTHER_FAILURE", 503),
        ("callback", "OIDC_DISABLED", 404),
        ("callback", "OIDC_UNAVAILABLE", 302),
        ("callback", "OTHER_FAILURE", 302),
    ],
)
def test_oidc_error_response_contract(app_client, monkeypatch, door, code, status):
    from unittest.mock import AsyncMock

    operations = (access.CookieOperation("oidc_tx_fixture"),)
    if door == "login":
        monkeypatch.setattr(access, "start_oidc_login", lambda *args: access.OidcStart("/login", operations, code))
    else:
        monkeypatch.setattr(
            access, "complete_oidc_login", AsyncMock(return_value=access.OidcCompletion("/login", operations, code))
        )
    response = app_client.get("/api/auth/oidc/" + door, follow_redirects=False)
    assert response.status_code == status
    if status == 302:
        assert response.headers["location"] == "/login"
        assert response.content == b""
    else:
        assert response.json() == {"detail": {"code": code}}
        assert "location" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert 'oidc_tx_fixture=""' in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert "Path=/api/auth/oidc/" in response.headers["set-cookie"]


@pytest.fixture
def secure_client(app_client, monkeypatch):
    from fastapi.testclient import TestClient

    import another_s3_manager.main as main
    from another_s3_manager import constants

    monkeypatch.setattr(constants, "COOKIE_SECURE", True)
    return TestClient(main.app, base_url="https://testserver")


def set_cookie_headers(response):
    return response.headers.get_list("set-cookie")


def header_for(response, name):
    return next(header for header in set_cookie_headers(response) if header.startswith(name + "="))


def browser_sso_login(client, op):
    from urllib.parse import parse_qs, urlsplit

    start = client.get("/api/auth/oidc/login?return_to=/files", follow_redirects=False)
    assert start.status_code == 302
    authorize = {key: values[0] for key, values in parse_qs(urlsplit(start.headers["location"]).query).items()}
    callback = urlsplit(op.authorize(authorize)).query
    return start, client.get("/api/auth/oidc/callback?" + callback, follow_redirects=False)


def test_secure_mode_uses_host_prefixed_cookies_end_to_end(secure_client, oidc):
    start, callback = browser_sso_login(secure_client, oidc)
    tx = next(h for h in set_cookie_headers(start) if h.startswith("__Host-oidc_tx_"))
    assert "Path=/;" in tx
    assert "Secure" in tx and "HttpOnly" in tx and "SameSite=lax" in tx
    assert "domain" not in tx.lower()
    assert not any(h.startswith("oidc_tx_") for h in set_cookie_headers(start))
    assert callback.status_code == 200
    session = header_for(callback, "__Host-access_token")
    assert "Path=/;" in session and "Secure" in session and "HttpOnly" in session and "SameSite=strict" in session
    assert "domain" not in session.lower()
    # The old plain session cookie is cleared, the transaction cookie deleted under its real name/path.
    assert "Max-Age=0" in header_for(callback, "access_token")
    deleted_tx = next(h for h in set_cookie_headers(callback) if h.startswith("__Host-oidc_tx_"))
    assert "Max-Age=0" in deleted_tx and "Path=/;" in deleted_tx and "Secure" in deleted_tx
    assert secure_client.get("/api/me").json()["username"] == "reader"


def test_plain_mode_keeps_historical_cookie_names_end_to_end(app_client, oidc):
    start, callback = browser_sso_login(app_client, oidc)
    tx = next(h for h in set_cookie_headers(start) if h.startswith("oidc_tx_"))
    assert "Path=/api/auth/oidc/" in tx and "Secure" not in tx
    assert callback.status_code == 200
    assert "Secure" not in header_for(callback, "access_token")
    assert not any(h.startswith("__Host-") for h in set_cookie_headers(start) + set_cookie_headers(callback))
    assert app_client.get("/api/me").json()["username"] == "reader"


def test_secure_mode_ignores_plain_session_and_transaction_cookies(secure_client, oidc):
    from another_s3_manager.access import users

    reader = users.create_user("legacy-reader", "hash", is_admin=False)
    from tests.test_web_user_lifecycle import authenticate

    authenticate(secure_client, reader)  # Sets the plain access_token name in the jar.
    assert secure_client.get("/api/me").status_code == 401
    token = secure_client.cookies.get("access_token")
    secure_client.cookies.clear()
    secure_client.cookies.set("__Host-access_token", token)
    assert secure_client.get("/api/me").status_code == 200
    # A transaction cookie under the old name is not a transaction in Secure mode.
    query, cookies = begin(oidc)
    secure_client.cookies.clear()
    for name, value in cookies.items():
        secure_client.cookies.set(name, value)
    response = secure_client.get("/api/auth/oidc/callback?" + urlencode(query), follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login?sso_error=expired"


def test_secure_local_login_and_logout_clear_the_old_name(secure_client):
    from another_s3_manager.access import users

    users.create_user("admin", access.hash_password("LocalPassword1"), is_admin=True)
    login = secure_client.post("/api/login", data={"username": "admin", "password": "LocalPassword1"})
    assert login.status_code == 200
    session = header_for(login, "__Host-access_token")
    assert "Secure" in session and "Path=/;" in session and "domain" not in session.lower()
    assert "Max-Age=0" in header_for(login, "access_token")
    assert secure_client.get("/api/me").status_code == 200
    logout = secure_client.post("/api/logout")
    assert "Max-Age=0" in header_for(logout, "__Host-access_token")
    assert "Max-Age=0" in header_for(logout, "access_token")
    assert secure_client.get("/api/me").status_code == 401


def test_secure_mode_keeps_three_transaction_cookies(secure_client, oidc):
    for _ in range(4):
        assert secure_client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 302
    names = [name for name in secure_client.cookies.keys() if name.startswith("__Host-oidc_tx_")]
    assert len(names) == 3


def test_secure_error_response_deletes_prefixed_transaction_cookie(secure_client, monkeypatch):
    operations = (access.CookieOperation("oidc_tx_fixture"),)
    monkeypatch.setattr(access, "start_oidc_login", lambda *args: access.OidcStart("/login", operations, "OIDC_X"))
    response = secure_client.get("/api/auth/oidc/login", follow_redirects=False)
    deleted = header_for(response, "__Host-oidc_tx_fixture")
    assert "Max-Age=0" in deleted and "Path=/;" in deleted and "Secure" in deleted


@pytest.mark.parametrize("secure", [True, False])
def test_startup_warns_only_for_insecure_cookies(monkeypatch, caplog, secure):
    from another_s3_manager import auth, constants

    monkeypatch.setattr(constants, "COOKIE_SECURE", secure)
    caplog.clear()
    auth.log_cookie_mode()
    assert ("COOKIE_SECURE=false" in caplog.text) is (not secure)
