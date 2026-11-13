from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from another_s3_manager import access, auth


def _request(*, cookie=None, bearer=""):
    return SimpleNamespace(cookies={"access_token": cookie} if cookie else {}, headers={"Authorization": bearer})


@pytest.mark.parametrize(
    "code,message", [("invalid_session", "Invalid authentication credentials"), ("user_not_found", "User not found")]
)
def test_cookie_maps_service_refusal(monkeypatch, code, message):
    def refuse(token):
        assert token == "cookie"
        raise access.AuthenticationError(code, message)

    monkeypatch.setattr(access, "authenticate_session", refuse)
    with pytest.raises(HTTPException) as error:
        auth.get_current_user(_request(cookie="cookie"))
    assert (error.value.status_code, error.value.detail) == (401, message)


def test_missing_cookie_preserves_error():
    with pytest.raises(HTTPException) as error:
        auth.get_current_user(_request())
    assert (error.value.status_code, error.value.detail) == (401, "Not authenticated")


def test_cookie_delegates_and_projects(monkeypatch):
    seen = []

    def authenticate(token):
        seen.append(token)
        return access.Principal({"username": "alice", "csrf_token": "csrf"})

    monkeypatch.setattr(access, "authenticate_session", authenticate)
    assert auth.get_current_user(_request(cookie="cookie")) == {"username": "alice", "csrf_token": "csrf"}
    assert seen == ["cookie"]


@pytest.mark.parametrize(
    "winner,expected",
    [("query", ["query"]), ("header", ["query", "header"]), ("cookie", ["query", "header", "cookie"])],
)
def test_download_source_order_and_delegation(monkeypatch, winner, expected):
    from another_s3_manager.main import get_user_for_download

    seen = []

    def authenticate(token):
        seen.append(token)
        if token != winner:
            raise access.AuthenticationError("invalid_session", "Invalid authentication credentials")
        return access.Principal({"username": "alice", "csrf_token": "csrf"})

    monkeypatch.setattr(access, "authenticate_session", authenticate)
    user = get_user_for_download(token="query", request=_request(cookie="cookie", bearer="Bearer header"))
    assert user == {"username": "alice", "csrf_token": "csrf"}
    assert seen == expected


def test_invalid_query_with_real_valid_cookie():
    from another_s3_manager import users
    from another_s3_manager.main import get_user_for_download

    users.create_user("alice", "hash")
    token = access.create_access_token({"sub": "alice"})
    assert get_user_for_download(token="invalid", request=_request(cookie=token))["username"] == "alice"


def test_download_retains_its_error_text():
    from another_s3_manager.main import get_user_for_download

    with pytest.raises(HTTPException) as error:
        get_user_for_download(token="invalid", request=_request())
    assert (error.value.status_code, error.value.detail) == (401, "Authentication required")


@pytest.mark.parametrize(
    "code,message,status,reason",
    [
        ("banned", "Account is banned. Try again in 59 minutes.", 403, "banned"),
        ("invalid_password", "Incorrect username or password", 401, "invalid_password"),
    ],
)
def test_local_login_maps_service_refusal_and_metric(app_client, monkeypatch, code, message, status, reason):
    from another_s3_manager.metrics import auth_logins_total

    counter = auth_logins_total.labels(result=reason)
    before = counter._value.get()

    def refuse(username, password, config):
        assert (username, password) == ("alice", "wrong")
        raise access.AuthenticationError(code, message)

    monkeypatch.setattr(access, "authenticate_local", refuse)
    response = app_client.post("/api/login", data={"username": "alice", "password": "wrong"})
    assert response.status_code == status
    assert response.json() == {"detail": message}
    assert counter._value.get() == before + 1


def test_empty_install_seed_wrong_password_and_admin_exemption():
    from another_s3_manager import users

    assert users.count_users() == 0
    for _ in range(4):
        with pytest.raises(access.AuthenticationError) as error:
            access.authenticate_local("admin", "wrong", {})
        assert error.value.code == "invalid_password"
    assert users.count_users() == 1
    assert users.load_bans() == {}
    user = access.authenticate_local("admin", "admin123", {}).to_user_dict()
    assert user["is_admin"] is True
    assert user["password_set_via"] == "env"


def test_local_ban_and_success_reset(monkeypatch):
    from another_s3_manager import users
    from another_s3_manager.access import service

    users.create_user("alice", access.hash_password("correct"))
    # Fix the clock so the exact remaining-minute message is deterministic.
    monkeypatch.setattr(service.time, "time", lambda: 2000000000)
    for _ in range(2):
        with pytest.raises(access.AuthenticationError):
            access.authenticate_local("alice", "wrong", {})
    access.authenticate_local("alice", "correct", {})
    assert service._login_attempts["alice"]["failed_count"] == 0
    for _ in range(3):
        with pytest.raises(access.AuthenticationError):
            access.authenticate_local("alice", "wrong", {})
    with pytest.raises(access.AuthenticationError) as error:
        access.authenticate_local("alice", "correct", {})
    assert (error.value.code, error.value.message) == ("banned", "Account is banned. Try again in 60 minutes.")
