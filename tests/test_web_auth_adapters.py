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

    def authenticate(token, *, require_subject=False):
        seen.append(token)
        return access.Principal(
            {"id": 1, "auth_generation": "test-generation", "username": "alice", "csrf_token": "csrf"}
        )

    monkeypatch.setattr(access, "authenticate_session", authenticate)
    assert auth.get_current_user(_request(cookie="cookie")) == {
        "id": 1,
        "auth_generation": "test-generation",
        "username": "alice",
        "csrf_token": "csrf",
    }
    assert seen == ["cookie"]


@pytest.mark.parametrize(
    "winner,expected",
    [("query", ["query"]), ("header", ["query", "header"]), ("cookie", ["query", "header", "cookie"])],
)
def test_download_source_order_and_delegation(monkeypatch, winner, expected):
    from another_s3_manager.main import get_user_for_download

    seen = []

    def authenticate(token, *, require_subject=False):
        seen.append(token)
        if token != winner:
            raise access.AuthenticationError("invalid_session", "Invalid authentication credentials")
        return access.Principal(
            {"id": 1, "auth_generation": "test-generation", "username": "alice", "csrf_token": "csrf"}
        )

    monkeypatch.setattr(access, "authenticate_session", authenticate)
    user = get_user_for_download(token="query", request=_request(cookie="cookie", bearer="Bearer header"))
    assert user == {"id": 1, "auth_generation": "test-generation", "username": "alice", "csrf_token": "csrf"}
    assert seen == expected


def test_invalid_query_with_real_valid_cookie():
    from another_s3_manager import users
    from another_s3_manager.main import get_user_for_download

    users.create_user("alice", "hash")
    token = access.issue_session(
        access.principal_for(users.get_user_by_username("alice")["id"]), method="pwd", lifetime_minutes=180
    )
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

    counter = auth_logins_total.labels(method="local", result=reason)
    before = counter._value.get()

    def refuse(username, password, config):
        assert (username, password) == ("alice", "wrong")
        raise access.AuthenticationError(code, message)

    monkeypatch.setattr(access, "authenticate_local", refuse)
    response = app_client.post("/api/login", data={"username": "alice", "password": "wrong"})
    assert response.status_code == status
    assert response.json() == {"detail": message}
    assert counter._value.get() == before + 1


@pytest.mark.parametrize(
    "code", ["ACCOUNT_DISABLED", "ACCOUNT_REPLACED", "SESSION_EPOCH_MISMATCH", "SSO_AUTHZ_EXPIRED"]
)
@pytest.mark.parametrize("door", ["cookie", "query", "bearer", "download_cookie"])
def test_current_account_denial_mapping(monkeypatch, code, door):
    from another_s3_manager.main import get_user_for_download

    def refuse(*args, **kwargs):
        raise access.AuthenticationError(code, "private diagnostic")

    monkeypatch.setattr(access, "authenticate_session", refuse)
    with pytest.raises(HTTPException) as error:
        if door == "cookie":
            auth.get_current_user(_request(cookie="token"))
        else:
            get_user_for_download(
                token="token" if door == "query" else None,
                request=_request(
                    cookie="token" if door == "download_cookie" else None,
                    bearer="Bearer token" if door == "bearer" else "",
                ),
            )
    assert error.value.status_code == 401
    assert error.value.detail == (
        "Invalid authentication credentials" if door == "cookie" else "Authentication required"
    )


@pytest.mark.parametrize("source", ["query", "bearer", "cookie"])
@pytest.mark.parametrize("change", ["disable", "epoch"])
def test_download_all_sources_reject_disabled_or_epoch_mismatch(source, change):
    from another_s3_manager import users
    from another_s3_manager.main import get_user_for_download

    user = users.create_user("alice", "hash")
    token = access.issue_session(access.Principal(user), method="pwd", lifetime_minutes=180)
    users.update_user("alice", **({"is_disabled": True} if change == "disable" else {"password_hash": "new"}))
    with pytest.raises(HTTPException) as error:
        get_user_for_download(
            token=token if source == "query" else None,
            request=_request(
                cookie=token if source == "cookie" else None, bearer="Bearer " + token if source == "bearer" else ""
            ),
        )
    assert error.value.status_code == 401


@pytest.mark.parametrize(
    "code", ["ACCOUNT_DISABLED", "ACCOUNT_REPLACED", "SESSION_EPOCH_MISMATCH", "SSO_AUTHZ_EXPIRED"]
)
def test_login_current_account_refusal_has_wrong_password_answer(app_client, monkeypatch, code):
    from another_s3_manager.metrics import auth_logins_total

    def refused(*args, **kwargs):
        raise access.AuthenticationError(code, "private diagnostic")

    counter = auth_logins_total.labels(method="local", result="invalid_password")
    before = counter._value.get()
    monkeypatch.setattr(access, "authenticate_local", refused)
    response = app_client.post("/api/login", data={"username": "alice", "password": "correct"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}
    assert counter._value.get() == before + 1
