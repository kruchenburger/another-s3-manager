import builtins
import importlib
import json
import time
from datetime import timedelta, UTC

import pytest
from jose import jwt
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request


def reload_auth():
    import auth

    importlib.reload(auth)
    auth._login_attempts = {}
    return auth


def reload_users():
    import users

    importlib.reload(users)
    return users


def ensure_user(username="admin", password="password", is_admin=True):
    users = reload_users()
    hashed = reload_auth().hash_password(password)
    users.save_users(
        {
            "users": [
                {
                    "username": username,
                    "password_hash": hashed,
                    "is_admin": is_admin,
                    "allowed_roles": [],
                    "theme": "auto",
                    "created_at": time.time(),
                }
            ]
        }
    )


def test_cryptcontext_fallback_initialization(monkeypatch):
    import auth
    import passlib.context as context

    calls = {"count": 0}
    original = context.CryptContext

    class FakeContext:
        def __init__(self, *args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("bcrypt unavailable")

        def hash(self, password):
            return "hash"

        def verify(self, password, hashed):
            return True

    monkeypatch.setattr(context, "CryptContext", FakeContext)
    module = importlib.reload(auth)
    try:
        assert calls["count"] == 2
        assert isinstance(module.pwd_context, FakeContext)
    finally:
        importlib.reload(auth)


def test_verify_password_all_contexts_fail(monkeypatch):
    auth = reload_auth()

    def boom_verify(*args, **kwargs):
        raise RuntimeError("broken")

    monkeypatch.setattr(auth.pwd_context, "verify", boom_verify)

    class DummyContext:
        def verify(self, *args, **kwargs):
            raise RuntimeError("fallback broken")

    monkeypatch.setattr("auth.CryptContext", lambda *a, **k: DummyContext())
    assert auth.verify_password("password", "hash") is False


def test_hash_password_re_raises_other_valueerror(monkeypatch):
    auth = reload_auth()

    def boom(password):
        raise ValueError("unexpected failure")

    monkeypatch.setattr(auth.pwd_context, "hash", boom)
    with pytest.raises(ValueError):
        auth.hash_password("password")


def test_get_jwt_secret_key_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    assert auth.get_jwt_secret_key() == "secret"


def test_get_jwt_secret_key_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    auth = reload_auth()
    with pytest.raises(ValueError):
        auth.get_jwt_secret_key()


def test_verify_password_success():
    auth = reload_auth()
    password = "strong-password"
    hashed = auth.hash_password(password)
    assert auth.verify_password(password, hashed) is True


def test_verify_password_failure():
    auth = reload_auth()
    hashed = auth.hash_password("secret")
    assert auth.verify_password("wrong", hashed) is False


def test_verify_password_long_password():
    auth = reload_auth()
    long_password = "x" * 200
    hashed = auth.hash_password(long_password)
    assert auth.verify_password(long_password, hashed) is True


def test_hash_password_returns_hash():
    auth = reload_auth()
    hashed = auth.hash_password("password")
    assert hashed != "password"
    assert auth.verify_password("password", hashed)


def test_generate_csrf_token_unique_and_length():
    auth = reload_auth()
    token1 = auth.generate_csrf_token()
    token2 = auth.generate_csrf_token()
    assert token1 != token2
    assert len(token1) >= 32


def test_create_access_token_contains_claims(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    token = auth.create_access_token({"sub": "user"}, expires_delta=timedelta(minutes=5))
    payload = jwt.decode(token, "secret", algorithms=["HS256"])
    assert payload["sub"] == "user"
    assert "csrf_token" in payload
    assert payload["exp"] > time.time()


def test_get_current_user_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="user", password="password", is_admin=False)
    token = auth.create_access_token({"sub": "user"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    user = auth.get_current_user(credentials)
    assert user["username"] == "user"
    assert "csrf_token" in user


def test_get_current_user_invalid_token(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid")
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(credentials)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_csrf_token_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="user", password="password", is_admin=False)
    token = auth.create_access_token({"sub": "user"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    current_user = auth.get_current_user(credentials)
    csrf_token = current_user["csrf_token"]

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"x-csrf-token", csrf_token.encode())],
        "path": "/",
    }
    request = Request(scope)
    assert auth.verify_csrf_token(request, current_user=current_user) is True


def test_verify_csrf_token_invalid(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="user", password="password", is_admin=False)
    token = auth.create_access_token({"sub": "user"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    current_user = auth.get_current_user(credentials)

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"x-csrf-token", b"invalid")],
        "path": "/",
    }
    request = Request(scope)
    with pytest.raises(HTTPException) as exc:
        auth.verify_csrf_token(request, current_user=current_user)
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_get_current_admin_user_success():
    auth = reload_auth()
    admin = {"username": "admin", "is_admin": True}
    assert auth.get_current_admin_user(admin)["username"] == "admin"


def test_get_current_admin_user_forbidden():
    auth = reload_auth()
    with pytest.raises(HTTPException) as exc:
        auth.get_current_admin_user({"username": "user", "is_admin": False})
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_check_ban_true(tmp_path):
    auth = reload_auth()
    users = reload_users()
    bans = {"user": {"banned_until": time.time() + 3600}}
    users.save_bans(bans)
    assert auth.check_ban("user") is True


def test_check_ban_false(tmp_path):
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})
    assert auth.check_ban("user") is False


def test_record_login_attempt_ban(tmp_path):
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})

    for _ in range(auth.MAX_LOGIN_ATTEMPTS):
        auth.record_login_attempt("user", success=False)

    bans = users.load_bans()
    assert "user" in bans
    assert bans["user"]["banned_until"] > time.time()


def test_record_login_attempt_success_resets(tmp_path):
    auth = reload_auth()
    auth.record_login_attempt("user", success=False)
    auth.record_login_attempt("user", success=False)
    assert auth._login_attempts["user"]["failed_count"] == 2
    auth.record_login_attempt("user", success=True)
    assert auth._login_attempts["user"]["failed_count"] == 0


def test_import_fallback_when_constants_unavailable(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "constants":
            raise ImportError("mock")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("auth"))
    try:
        assert module.JWT_ALGORITHM == "HS256"
        assert module.ACCESS_TOKEN_EXPIRE_MINUTES == 60 * 24
    finally:
        importlib.reload(module)


def test_verify_password_uses_fallback_context(monkeypatch):
    auth = reload_auth()

    def boom(*args, **kwargs):
        raise RuntimeError("broken verify")

    monkeypatch.setattr(auth.pwd_context, "verify", boom)
    fallback = auth.CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    hashed = fallback.hash("secret")
    assert auth.verify_password("secret", hashed) is True


def test_hash_password_fallback(monkeypatch):
    auth = reload_auth()

    def boom(password):
        raise ValueError("password cannot be longer than 72 bytes")

    monkeypatch.setattr(auth.pwd_context, "hash", boom)
    hashed = auth.hash_password("password")
    assert auth.verify_password("password", hashed) is True


def test_get_current_user_missing_sub(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    token = jwt.encode(
        {"csrf_token": "tok", "exp": int(time.time()) + 60},
        "secret",
        algorithm="HS256",
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(credentials)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_current_user_adds_missing_theme(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()

    def fake_load_users():
        return {
            "users": [
                {
                    "username": "noteheme",
                    "password_hash": auth.hash_password("password"),
                    "is_admin": False,
                }
            ]
        }

    saved = {}

    def fake_save_users(data):
        saved["data"] = data

    monkeypatch.setattr("users.load_users", fake_load_users)
    monkeypatch.setattr("users.save_users", fake_save_users)

    token = auth.create_access_token({"sub": "noteheme"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    user = auth.get_current_user(credentials)
    assert user["theme"] == "auto"
    assert saved["data"]["users"][0]["theme"] == "auto"


def test_get_current_user_user_not_found(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()

    monkeypatch.setattr("users.load_users", lambda: {"users": []})

    token = auth.create_access_token({"sub": "ghost"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(credentials)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.detail == "User not found"


def test_check_ban_removes_expired(monkeypatch):
    auth = reload_auth()

    def fake_load_bans():
        return {"user": {"banned_until": time.time() - 10}}

    saved = {"data": None}

    def fake_save_bans(data):
        saved["data"] = data

    monkeypatch.setattr("users.load_bans", fake_load_bans)
    monkeypatch.setattr("users.save_bans", fake_save_bans)

    assert auth.check_ban("user") is False
    assert saved["data"] == {}


def test_verify_csrf_token_missing_header():
    auth = reload_auth()
    scope = {"type": "http", "method": "POST", "headers": [], "path": "/"}
    request = Request(scope)
    with pytest.raises(HTTPException) as exc:
        auth.verify_csrf_token(request, current_user={"csrf_token": "expected"})
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_verify_csrf_token_missing_expected(monkeypatch):
    auth = reload_auth()
    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"x-csrf-token", b"value")],
        "path": "/",
    }
    request = Request(scope)
    with pytest.raises(HTTPException) as exc:
        auth.verify_csrf_token(request, current_user={})
    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_record_login_attempt_logs(monkeypatch):
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})

    messages = []

    def fake_print(message):
        messages.append(message)

    monkeypatch.setattr(builtins, "print", fake_print)
    for _ in range(auth.MAX_LOGIN_ATTEMPTS):
        auth.record_login_attempt("noisy", success=False)

    assert any("User noisy banned" in msg for msg in messages)

