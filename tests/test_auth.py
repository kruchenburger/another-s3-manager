import importlib
import time
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, status
from jose import jwt
from starlette.requests import Request


def _make_request_with_cookie(token_value):
    """Build a fake Starlette Request whose .cookies acts like a dict."""
    request = MagicMock()
    request.cookies = {} if token_value is None else {"access_token": token_value}
    return request


def reload_auth():
    import another_s3_manager.auth as auth

    importlib.reload(auth)
    auth._login_attempts = {}
    return auth


def reload_users():
    import another_s3_manager.users as users

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
    import passlib.context as context

    import another_s3_manager.auth as auth

    calls = {"count": 0}

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

    monkeypatch.setattr("another_s3_manager.auth.CryptContext", lambda *a, **k: DummyContext())
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
    request = _make_request_with_cookie(token)
    user = auth.get_current_user(request)
    assert user["username"] == "user"
    assert "csrf_token" in user


def test_get_current_user_invalid_token(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    request = _make_request_with_cookie("invalid")
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_csrf_token_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="user", password="password", is_admin=False)
    token = auth.create_access_token({"sub": "user"})
    auth_request = _make_request_with_cookie(token)
    current_user = auth.get_current_user(auth_request)
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
    auth_request = _make_request_with_cookie(token)
    current_user = auth.get_current_user(auth_request)

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
    # User must exist for the ban FK to be honored
    users.create_user(username="user", password_hash="h")
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
    # User must exist for the ban FK to be honored
    users.create_user(username="user", password_hash="h")

    for _ in range(auth.MAX_LOGIN_ATTEMPTS):
        auth.record_login_attempt("user", success=False)

    bans = users.load_bans()
    assert "user" in bans
    assert bans["user"]["banned_until"] > time.time()


def test_record_login_attempt_admin_is_never_banned(tmp_path):
    """Admins must be exempt from the brute-force auto-ban: the `admin` username
    is predictable, and a drive-by attacker could otherwise lock the only admin
    out of the system. Brute-force defense for admins is the deployment layer's
    job (Cloudflare Access / WAF / strong password / 2FA)."""
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})
    users.create_user(username="root", password_hash="h", is_admin=True)

    # Hammer the admin account with way more than the threshold.
    for _ in range(auth.MAX_LOGIN_ATTEMPTS * 3):
        auth.record_login_attempt("root", success=False)

    bans = users.load_bans()
    assert "root" not in bans, "admin account must not be auto-banned"


def test_record_login_attempt_non_admin_still_banned_with_admin_exemption(tmp_path):
    """The admin exemption must not leak to non-admin users: non-admins are
    still banned per the existing rules."""
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})
    users.create_user(username="alice", password_hash="h", is_admin=False)

    for _ in range(auth.MAX_LOGIN_ATTEMPTS):
        auth.record_login_attempt("alice", success=False)

    bans = users.load_bans()
    assert "alice" in bans


def test_record_login_attempt_success_resets(tmp_path):
    auth = reload_auth()
    auth.record_login_attempt("user", success=False)
    auth.record_login_attempt("user", success=False)
    assert auth._login_attempts["user"]["failed_count"] == 2
    auth.record_login_attempt("user", success=True)
    assert auth._login_attempts["user"]["failed_count"] == 0


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
    request = _make_request_with_cookie(token)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_current_user_theme_always_present(monkeypatch):
    """_user_to_dict() always renders `theme` (the DB column is NOT NULL with
    a default), so a real get_user_by_username() result never lacks it —
    there is no dead "migration" branch to exercise anymore."""
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="noteheme", password="password", is_admin=False)

    token = auth.create_access_token({"sub": "noteheme"})
    request = _make_request_with_cookie(token)
    user = auth.get_current_user(request)
    assert user["theme"] == "auto"


def test_get_current_user_user_not_found(monkeypatch):
    """Pins the real deleted-user-race behavior: mint a valid JWT for a real
    user, delete that user's row, then drive get_current_user through the
    actual get_user_by_username() lookup (no stub) and assert the 401. This
    is the exact semantics the targeted-lookup refactor is riskiest
    against, so it must exercise the real DB path, not a mocked function."""
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    ensure_user(username="ghost", password="password", is_admin=False)

    token = auth.create_access_token({"sub": "ghost"})

    import another_s3_manager.users as users

    users.delete_user("ghost")

    request = _make_request_with_cookie(token)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request)
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.detail == "User not found"


def test_check_ban_removes_expired(monkeypatch):
    auth = reload_auth()

    def fake_load_bans():
        return {"user": {"banned_until": time.time() - 10}}

    saved = {"data": None}

    def fake_save_bans(data):
        saved["data"] = data

    monkeypatch.setattr("another_s3_manager.users.load_bans", fake_load_bans)
    monkeypatch.setattr("another_s3_manager.users.save_bans", fake_save_bans)

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


def test_record_login_attempt_logs(caplog):
    auth = reload_auth()
    users = reload_users()
    users.save_bans({})
    # User must exist for the ban FK to be honored
    users.create_user(username="noisy", password_hash="h")

    with caplog.at_level("WARNING", logger="another_s3_manager.auth"):
        for _ in range(auth.MAX_LOGIN_ATTEMPTS):
            auth.record_login_attempt("noisy", success=False)

    assert any("User noisy banned" in record.getMessage() for record in caplog.records)


def test_get_current_user_reads_from_cookie(monkeypatch, valid_jwt_token, valid_user_dict):
    """get_current_user pulls the token from request.cookies['access_token']."""
    auth = reload_auth()
    monkeypatch.setattr("another_s3_manager.users.get_user_by_username", lambda username: dict(valid_user_dict))

    request = _make_request_with_cookie(valid_jwt_token)
    user = auth.get_current_user(request)

    assert user["username"] == valid_user_dict["username"]


def test_get_current_user_401_when_cookie_missing():
    """No cookie -> 401."""
    auth = reload_auth()
    request = _make_request_with_cookie(None)
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request)
    assert exc.value.status_code == 401


def test_get_current_user_401_when_cookie_invalid():
    """Garbage cookie -> 401."""
    auth = reload_auth()
    request = _make_request_with_cookie("not-a-jwt")
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(request)
    assert exc.value.status_code == 401


def test_has_valid_session_true_for_valid_cookie(valid_jwt_token):
    """A well-formed, unexpired JWT with a `sub` claim -> True. This mirrors
    get_current_user's happy path but WITHOUT touching load_users()."""
    auth = reload_auth()
    request = _make_request_with_cookie(valid_jwt_token)
    assert auth.has_valid_session(request) is True


def test_has_valid_session_false_when_cookie_missing():
    """No access_token cookie -> False."""
    auth = reload_auth()
    request = _make_request_with_cookie(None)
    assert auth.has_valid_session(request) is False


def test_has_valid_session_false_for_garbage_token():
    """Undecodable/malformed token -> False."""
    auth = reload_auth()
    request = _make_request_with_cookie("not-a-jwt")
    assert auth.has_valid_session(request) is False


def test_has_valid_session_false_for_expired_token(monkeypatch):
    """Expired JWT -> False. jose raises ExpiredSignatureError (a JWTError
    subclass) on decode, which must be treated the same as any other
    undecodable token."""
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    expired_token = jwt.encode(
        {"sub": "user", "exp": int(time.time()) - 60},
        "secret",
        algorithm="HS256",
    )
    request = _make_request_with_cookie(expired_token)
    assert auth.has_valid_session(request) is False


def test_has_valid_session_false_when_sub_missing(monkeypatch):
    """Valid signature and not expired, but no `sub` claim -> False."""
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    token = jwt.encode(
        {"csrf_token": "tok", "exp": int(time.time()) + 60},
        "secret",
        algorithm="HS256",
    )
    request = _make_request_with_cookie(token)
    assert auth.has_valid_session(request) is False


def test_has_valid_session_never_touches_load_users(monkeypatch, valid_jwt_token):
    """The whole point of has_valid_session is to be DB-free — assert it never
    calls load_users()."""
    import another_s3_manager.users as users_module

    def _boom():
        raise AssertionError("has_valid_session must not call load_users()")

    monkeypatch.setattr(users_module, "load_users", _boom)
    auth = reload_auth()
    request = _make_request_with_cookie(valid_jwt_token)
    assert auth.has_valid_session(request) is True


def test_get_current_user_never_calls_load_users(monkeypatch):
    """get_current_user runs on every authenticated request. Before this fix
    it called load_users() — which loads every user row (plus a roles join)
    from the DB just to linearly scan for the one making the request. Assert
    it now only ever calls the targeted get_user_by_username() lookup."""
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")
    auth = reload_auth()
    users_module = reload_users()

    # Seed several users so a regression back to load_users() would have
    # real O(N) rows to scan, not an empty/trivial table.
    for name in ("alice", "bob", "carol", "dave"):
        users_module.create_user(username=name, password_hash="x")

    def _boom():
        raise AssertionError("get_current_user must not call load_users()")

    monkeypatch.setattr(users_module, "load_users", _boom)

    token = auth.create_access_token({"sub": "carol"})
    request = _make_request_with_cookie(token)
    user = auth.get_current_user(request)
    assert user["username"] == "carol"


def test_verify_password_warn_logs_when_hash_is_corrupt(caplog):
    """If both bcrypt AND pbkdf2_sha256 raise on a corrupted hash, we still
    return False (correct UX — user gets 'wrong password'), but we WARN-log
    so operators can detect the broken hash."""
    import logging

    from another_s3_manager.auth import verify_password

    with caplog.at_level(logging.WARNING, logger="another_s3_manager.auth"):
        # Garbage input that no scheme can parse.
        result = verify_password("anything", "$not-a-real-hash$xyz")

    assert result is False
    assert any(record.levelno == logging.WARNING and "verify" in record.message.lower() for record in caplog.records), (
        "Expected a WARNING log when both hash schemes fail"
    )
