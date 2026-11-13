import builtins
import importlib
import sys

import pytest


@pytest.fixture
def restore_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")


def test_main_import_without_dotenv(monkeypatch, restore_jwt_secret):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    import another_s3_manager.main as main

    importlib.reload(main)


def test_main_import_missing_jwt_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    def boom():
        raise ValueError("missing secret")

    monkeypatch.setattr("another_s3_manager.auth.get_jwt_secret_key", boom)

    exit_called = {}

    def fake_exit(code):
        exit_called["code"] = code
        raise RuntimeError("exit called")

    monkeypatch.setattr(sys, "exit", fake_exit)

    import another_s3_manager.main as main

    with pytest.raises(RuntimeError):
        importlib.reload(main)
    assert exit_called.get("code") == 1

    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    monkeypatch.setattr("another_s3_manager.auth.get_jwt_secret_key", lambda: "test-secret-key")
    importlib.reload(main)


def test_main_import_load_dotenv_without_path(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "secret")

    calls = {}

    def fake_load_dotenv(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs

    monkeypatch.setattr("dotenv.load_dotenv", fake_load_dotenv)
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    monkeypatch.delitem(sys.modules, "another_s3_manager.main", raising=False)

    import another_s3_manager.main as main  # noqa: F401

    assert calls.get("args") == ()
    assert calls.get("kwargs") == {}


def _loaded_main():
    # The module registered in sys.modules, not the package attribute: an earlier test
    # re-imports main under a monkeypatched sys.modules entry, and on undo the package
    # attribute keeps pointing at a module object that reload() no longer finds.
    return importlib.import_module("another_s3_manager.main")


@pytest.mark.parametrize("value", ["0", "10081", "abc", "1.5"])
def test_main_import_refuses_invalid_session_lifetime(monkeypatch, value, capsys):
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", value)

    def fake_exit(code):
        raise SystemExit(code)

    monkeypatch.setattr(sys, "exit", fake_exit)
    main = _loaded_main()

    with pytest.raises(SystemExit) as caught:
        importlib.reload(main)
    assert caught.value.code == 1
    out = capsys.readouterr().out
    assert "JWT_ACCESS_TOKEN_EXPIRE_MINUTES" in out and "1 to 10080" in out

    monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    importlib.reload(main)


@pytest.mark.parametrize("value", ["1", "10080"])
def test_main_import_accepts_session_lifetime_bounds(monkeypatch, value):
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", value)
    main = _loaded_main()

    importlib.reload(main)
    assert main.access_service.validate_lifetime_minutes() == int(value)
    monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    importlib.reload(main)
