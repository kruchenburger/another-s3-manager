import builtins
import importlib
import sys

import pytest


@pytest.fixture
def restore_jwt_secret(monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY', 'test-secret-key')


def test_main_import_without_dotenv(monkeypatch, restore_jwt_secret):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == 'dotenv':
            raise ImportError('missing')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', fake_import)
    import main
    importlib.reload(main)


def test_main_import_missing_jwt_secret(monkeypatch):
    monkeypatch.delenv('JWT_SECRET_KEY', raising=False)

    def boom():
        raise ValueError('missing secret')

    monkeypatch.setattr('auth.get_jwt_secret_key', boom)

    exit_called = {}

    def fake_exit(code):
        exit_called['code'] = code
        raise RuntimeError('exit called')

    monkeypatch.setattr(sys, 'exit', fake_exit)

    import main
    with pytest.raises(RuntimeError):
        importlib.reload(main)
    assert exit_called.get('code') == 1

    monkeypatch.setenv('JWT_SECRET_KEY', 'test-secret-key')
    monkeypatch.setattr('auth.get_jwt_secret_key', lambda: 'test-secret-key')
    importlib.reload(main)


def test_main_import_load_dotenv_without_path(monkeypatch):
    monkeypatch.setenv('JWT_SECRET_KEY', 'secret')

    calls = {}

    def fake_load_dotenv(*args, **kwargs):
        calls['args'] = args
        calls['kwargs'] = kwargs

    monkeypatch.setattr('dotenv.load_dotenv', fake_load_dotenv)
    monkeypatch.setattr('pathlib.Path.exists', lambda self: False)
    monkeypatch.delitem(sys.modules, 'main', raising=False)

    import main  # noqa: F401

    assert calls.get('args') == ()
    assert calls.get('kwargs') == {}
