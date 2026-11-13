import pytest

from another_s3_manager import access, api_tokens, auth, users
from another_s3_manager.access import passwords, sessions


def test_compatibility_exports_are_same_objects():
    assert auth.hash_password is access.hash_password is passwords.hash_password
    assert auth.verify_password is access.verify_password is passwords.verify_password
    assert auth.pwd_context is access.pwd_context is passwords.pwd_context
    assert auth.create_access_token is access.create_access_token is sessions.create_access_token
    assert auth.get_jwt_secret_key is access.get_jwt_secret_key is sessions.get_jwt_secret_key
    assert auth.generate_csrf_token is access.generate_csrf_token is sessions.generate_csrf_token
    from another_s3_manager.access import tokens
    from another_s3_manager.access import users as owner

    assert users.role_grants_lock is owner.role_grants_lock
    assert users._admin_password_force_enabled is owner._admin_password_force_enabled
    assert api_tokens._utcnow is tokens._utcnow


@pytest.mark.parametrize("password", ["ordinary", "a" * 71 + "é" + "tail", "é" * 80])
def test_password_truncation_is_utf8_byte_based(password):
    truncated = password.encode()[:72].decode(errors="ignore")
    hashed = passwords.hash_password(password)
    assert passwords.verify_password(truncated, hashed)
    assert not passwords.verify_password("wrong", hashed)


def test_pbkdf2_historical_fallback():
    from passlib.context import CryptContext

    hashed = CryptContext(schemes=["pbkdf2_sha256"]).hash("historical")
    assert passwords.verify_password("historical", hashed)
    assert not passwords.verify_password("wrong", hashed)
