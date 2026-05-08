"""Tests for the typed S3 exception hierarchy in another_s3_manager.errors."""

from __future__ import annotations

from another_s3_manager.errors import (
    CredentialsExpiredError,
    S3AccessDeniedError,
    S3ConfigError,
    S3NetworkError,
    S3NotFoundError,
    S3OperationError,
)


def test_base_class_carries_code_message_and_default_500_status():
    err = S3OperationError("InvalidXYZ", "something broke")
    assert err.code == "InvalidXYZ"
    assert err.http_status == 500
    assert str(err) == "something broke"


def test_base_class_accepts_explicit_status():
    err = S3OperationError("X", "y", http_status=418)
    assert err.http_status == 418


def test_config_error_defaults_to_400():
    err = S3ConfigError("InvalidRegion", "bad region")
    assert err.code == "InvalidRegion"
    assert err.http_status == 400
    assert isinstance(err, S3OperationError)


def test_access_denied_defaults_to_403():
    err = S3AccessDeniedError("AccessDenied", "no")
    assert err.http_status == 403


def test_not_found_defaults_to_404():
    err = S3NotFoundError("NoSuchBucket", "missing")
    assert err.http_status == 404


def test_network_defaults_to_502():
    err = S3NetworkError("EndpointConnectionError", "dns failed")
    assert err.http_status == 502


def test_credentials_expired_defaults_to_401():
    err = CredentialsExpiredError("ExpiredToken", "stale token")
    assert err.http_status == 401


def test_subclass_status_can_be_overridden():
    err = S3ConfigError("X", "y", http_status=422)
    assert err.http_status == 422


def test_str_returns_message_not_code():
    err = S3AccessDeniedError("AccessDenied", "User does not have permission")
    assert str(err) == "User does not have permission"
    # The code is the structured field, NOT in the message.
    assert "AccessDenied" not in str(err)


def test_all_subclasses_inherit_from_base():
    for cls in (S3ConfigError, S3AccessDeniedError, S3NotFoundError, S3NetworkError, CredentialsExpiredError):
        assert issubclass(cls, S3OperationError)
        assert issubclass(cls, Exception)
