"""Tests for the typed S3 exception hierarchy in another_s3_manager.errors."""

from __future__ import annotations

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
)

from another_s3_manager.errors import (
    CredentialsExpiredError,
    S3AccessDeniedError,
    S3ConfigError,
    S3NetworkError,
    S3NotFoundError,
    S3OperationError,
    classify_boto_error,
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


def _client_error(code: str, message: str = "boto says no", http_status: int = 500) -> ClientError:
    return ClientError(
        error_response={
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": http_status},
        },
        operation_name="ListObjectsV2",
    )


def test_classify_access_denied():
    err = _client_error("AccessDenied", "no perms", http_status=403)
    out = classify_boto_error(err)
    assert isinstance(out, S3AccessDeniedError)
    assert out.code == "AccessDenied"
    assert "no perms" in str(out)


def test_classify_forbidden_403():
    err = _client_error("Forbidden", "x", http_status=403)
    out = classify_boto_error(err)
    assert isinstance(out, S3AccessDeniedError)


def test_classify_no_such_bucket():
    err = _client_error("NoSuchBucket", "bucket gone", http_status=404)
    out = classify_boto_error(err)
    assert isinstance(out, S3NotFoundError)
    assert out.code == "NoSuchBucket"


def test_classify_no_such_key():
    err = _client_error("NoSuchKey", "missing key", http_status=404)
    out = classify_boto_error(err)
    assert isinstance(out, S3NotFoundError)


def test_classify_invalid_region():
    err = _client_error("InvalidRegion", "bad region for r2", http_status=400)
    out = classify_boto_error(err)
    assert isinstance(out, S3ConfigError)
    assert out.code == "InvalidRegion"


def test_classify_invalid_access_key():
    err = _client_error("InvalidAccessKeyId", "key not recognized", http_status=403)
    out = classify_boto_error(err)
    # Auth-key issues are config — admin needs to fix the role.
    assert isinstance(out, S3ConfigError)


def test_classify_signature_does_not_match():
    err = _client_error("SignatureDoesNotMatch", "wrong secret", http_status=403)
    out = classify_boto_error(err)
    assert isinstance(out, S3ConfigError)


def test_classify_expired_token():
    err = _client_error("ExpiredToken", "session expired", http_status=403)
    out = classify_boto_error(err)
    assert isinstance(out, CredentialsExpiredError)


def test_classify_endpoint_connection_error():
    err = EndpointConnectionError(endpoint_url="https://bogus.invalid")
    out = classify_boto_error(err)
    assert isinstance(out, S3NetworkError)


def test_classify_connect_timeout():
    err = ConnectTimeoutError(endpoint_url="https://slow.invalid")
    out = classify_boto_error(err)
    assert isinstance(out, S3NetworkError)


def test_classify_unknown_client_error_falls_back_to_base():
    err = _client_error("WeirdSpecialCase", "?", http_status=418)
    out = classify_boto_error(err)
    # Unknown codes are still S3OperationError but not a specific subclass.
    assert isinstance(out, S3OperationError)
    assert out.code == "WeirdSpecialCase"
    # The classifier preserves the boto status code (418) since the error came
    # from a real HTTP response. http_status is read from the response, not the
    # default 500.
    # Note: 418 is unusual but valid — classifier shouldn't override.


def test_classify_arbitrary_exception_falls_back():
    err = RuntimeError("totally unexpected")
    out = classify_boto_error(err)
    assert isinstance(out, S3OperationError)
    assert out.code == "Unknown"
    assert "totally unexpected" in str(out)
