import pytest
from botocore.exceptions import ClientError

from utils import (
    sanitize_path,
    sanitize_bucket_name,
    validate_role_name,
    format_boto_error,
)


# -----------------------------------------------------------------------------
# sanitize_path
# -----------------------------------------------------------------------------


def test_sanitize_path_normalizes_and_trims():
    assert sanitize_path("/folder/sub/file.txt/") == "folder/sub/file.txt"


def test_sanitize_path_empty_returns_empty():
    assert sanitize_path("") == ""
    assert sanitize_path(None) == ""


def test_sanitize_path_raises_on_traversal():
    with pytest.raises(ValueError, match="path traversal not allowed"):
        sanitize_path("../secret.txt")


def test_sanitize_path_raises_on_invalid_chars():
    with pytest.raises(ValueError, match="contains invalid characters"):
        sanitize_path("folder/<bad>.txt")


# -----------------------------------------------------------------------------
# sanitize_bucket_name
# -----------------------------------------------------------------------------


def test_sanitize_bucket_name_valid():
    assert sanitize_bucket_name("My-Bucket.Name") == "my-bucket.name"


def test_sanitize_bucket_name_invalid_length():
    with pytest.raises(ValueError, match="between 3 and 63 characters"):
        sanitize_bucket_name("ab")


def test_sanitize_bucket_name_invalid_characters():
    with pytest.raises(ValueError, match="Invalid bucket name format"):
        sanitize_bucket_name("bucket_with_underscores")


def test_sanitize_bucket_name_empty():
    with pytest.raises(ValueError, match="cannot be empty"):
        sanitize_bucket_name("")


# -----------------------------------------------------------------------------
# validate_role_name
# -----------------------------------------------------------------------------


def test_validate_role_name_returns_trimmed():
    assert validate_role_name("  admin  ") == "admin"


def test_validate_role_name_none():
    assert validate_role_name(None) is None
    assert validate_role_name("   ") is None


def test_validate_role_name_invalid_characters():
    with pytest.raises(ValueError, match="contains invalid characters"):
        validate_role_name('role"name')


# -----------------------------------------------------------------------------
# format_boto_error
# -----------------------------------------------------------------------------


class DummyUnauthorizedSSOTokenError(Exception):
    pass


def test_format_boto_error_handles_sso_error():
    error = DummyUnauthorizedSSOTokenError("UnauthorizedSSOTokenError: expired")
    message = format_boto_error(error)
    assert "AWS SSO session has expired" in message


def test_format_boto_error_handles_client_error_access_denied():
    error = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Not allowed",
            }
        },
        "ListBuckets",
    )
    message = format_boto_error(error)
    assert message == "Access denied: Not allowed"


def test_format_boto_error_handles_no_credentials():
    class NoCredentials(Exception):
        pass

    message = format_boto_error(
        NoCredentials("Unable to locate credentials")
    )
    assert "credentials not found" in message.lower()


def test_format_boto_error_handles_generic_exception():
    message = format_boto_error(Exception("An error occurred (404) when calling the Describe operation: Not Found"))
    assert message == "Not Found"


def test_format_boto_error_handles_invalid_access_key():
    message = format_boto_error(Exception("InvalidAccessKeyId: bad key"))
    assert "invalid aws access key id" in message.lower()


def test_format_boto_error_handles_signature_mismatch():
    message = format_boto_error(Exception("SignatureDoesNotMatch: wrong signature"))
    assert "signature mismatch" in message.lower()


def test_format_boto_error_handles_client_error_message_only():
    error = ClientError({"Error": {"Code": "Custom", "Message": "Oops"}}, "ListBuckets")
    assert format_boto_error(error) == "Oops"


def test_format_boto_error_handles_sso_text_without_code():
    message = format_boto_error(Exception("SSO session expired"))
    assert "sso session has expired" in message.lower()


def test_format_boto_error_handles_nosuchbucket():
    error = ClientError({"Error": {"Code": "NoSuchBucket", "Message": "Missing"}}, "ListObjects")
    message = format_boto_error(error)
    assert "Bucket not found" in message


def test_format_boto_error_handles_nosuchkey():
    error = ClientError({"Error": {"Code": "NoSuchKey", "Message": "Missing"}}, "GetObject")
    message = format_boto_error(error)
    assert "Object not found" in message


def test_format_boto_error_handles_signature_client_error():
    error = ClientError({"Error": {"Code": "SignatureDoesNotMatch", "Message": "Mismatch"}}, "PutObject")
    message = format_boto_error(error)
    assert "signature mismatch" in message.lower()


def test_format_boto_error_handles_empty_message():
    class Dummy(Exception):
        pass

    message = format_boto_error(Dummy("An error occurred (403) when calling the Test operation: "))
    assert message == "An error occurred while accessing AWS services."


def test_format_boto_error_returns_message(monkeypatch):
    err = Exception("Something bad happened")
    assert format_boto_error(err) == "Something bad happened"


def test_format_boto_error_sso_profile_message():
    class FakeError:
        def __str__(self):
            return "SSO profile default expired"

    message = format_boto_error(FakeError())
    assert "aws sso login" in message.lower()


def test_format_boto_error_invalid_access_key_response():
    class FakeError:
        response = {"Error": {"Code": "InvalidAccessKeyId"}}

        def __str__(self):
            return ""

    message = format_boto_error(FakeError())
    assert "Invalid AWS Access Key ID" in message


def test_format_boto_error_signature_mismatch_response():
    class FakeError:
        response = {"Error": {"Code": "SignatureDoesNotMatch"}}

        def __str__(self):
            return ""

    message = format_boto_error(FakeError())
    assert "signature mismatch" in message.lower()


def test_format_boto_error_strip_prefix():
    err = Exception("An error occurred (Boom) when calling the Test operation: Something broke")
    message = format_boto_error(err)
    assert message == "Something broke"


def test_format_boto_error_colon_strip():
    err = Exception("An error occurred: Bad things happened")
    message = format_boto_error(err)
    assert message == "Bad things happened"