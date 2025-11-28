import builtins
import importlib
from unittest.mock import MagicMock, Mock

import pytest
from botocore.exceptions import ClientError, CredentialRetrievalError


def reload_s3_client():
    import s3_client

    importlib.reload(s3_client)
    s3_client._s3_clients_cache.clear()
    return s3_client


def test_get_boto3_config():
    module = reload_s3_client()
    config = module._get_boto3_config()
    assert config.signature_version == "s3v4"
    assert config.retries["max_attempts"] == 3


def test_create_s3_client_default(mocker):
    module = reload_s3_client()
    mock_client = Mock("default")
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    client = module._create_s3_client_from_role({"type": "default"})
    assert client is mock_client
    assert patched_client.call_count == 1
    args, kwargs = patched_client.call_args
    assert args[0] == "s3"
    assert kwargs["use_ssl"] is module.S3_USE_SSL
    assert kwargs["verify"] is module.S3_VERIFY_SSL
    assert kwargs["config"].signature_version == "s3v4"
    assert "endpoint_url" not in kwargs


def test_create_s3_client_profile(mocker):
    module = reload_s3_client()
    session_mock = mocker.MagicMock()
    session_mock.client.return_value = "profile-client"
    mocker.patch("boto3.Session", return_value=session_mock)

    client = module._create_s3_client_from_role(
        {
            "type": "profile",
            "profile_name": "dev",
            "endpoint_url": "http://minio:9000",
            "use_ssl": False,
        }
    )
    assert client == "profile-client"
    session_mock.client.assert_called_once()
    _, kwargs = session_mock.client.call_args
    assert kwargs["endpoint_url"] == "http://minio:9000"
    assert kwargs["use_ssl"] is False


def test_create_s3_client_assume_role(mocker):
    module = reload_s3_client()

    sts_client = mocker.MagicMock()
    sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
        }
    }

    s3_client_mock = mocker.MagicMock()
    captured_kwargs = {}

    def client_side_effect(service_name, **kwargs):
        if service_name == "sts":
            return sts_client
        captured_kwargs.update(kwargs)
        return s3_client_mock

    mocker.patch("boto3.client", side_effect=client_side_effect)

    # Mock RefreshableCredentials
    refreshable_creds_mock = mocker.MagicMock()
    mocker.patch("s3_client.RefreshableCredentials.create_from_metadata", return_value=refreshable_creds_mock)

    # Mock BotocoreSession and its create_client method
    botocore_session_mock = mocker.MagicMock()
    botocore_session_mock.create_client.return_value = s3_client_mock
    mocker.patch("s3_client.BotocoreSession", return_value=botocore_session_mock)

    role = {
        "type": "assume_role",
        "role_arn": "arn:aws:iam::123:role/Test",
        "endpoint_url": "http://minio:9000",
        "use_ssl": False,
    }
    client = module._create_s3_client_from_role(role)
    assert client is s3_client_mock
    sts_client.assume_role.assert_called_once()
    # Check that create_client was called with correct arguments
    botocore_session_mock.create_client.assert_called_once()
    call_kwargs = botocore_session_mock.create_client.call_args[1]
    assert call_kwargs["endpoint_url"] == "http://minio:9000"
    assert call_kwargs["use_ssl"] is False


def test_create_s3_client_assume_role_with_datetime_expiration(mocker):
    """Test that assume_role handles datetime expiration correctly (not mocked RefreshableCredentials)."""
    module = reload_s3_client()
    from datetime import datetime, timezone

    sts_client = mocker.MagicMock()
    expiration_dt = datetime.now(timezone.utc)
    sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
            "Expiration": expiration_dt,  # datetime object
        }
    }

    s3_client_mock = mocker.MagicMock()
    captured_kwargs = {}

    def client_side_effect(service_name, **kwargs):
        if service_name == "sts":
            return sts_client
        captured_kwargs.update(kwargs)
        return s3_client_mock

    mocker.patch("boto3.client", side_effect=client_side_effect)

    # Mock BotocoreSession and its create_client method
    botocore_session_mock = mocker.MagicMock()
    botocore_session_mock.create_client.return_value = s3_client_mock
    mocker.patch("s3_client.BotocoreSession", return_value=botocore_session_mock)

    # Don't mock RefreshableCredentials - let it run to test datetime handling
    # But we need to verify it gets called with string expiry_time
    original_create = module.RefreshableCredentials.create_from_metadata
    call_args_capture = {}

    def capture_create(*args, **kwargs):
        call_args_capture['metadata'] = kwargs.get('metadata', args[0] if args else {})
        return mocker.MagicMock()

    mocker.patch("s3_client.RefreshableCredentials.create_from_metadata", side_effect=capture_create)

    role = {
        "type": "assume_role",
        "role_arn": "arn:aws:iam::123:role/Test",
    }
    client = module._create_s3_client_from_role(role)
    assert client is s3_client_mock
    sts_client.assume_role.assert_called_once()

    # Verify that expiry_time was passed as string, not datetime
    metadata = call_args_capture.get('metadata', {})
    expiry_time = metadata.get('expiry_time')
    assert expiry_time is not None
    assert isinstance(expiry_time, str), f"expiry_time should be string, got {type(expiry_time)}"
    # Should be ISO format string
    assert 'T' in expiry_time or '+' in expiry_time or 'Z' in expiry_time


def test_create_s3_client_credentials(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    role = {
        "type": "credentials",
        "access_key_id": "  AKIA ",
        "secret_access_key": " SECRET ",
        "region": " us-east-1 ",
    }
    client = module._create_s3_client_from_role(role)
    assert client is mock_client
    args, kwargs = patched_client.call_args
    assert args[0] == "s3"
    assert kwargs["aws_access_key_id"] == "AKIA"
    assert kwargs["aws_secret_access_key"] == "SECRET"
    assert kwargs["region_name"] == "us-east-1"
    assert kwargs["use_ssl"] is module.S3_USE_SSL
    assert kwargs["verify"] is module.S3_VERIFY_SSL
    assert kwargs["config"].signature_version == "s3v4"
    assert "endpoint_url" not in kwargs


def test_create_s3_client_custom_endpoint_and_path_style(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    role = {
        "type": "credentials",
        "access_key_id": "AKIA",
        "secret_access_key": "SECRET",
        "endpoint_url": "http://minio:9000",
        "use_ssl": False,
        "verify_ssl": False,
        "path_style": True,
    }

    client = module._create_s3_client_from_role(role)
    assert client is mock_client
    args, kwargs = patched_client.call_args
    assert kwargs["endpoint_url"] == "http://minio:9000"
    assert kwargs["use_ssl"] is False
    assert kwargs["verify"] is False
    assert kwargs["config"].s3["addressing_style"] == "path"


def test_get_s3_client_caches_results(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    mocker.patch("boto3.client", return_value=mock_client)

    client1 = module.get_s3_client()
    client2 = module.get_s3_client()
    assert client1 is client2


def test_get_s3_client_with_named_role(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    mocker.patch("boto3.client", return_value=mock_client)

    import config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["roles"] = [
        {
            "name": "Custom",
            "type": "default",
            "description": "Default creds",
            "endpoint_url": "http://minio:9000",
            "use_ssl": False,
        }
    ]
    config_module.save_config(config_data)

    client = module.get_s3_client("Custom")
    assert client is mock_client


def test_get_s3_client_missing_role_raises(mocker):
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module.get_s3_client("missing")


def test_clear_s3_clients_cache(mocker):
    module = reload_s3_client()
    mocker.patch("boto3.client", return_value="client")
    module.get_s3_client()
    assert module._s3_clients_cache
    module.clear_s3_clients_cache()
    assert module._s3_clients_cache == {}


def test_s3_client_import_fallback(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "constants":
            raise ImportError("mock")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("s3_client"))
    try:
        assert module.S3_USE_SSL is True
        assert module.S3_VERIFY_SSL is True
    finally:
        importlib.reload(module)


def test_create_s3_client_requires_profile_name():
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module._create_s3_client_from_role({"type": "profile"})


def test_create_s3_client_requires_role_arn():
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module._create_s3_client_from_role({"type": "assume_role"})


def test_create_s3_client_credentials_require_keys():
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module._create_s3_client_from_role({"type": "credentials"})


def test_create_s3_client_credentials_empty_after_trim():
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module._create_s3_client_from_role(
            {
                "type": "credentials",
                "access_key_id": "   ",
                "secret_access_key": "   ",
            }
        )


def test_create_s3_client_unknown_type():
    module = reload_s3_client()
    with pytest.raises(ValueError):
        module._create_s3_client_from_role({"type": "unknown"})


def test_get_s3_client_without_roles_uses_default(mocker):
    module = reload_s3_client()
    mocker.patch("boto3.client", return_value="client")
    import config as config_module

    config_module.save_config(
        {
            "roles": [],
            "items_per_page": 200,
            "enable_lazy_loading": True,
            "max_file_size": 100,
        }
    )

    client = module.get_s3_client()
    assert client == "client"


def test_get_s3_client_missing_named_role_raises(mocker):
    module = reload_s3_client()
    mocker.patch("boto3.client", return_value="client")
    import config as config_module

    config_module.save_config(
        {
            "roles": [{"name": "OnlyDefault", "type": "default"}],
            "items_per_page": 200,
            "enable_lazy_loading": True,
            "max_file_size": 100,
        }
    )

    with pytest.raises(ValueError):
        module.get_s3_client("Missing")


def test_parse_bool_helper():
    module = reload_s3_client()
    assert module._parse_bool("true", False) is True
    assert module._parse_bool("FALSE", True) is False
    assert module._parse_bool(None, True) is True
    assert module._parse_bool(0, True) is False


def test_create_s3_client_s3_compatible(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    role = {
        "type": "s3_compatible",
        "access_key_id": "minioadmin",
        "secret_access_key": "minioadmin",
        "endpoint_url": "http://minio:9000",
        "use_ssl": False,
        "verify_ssl": False,
        "addressing_style": "path",
        "region": "us-east-1",
    }
    client = module._create_s3_client_from_role(role)
    assert client is mock_client
    args, kwargs = patched_client.call_args
    assert args[0] == "s3"
    assert kwargs["aws_access_key_id"] == "minioadmin"
    assert kwargs["aws_secret_access_key"] == "minioadmin"
    assert kwargs["endpoint_url"] == "http://minio:9000"
    assert kwargs["use_ssl"] is False
    assert kwargs["verify"] is False
    assert kwargs["region_name"] == "us-east-1"
    assert kwargs["config"].s3["addressing_style"] == "path"


def test_create_s3_client_s3_compatible_defaults(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    role = {
        "type": "s3_compatible",
        "access_key_id": "  mykey  ",
        "secret_access_key": "  mysecret  ",
        "endpoint_url": "  https://s3.example.com  ",
    }
    client = module._create_s3_client_from_role(role)
    assert client is mock_client
    args, kwargs = patched_client.call_args
    assert kwargs["aws_access_key_id"] == "mykey"
    assert kwargs["aws_secret_access_key"] == "mysecret"
    assert kwargs["endpoint_url"] == "https://s3.example.com"
    assert kwargs["use_ssl"] is True  # Default
    assert kwargs["verify"] is True  # Default
    assert "region_name" not in kwargs
    assert kwargs["config"].signature_version == "s3v4"


def test_create_s3_client_s3_compatible_requires_endpoint_url():
    module = reload_s3_client()
    with pytest.raises(ValueError, match="endpoint_url is required"):
        module._create_s3_client_from_role(
            {
                "type": "s3_compatible",
                "access_key_id": "key",
                "secret_access_key": "secret",
            }
        )


def test_create_s3_client_s3_compatible_requires_keys():
    module = reload_s3_client()
    with pytest.raises(ValueError, match="access_key_id and secret_access_key are required"):
        module._create_s3_client_from_role(
            {
                "type": "s3_compatible",
                "endpoint_url": "http://minio:9000",
            }
        )


def test_create_s3_client_s3_compatible_empty_after_trim():
    module = reload_s3_client()
    with pytest.raises(ValueError, match="cannot be empty after trimming"):
        module._create_s3_client_from_role(
            {
                "type": "s3_compatible",
                "access_key_id": "   ",
                "secret_access_key": "   ",
                "endpoint_url": "   ",
            }
        )


def test_create_s3_client_s3_compatible_path_style_backward_compat(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = mocker.patch("boto3.client", return_value=mock_client)

    role = {
        "type": "s3_compatible",
        "access_key_id": "key",
        "secret_access_key": "secret",
        "endpoint_url": "http://minio:9000",
        "path_style": True,  # Backward compatibility
    }
    client = module._create_s3_client_from_role(role)
    assert client is mock_client
    args, kwargs = patched_client.call_args
    assert kwargs["config"].s3["addressing_style"] == "path"


def test_is_expired_credentials_error_handles_credential_retrieval_error():
    module = reload_s3_client()
    error = CredentialRetrievalError(provider="eks-pod-identity", error_msg="Token is expired")
    assert module._is_expired_credentials_error(error) is True


def test_is_expired_credentials_error_handles_client_error():
    module = reload_s3_client()
    error = ClientError(
        {"Error": {"Code": "ExpiredTokenException", "Message": "Token expired"}}, "ListBuckets"
    )
    assert module._is_expired_credentials_error(error) is True


def test_execute_with_s3_retry_clears_cache_on_expired_creds(mocker):
    module = reload_s3_client()
    mocker.patch.object(module, "get_s3_client", return_value="client")
    mocker.patch.object(module, "_is_expired_credentials_error", return_value=True)
    invalidate_mock = mocker.patch.object(module, "invalidate_s3_client")
    clear_cache_mock = mocker.patch.object(module, "_clear_boto3_cached_credentials")

    call_counter = {"count": 0}

    def failing_then_successful_callback(_client):
        call_counter["count"] += 1
        if call_counter["count"] == 1:
            raise RuntimeError("Token expired")
        return "ok"

    result = module.execute_with_s3_retry(None, failing_then_successful_callback)

    assert result == "ok"
    assert call_counter["count"] == 2
    invalidate_mock.assert_called_once_with(None)
    clear_cache_mock.assert_called_once()


class Mock(MagicMock):
    """Helper class to improve assertion error messages."""

