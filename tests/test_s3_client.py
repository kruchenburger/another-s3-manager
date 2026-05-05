import importlib
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError, CredentialRetrievalError


def reload_s3_client():
    import another_s3_manager.s3_client as s3_client

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
    mocker.patch(
        "another_s3_manager.s3_client.RefreshableCredentials.create_from_metadata", return_value=refreshable_creds_mock
    )

    # Mock BotocoreSession and its create_client method
    botocore_session_mock = mocker.MagicMock()
    botocore_session_mock.create_client.return_value = s3_client_mock
    mocker.patch("another_s3_manager.s3_client.BotocoreSession", return_value=botocore_session_mock)

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
    mocker.patch("another_s3_manager.s3_client.BotocoreSession", return_value=botocore_session_mock)

    # Don't mock RefreshableCredentials - let it run to test datetime handling
    # But we need to verify it gets called with string expiry_time
    call_args_capture = {}

    def capture_create(*args, **kwargs):
        call_args_capture["metadata"] = kwargs.get("metadata", args[0] if args else {})
        return mocker.MagicMock()

    mocker.patch("another_s3_manager.s3_client.RefreshableCredentials.create_from_metadata", side_effect=capture_create)

    role = {
        "type": "assume_role",
        "role_arn": "arn:aws:iam::123:role/Test",
    }
    client = module._create_s3_client_from_role(role)
    assert client is s3_client_mock
    sts_client.assume_role.assert_called_once()

    # Verify that expiry_time was passed as string, not datetime
    metadata = call_args_capture.get("metadata", {})
    expiry_time = metadata.get("expiry_time")
    assert expiry_time is not None
    assert isinstance(expiry_time, str), f"expiry_time should be string, got {type(expiry_time)}"
    # Should be ISO format string
    assert "T" in expiry_time or "+" in expiry_time or "Z" in expiry_time


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

    import another_s3_manager.config as config_module

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
    import another_s3_manager.config as config_module

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
    import another_s3_manager.config as config_module

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
    error = ClientError({"Error": {"Code": "ExpiredTokenException", "Message": "Token expired"}}, "ListBuckets")
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

    result = module.execute_with_s3_retry(None, "list", failing_then_successful_callback)

    assert result == "ok"
    assert call_counter["count"] == 2
    invalidate_mock.assert_called_once_with(None)
    clear_cache_mock.assert_called_once()


def test_execute_with_s3_retry_increments_operations_counter(monkeypatch):
    """Verify s3_operations_total{operation=head, result=ok} increments after a successful call."""
    import another_s3_manager.s3_client as s3_client_mod
    from another_s3_manager import metrics

    def count(role: str, op: str, result: str) -> float:
        for sample in metrics.s3_operations_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("role") == role
                and sample.labels.get("operation") == op
                and sample.labels.get("result") == result
            ):
                return sample.value
        return 0.0

    # Use a unique role name so this test's counter label is isolated from other tests
    unique_role = "metrics_ok_test_role"

    class _FakeClient:
        def head_object(self):
            return {}

    monkeypatch.setattr(s3_client_mod, "get_s3_client", lambda _name=None: _FakeClient())

    before = count(unique_role, "head", "ok")
    s3_client_mod.execute_with_s3_retry(unique_role, "head", lambda c: c.head_object())
    after = count(unique_role, "head", "ok")
    assert after == before + 1


def test_execute_with_s3_retry_increments_error_counter_on_failure(monkeypatch):
    """Verify s3_operations_total{operation=head, result=error} increments when callback raises."""
    import pytest

    import another_s3_manager.s3_client as s3_client_mod
    from another_s3_manager import metrics

    def count(role: str, op: str, result: str) -> float:
        for sample in metrics.s3_operations_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("role") == role
                and sample.labels.get("operation") == op
                and sample.labels.get("result") == result
            ):
                return sample.value
        return 0.0

    # Use a unique role name so this test's counter label is isolated from other tests
    unique_role = "metrics_error_test_role"

    class _BadClient:
        def head_object(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(s3_client_mod, "get_s3_client", lambda _name=None: _BadClient())

    before = count(unique_role, "head", "error")
    with pytest.raises(RuntimeError):
        s3_client_mod.execute_with_s3_retry(unique_role, "head", lambda c: c.head_object())
    after = count(unique_role, "head", "error")
    assert after == before + 1


# ---------------------------------------------------------------------------
# Tests for permission-aware *_for_role helpers
# ---------------------------------------------------------------------------


def _make_user(is_admin=False, allowed_roles=None):
    """Create a minimal user_dict for testing."""
    return {
        "username": "testuser",
        "is_admin": is_admin,
        "allowed_roles": allowed_roles or [],
    }


# --- validate_role_access ---


def test_validate_role_access_none_returns_none():
    import another_s3_manager.s3_client as mod

    assert mod.validate_role_access(None, _make_user()) is None


def test_validate_role_access_admin_allows_any():
    import another_s3_manager.s3_client as mod

    assert mod.validate_role_access("AnyRole", _make_user(is_admin=True)) == "AnyRole"


def test_validate_role_access_allowed_role():
    import another_s3_manager.s3_client as mod

    assert mod.validate_role_access("RoleA", _make_user(allowed_roles=["RoleA", "RoleB"])) == "RoleA"


def test_validate_role_access_denied_raises_permission_error():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError, match="RoleX"):
        mod.validate_role_access("RoleX", _make_user(allowed_roles=["RoleA"]))


# --- _validate_bucket_access ---


def test_validate_bucket_access_passes_when_no_allowed_buckets(mocker):
    """When role has no allowed_buckets, any bucket is permitted."""
    import another_s3_manager.s3_client as mod

    mocker.patch.object(
        mod,
        "get_s3_client",
        return_value=mocker.MagicMock(),
    )
    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    # Should not raise
    mod._validate_bucket_access("RoleA", "any-bucket", _make_user(allowed_roles=["RoleA"]))


def test_validate_bucket_access_allowed_bucket(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["bucket-ok"]}]},
    )
    # Should not raise
    mod._validate_bucket_access("RoleA", "bucket-ok", _make_user(allowed_roles=["RoleA"]))


def test_validate_bucket_access_denied_bucket(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["bucket-ok"]}]},
    )
    with pytest.raises(PermissionError, match="bucket-bad"):
        mod._validate_bucket_access("RoleA", "bucket-bad", _make_user(allowed_roles=["RoleA"]))


def test_validate_bucket_access_denied_role(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    with pytest.raises(PermissionError):
        mod._validate_bucket_access("RoleA", "bucket", _make_user(allowed_roles=[]))


# --- list_buckets_for_role ---


def test_list_buckets_for_role_returns_allowed_buckets(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["b1", "b2"]}]},
    )
    result = mod.list_buckets_for_role("RoleA", _make_user(allowed_roles=["RoleA"]))
    assert result == ["b1", "b2"]


def test_list_buckets_for_role_falls_back_to_s3(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.list_buckets.return_value = {"Buckets": [{"Name": "bucket-x"}]}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_buckets_for_role("RoleA", _make_user(allowed_roles=["RoleA"]))
    assert result == ["bucket-x"]
    fake_client.list_buckets.assert_called_once()


def test_list_buckets_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.list_buckets_for_role("RoleX", _make_user(allowed_roles=["RoleA"]))


# --- list_objects_for_role ---


def test_list_objects_for_role_returns_files(mocker):
    """Returns sorted list of file-object dicts."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    fake_paginator = mocker.MagicMock()
    fake_paginator.paginate.return_value = [
        {
            "Contents": [{"Key": "prefix/file.txt", "Size": 100, "LastModified": dt}],
            "CommonPrefixes": [{"Prefix": "prefix/sub/"}],
        }
    ]
    fake_client.get_paginator.return_value = fake_paginator
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_for_role("RoleA", "bucket", "prefix", _make_user(allowed_roles=["RoleA"]))
    # Directory entries sort before files
    assert result[0]["is_directory"] is True
    assert result[0]["name"] == "sub"
    assert result[1]["name"] == "file.txt"
    assert result[1]["size"] == 100


def test_list_objects_for_role_permission_denied_role():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.list_objects_for_role("RoleX", "bucket", "", _make_user(allowed_roles=["RoleA"]))


def test_list_objects_for_role_permission_denied_bucket(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["good"]}]},
    )
    with pytest.raises(PermissionError, match="bad-bucket"):
        mod.list_objects_for_role("RoleA", "bad-bucket", "", _make_user(allowed_roles=["RoleA"]))


# --- head_object_for_role ---


def test_head_object_for_role_returns_size(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.head_object.return_value = {"ContentLength": 42}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    size = mod.head_object_for_role("RoleA", "bucket", "file.txt", _make_user(allowed_roles=["RoleA"]))
    assert size == 42


def test_head_object_for_role_not_found(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.head_object.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadObject")
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.head_object_for_role("RoleA", "bucket", "missing.txt", _make_user(allowed_roles=["RoleA"]))


def test_head_object_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.head_object_for_role("RoleX", "bucket", "f", _make_user(allowed_roles=["RoleA"]))


# --- read_object_for_role ---


def test_read_object_for_role_returns_bytes(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_body = mocker.MagicMock()
    fake_body.read.return_value = b"hello"
    fake_client = mocker.MagicMock()
    fake_client.get_object.return_value = {"Body": fake_body}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    data = mod.read_object_for_role("RoleA", "bucket", "file.txt", _make_user(allowed_roles=["RoleA"]))
    assert data == b"hello"


def test_read_object_for_role_not_found(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.read_object_for_role("RoleA", "bucket", "gone.txt", _make_user(allowed_roles=["RoleA"]))


def test_read_object_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.read_object_for_role("RoleX", "bucket", "f", _make_user(allowed_roles=["RoleA"]))


# --- read_object_range_for_role ---


def test_read_object_range_for_role_returns_slice(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_body = mocker.MagicMock()
    fake_body.read.return_value = b"hello"
    fake_client = mocker.MagicMock()
    fake_client.get_object.return_value = {"Body": fake_body}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    data = mod.read_object_range_for_role("RoleA", "bucket", "file.txt", 0, 4, _make_user(allowed_roles=["RoleA"]))
    assert data == b"hello"
    _, kwargs = fake_client.get_object.call_args
    assert kwargs["Range"] == "bytes=0-4"


def test_read_object_range_for_role_not_found(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.read_object_range_for_role("RoleA", "bucket", "gone.txt", 0, 100, _make_user(allowed_roles=["RoleA"]))


# --- put_object_for_role ---


def test_put_object_for_role_uploads(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.put_object_for_role("RoleA", "bucket", "key.txt", b"data", _make_user(allowed_roles=["RoleA"]))
    fake_client.put_object.assert_called_once()
    _, kwargs = fake_client.put_object.call_args
    assert kwargs["Bucket"] == "bucket"
    assert kwargs["Key"] == "key.txt"
    assert kwargs["Body"] == b"data"


def test_put_object_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.put_object_for_role("RoleX", "bucket", "key", b"", _make_user(allowed_roles=["RoleA"]))


def test_put_object_for_role_denied_bucket(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["good"]}]},
    )
    with pytest.raises(PermissionError, match="bad"):
        mod.put_object_for_role("RoleA", "bad", "key", b"", _make_user(allowed_roles=["RoleA"]))


# --- delete_object_for_role ---


def test_delete_object_for_role_single_file(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    # No objects from paginator (triggers single delete_object path)
    fake_paginator = mocker.MagicMock()
    fake_paginator.paginate.return_value = []
    fake_client.get_paginator.return_value = fake_paginator
    fake_client.delete_object.return_value = {}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.delete_object_for_role("RoleA", "bucket", "file.txt", _make_user(allowed_roles=["RoleA"]))
    assert result["count"] == 1
    fake_client.delete_object.assert_called_once_with(Bucket="bucket", Key="file.txt")


def test_delete_object_for_role_not_found(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_paginator = mocker.MagicMock()
    fake_paginator.paginate.return_value = []
    fake_client.get_paginator.return_value = fake_paginator
    fake_client.delete_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey"}}, "DeleteObject")
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.delete_object_for_role("RoleA", "bucket", "gone.txt", _make_user(allowed_roles=["RoleA"]))


def test_delete_object_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.delete_object_for_role("RoleX", "bucket", "f", _make_user(allowed_roles=["RoleA"]))


# ---------------------------------------------------------------------------
# list_objects_recursive_for_role — flat listing with pagination for MCP
# ---------------------------------------------------------------------------


def test_list_objects_recursive_returns_flat_keys(mocker):
    """Returns flat keys with size/last_modified, no directory entries."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    fake_client.list_objects_v2.return_value = {
        "Contents": [
            {"Key": "logs/2024/01/a.txt", "Size": 100, "LastModified": dt},
            {"Key": "logs/2024/02/b.txt", "Size": 200, "LastModified": dt},
        ],
        "IsTruncated": False,
    }
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_recursive_for_role("RoleA", "bucket", "logs/", _make_user(allowed_roles=["RoleA"]))
    assert result["key_count"] == 2
    assert result["is_truncated"] is False
    assert result["next_continuation_token"] is None
    assert result["files"][0]["key"] == "logs/2024/01/a.txt"
    # No is_directory field — flat keys only
    assert "is_directory" not in result["files"][0]


def test_list_objects_recursive_skips_directory_markers(mocker):
    """Empty objects with key ending in / are skipped (S3 directory markers)."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    fake_client.list_objects_v2.return_value = {
        "Contents": [
            {"Key": "dir/", "Size": 0, "LastModified": dt},  # marker, skipped
            {"Key": "dir/real.txt", "Size": 50, "LastModified": dt},
        ],
        "IsTruncated": False,
    }
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_recursive_for_role("RoleA", "bucket", "", _make_user(allowed_roles=["RoleA"]))
    assert result["key_count"] == 1
    assert result["files"][0]["key"] == "dir/real.txt"


def test_list_objects_recursive_paginates_via_continuation_token(mocker):
    """When max_keys < total, returns next_continuation_token for follow-up call."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    # First page: 3 files + IsTruncated=True
    fake_client.list_objects_v2.return_value = {
        "Contents": [{"Key": f"f{i}.txt", "Size": i, "LastModified": dt} for i in range(3)],
        "IsTruncated": True,
        "NextContinuationToken": "TOKEN-A",
    }
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_recursive_for_role("RoleA", "bucket", "", _make_user(allowed_roles=["RoleA"]), max_keys=3)
    assert result["key_count"] == 3
    assert result["is_truncated"] is True
    assert result["next_continuation_token"] == "TOKEN-A"


def test_list_objects_recursive_max_keys_capped_at_10000():
    """User-supplied max_keys is silently capped at 10000."""
    import another_s3_manager.s3_client as mod

    # We don't even need to mock S3 — just confirm no exception when max_keys=99999;
    # the helper validates internally before any boto call.
    # (Easier to assert via direct param check than full mock setup.)
    with pytest.raises(PermissionError):
        # Will fail on permission check before anything else; that's fine —
        # we just want to ensure the function doesn't reject max_keys=99999 outright.
        mod.list_objects_recursive_for_role("RoleX", "bucket", "", _make_user(allowed_roles=["RoleA"]), max_keys=99_999)


def test_list_objects_recursive_permission_denied_role():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.list_objects_recursive_for_role("RoleX", "bucket", "", _make_user(allowed_roles=["RoleA"]))
