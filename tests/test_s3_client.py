import importlib
import threading
import time
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError, CredentialRetrievalError


def reload_s3_client():
    import another_s3_manager.s3_client as s3_client

    importlib.reload(s3_client)
    s3_client._s3_clients_cache.clear()
    return s3_client


def _mock_session_client(mocker, return_value=None, side_effect=None):
    """Patch `boto3.Session` so `_new_boto3_session().client(...)` is intercepted.

    The client-build code paths were moved off the module-level
    `boto3.client(...)` (shared, non-thread-safe default session) onto an
    explicit `boto3.Session()` per build — see `_new_boto3_session`. Tests
    that used to patch `boto3.client` directly now patch `boto3.Session`
    instead and assert against the returned Mock's `.client` attribute,
    which behaves identically to the old `boto3.client` mock for call_args
    purposes (same positional/keyword arguments are passed through).
    """
    session_mock = mocker.MagicMock()
    if side_effect is not None:
        session_mock.client.side_effect = side_effect
    else:
        session_mock.client.return_value = return_value
    mocker.patch("boto3.Session", return_value=session_mock)
    return session_mock.client


def test_get_boto3_config():
    module = reload_s3_client()
    config = module._get_boto3_config()
    assert config.signature_version == "s3v4"
    assert config.retries["max_attempts"] == 3


def test_create_s3_client_default(mocker):
    module = reload_s3_client()
    mock_client = Mock("default")
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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

    _mock_session_client(mocker, side_effect=client_side_effect)

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

    _mock_session_client(mocker, side_effect=client_side_effect)

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
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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
    _mock_session_client(mocker, return_value=mock_client)

    client1 = module.get_s3_client()
    client2 = module.get_s3_client()
    assert client1 is client2


def test_get_s3_client_with_named_role(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    _mock_session_client(mocker, return_value=mock_client)

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
    # Mock client must answer list_buckets() — get_s3_client probes it on cache miss.
    fake = mocker.MagicMock()
    fake.list_buckets.return_value = {"Buckets": []}
    _mock_session_client(mocker, return_value=fake)
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
    # Mock client must answer list_buckets() — get_s3_client probes it on cache miss.
    fake = mocker.MagicMock()
    fake.list_buckets.return_value = {"Buckets": []}
    _mock_session_client(mocker, return_value=fake)
    import another_s3_manager.config as config_module

    config_module.save_config(
        {
            "roles": [],
            "enable_lazy_loading": True,
            "max_file_size": 100,
        }
    )

    client = module.get_s3_client()
    assert client is fake


def test_get_s3_client_missing_named_role_raises(mocker):
    module = reload_s3_client()
    _mock_session_client(mocker, return_value="client")
    import another_s3_manager.config as config_module

    config_module.save_config(
        {
            "roles": [{"name": "OnlyDefault", "type": "default"}],
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
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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


def test_assume_role_retries_once_on_expired_credentials(mocker):
    """First assume_role raises an expired-credential error → cache cleared, retry succeeds."""
    from botocore.exceptions import CredentialRetrievalError

    from another_s3_manager import s3_client

    creds = {
        "AccessKeyId": "AKIATEST",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.side_effect = [
        CredentialRetrievalError(provider="x", error_msg="token expired"),
        {"Credentials": creds},
    ]
    _mock_session_client(mocker, return_value=sts)
    fake_client = mocker.Mock()
    mocker.patch.object(s3_client.BotocoreSession, "create_client", return_value=fake_client)
    clear = mocker.patch.object(s3_client, "_clear_boto3_cached_credentials")

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    client = s3_client._create_s3_client_from_role(role)

    assert client is fake_client
    assert sts.assume_role.call_count == 2
    clear.assert_called_once()


def test_assume_role_raises_typed_when_both_attempts_expired(mocker):
    """Both attempts hit expired creds → typed CredentialsExpiredError (→ 401 at HTTP boundary)."""
    from botocore.exceptions import CredentialRetrievalError

    from another_s3_manager import s3_client
    from another_s3_manager.errors import CredentialsExpiredError

    sts = mocker.Mock()
    sts.assume_role.side_effect = CredentialRetrievalError(provider="x", error_msg="token expired")
    _mock_session_client(mocker, return_value=sts)
    mocker.patch.object(s3_client, "_clear_boto3_cached_credentials")

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    with pytest.raises(CredentialsExpiredError):
        s3_client._create_s3_client_from_role(role)
    assert sts.assume_role.call_count == 2


def test_assume_role_refreshes_via_refreshable_credentials(mocker):
    """The RefreshableCredentials callback re-assumes the role to mint fresh creds on expiry."""
    from another_s3_manager import s3_client

    first = {
        "AccessKeyId": "AKIA1",
        "SecretAccessKey": "s1",
        "SessionToken": "t1",
        "Expiration": "2000-01-01T00:00:00Z",  # already past → next access forces a refresh
    }
    second = {
        "AccessKeyId": "AKIA2",
        "SecretAccessKey": "s2",
        "SessionToken": "t2",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.side_effect = [{"Credentials": first}, {"Credentials": second}]
    _mock_session_client(mocker, return_value=sts)

    captured = {}

    def capture(self, *a, **k):
        captured["session"] = self
        return mocker.Mock()

    mocker.patch.object(s3_client.BotocoreSession, "create_client", capture)

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    s3_client._create_s3_client_from_role(role)

    frozen = captured["session"]._credentials.get_frozen_credentials()
    assert frozen.access_key == "AKIA2"  # refreshed via a second assume_role
    assert sts.assume_role.call_count == 2


def test_assume_role_metrics_attribute_initial_and_refresh_to_separate_counters(mocker):
    """Pin per-call-site metric attribution.

    Both the initial assume and the refresh callback call `sts.assume_role`, so
    `test_assume_role_refreshes_via_refreshable_credentials` (call_count == 2) would
    still pass even if the two `.inc()` calls were swapped between call sites. This
    test reads `as3m_sts_assume_role_total` and `as3m_credentials_refreshed_total`
    separately before/after each phase to catch exactly that swap.
    """
    from another_s3_manager import s3_client
    from another_s3_manager.metrics import REGISTRY

    def sample(name: str, labels: dict) -> float:
        return REGISTRY.get_sample_value(name, labels) or 0.0

    first = {
        "AccessKeyId": "AKIA1",
        "SecretAccessKey": "s1",
        "SessionToken": "t1",
        "Expiration": "2000-01-01T00:00:00Z",  # already past → next access forces a refresh
    }
    second = {
        "AccessKeyId": "AKIA2",
        "SecretAccessKey": "s2",
        "SessionToken": "t2",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.side_effect = [{"Credentials": first}, {"Credentials": second}]
    _mock_session_client(mocker, return_value=sts)

    captured = {}

    def capture(self, *a, **k):
        captured["session"] = self
        return mocker.Mock()

    mocker.patch.object(s3_client.BotocoreSession, "create_client", capture)

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    assume_labels = {"role": "r", "result": "ok"}
    refresh_labels = {"role": "r", "result": "ok"}

    assume_before = sample("as3m_sts_assume_role_total", assume_labels)
    refresh_before = sample("as3m_credentials_refreshed_total", refresh_labels)

    s3_client._create_s3_client_from_role(role)

    assume_after_initial = sample("as3m_sts_assume_role_total", assume_labels)
    refresh_after_initial = sample("as3m_credentials_refreshed_total", refresh_labels)

    # Only the initial-assume counter moves; the refresh counter must stay untouched.
    assert assume_after_initial - assume_before == 1
    assert refresh_after_initial - refresh_before == 0

    # Drive the RefreshableCredentials refresh callback, same as the sibling test above.
    frozen = captured["session"]._credentials.get_frozen_credentials()
    assert frozen.access_key == "AKIA2"  # refreshed via a second assume_role

    assume_after_refresh = sample("as3m_sts_assume_role_total", assume_labels)
    refresh_after_refresh = sample("as3m_credentials_refreshed_total", refresh_labels)

    # Only the refresh counter moves this time; the initial-assume counter must not move again.
    assert refresh_after_refresh - refresh_after_initial == 1
    assert assume_after_refresh - assume_after_initial == 0


def test_assume_role_sts_region_falls_back_to_aws_region_env(mocker, monkeypatch):
    """The STS client gets its region from AWS_REGION when the role has none.

    botocore itself only reads AWS_DEFAULT_REGION / shared config for the
    region — without this fallback an assume_role role in a bare container
    (only AWS_REGION set, per the README env table) dies with NoRegionError
    ("You must specify a region") before it can even call AssumeRole.
    """
    from another_s3_manager import s3_client

    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    creds = {
        "AccessKeyId": "AKIATEST",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.return_value = {"Credentials": creds}
    boto_client = _mock_session_client(mocker, return_value=sts)
    create_client = mocker.patch.object(s3_client.BotocoreSession, "create_client", return_value=mocker.Mock())

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    s3_client._create_s3_client_from_role(role)

    assert boto_client.call_args.kwargs["region_name"] == "eu-central-1"
    # The assumed-role S3 client inherits the same region.
    assert create_client.call_args.kwargs["region_name"] == "eu-central-1"


def test_assume_role_role_region_beats_aws_region_env(mocker, monkeypatch):
    """An explicit region on the role config wins over the AWS_REGION env."""
    from another_s3_manager import s3_client

    monkeypatch.setenv("AWS_REGION", "eu-central-1")

    creds = {
        "AccessKeyId": "AKIATEST",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.return_value = {"Credentials": creds}
    boto_client = _mock_session_client(mocker, return_value=sts)
    mocker.patch.object(s3_client.BotocoreSession, "create_client", return_value=mocker.Mock())

    role = {
        "name": "r",
        "type": "assume_role",
        "role_arn": "arn:aws:iam::000000000000:role/x",
        "region": "us-west-2",
    }
    s3_client._create_s3_client_from_role(role)

    assert boto_client.call_args.kwargs["region_name"] == "us-west-2"


def test_assume_role_region_none_without_any_source(mocker, monkeypatch):
    """No role region and no AWS_REGION → region_name=None keeps botocore's own chain."""
    from another_s3_manager import s3_client

    monkeypatch.delenv("AWS_REGION", raising=False)

    creds = {
        "AccessKeyId": "AKIATEST",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2999-01-01T00:00:00Z",
    }
    sts = mocker.Mock()
    sts.assume_role.return_value = {"Credentials": creds}
    boto_client = _mock_session_client(mocker, return_value=sts)
    create_client = mocker.patch.object(s3_client.BotocoreSession, "create_client", return_value=mocker.Mock())

    role = {"name": "r", "type": "assume_role", "role_arn": "arn:aws:iam::000000000000:role/x"}
    s3_client._create_s3_client_from_role(role)

    assert boto_client.call_args.kwargs["region_name"] is None
    assert "region_name" not in create_client.call_args.kwargs


def test_create_s3_client_s3_compatible_path_style_backward_compat(mocker):
    module = reload_s3_client()
    mock_client = mocker.MagicMock()
    patched_client = _mock_session_client(mocker, return_value=mock_client)

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
    """Verify s3_operations_total{operation=head, error_code=none} increments after a successful call."""
    import another_s3_manager.s3_client as s3_client_mod
    from another_s3_manager import metrics

    def count(role: str, op: str, error_code: str) -> float:
        for sample in metrics.s3_operations_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("role") == role
                and sample.labels.get("operation") == op
                and sample.labels.get("error_code") == error_code
            ):
                return sample.value
        return 0.0

    # Use a unique role name so this test's counter label is isolated from other tests
    unique_role = "metrics_ok_test_role"

    class _FakeClient:
        def head_object(self):
            return {}

    monkeypatch.setattr(s3_client_mod, "get_s3_client", lambda _name=None: _FakeClient())

    before = count(unique_role, "head", "none")
    s3_client_mod.execute_with_s3_retry(unique_role, "head", lambda c: c.head_object())
    after = count(unique_role, "head", "none")
    assert after == before + 1


def test_execute_with_s3_retry_increments_error_counter_on_failure(monkeypatch):
    """Verify s3_operations_total{operation=head, error_code=other} increments when callback raises."""
    import pytest

    import another_s3_manager.s3_client as s3_client_mod
    from another_s3_manager import metrics

    def count(role: str, op: str, error_code: str) -> float:
        for sample in metrics.s3_operations_total.collect()[0].samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("role") == role
                and sample.labels.get("operation") == op
                and sample.labels.get("error_code") == error_code
            ):
                return sample.value
        return 0.0

    # Use a unique role name so this test's counter label is isolated from other tests
    unique_role = "metrics_error_test_role"

    class _BadClient:
        def head_object(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(s3_client_mod, "get_s3_client", lambda _name=None: _BadClient())

    before = count(unique_role, "head", "other")
    with pytest.raises(RuntimeError):
        s3_client_mod.execute_with_s3_retry(unique_role, "head", lambda c: c.head_object())
    after = count(unique_role, "head", "other")
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


def test_list_buckets_for_role_allowed_buckets_short_circuit(mocker):
    """When a role has allowed_buckets configured, the helper returns it without
    hitting S3 — moved from tests/test_main_logic.py::test_list_buckets_allowed_buckets
    when the route refactor moved this logic into the helper."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={
            "roles": [
                {
                    "name": "RoleA",
                    "type": "default",
                    "allowed_buckets": ["bucket-1", "bucket-2"],
                }
            ],
        },
    )
    # Fail loudly if anything tries to reach S3 — short-circuit must skip it.
    mocker.patch.object(mod, "get_s3_client", side_effect=AssertionError("should not call"))

    result = mod.list_buckets_for_role("RoleA", _make_user(allowed_roles=["RoleA"]))
    assert result == ["bucket-1", "bucket-2"]


def test_list_buckets_for_role_invalid_allowed_type_raises_value_error(mocker):
    """When allowed_buckets is not a list, the helper raises ValueError —
    moved from tests/test_main_logic.py::test_list_buckets_invalid_allowed_type
    when the route refactor moved this validation into the helper."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={
            "roles": [{"name": "RoleA", "type": "default", "allowed_buckets": "not-a-list"}],
        },
    )
    with pytest.raises(ValueError, match="allowed_buckets"):
        mod.list_buckets_for_role("RoleA", _make_user(allowed_roles=["RoleA"]))


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


# --- iter_object_for_role ---


def test_iter_object_for_role_streams_body(moto_s3):
    """B1: helper yields the stored body in chunks of at most chunk_size bytes."""
    moto_s3.create_bucket(Bucket="stream-b")
    moto_s3.put_object(
        Bucket="stream-b",
        Key="x.bin",
        Body=b"hello world",
        ContentType="application/octet-stream",
    )

    from another_s3_manager.s3_client import iter_object_for_role

    metadata, body_iter = iter_object_for_role(
        None,
        "stream-b",
        "x.bin",
        {"username": "admin", "is_admin": True, "allowed_roles": []},
        chunk_size=4,
    )

    assert metadata["content_length"] == 11
    assert metadata["content_type"] == "application/octet-stream"
    chunks = list(body_iter)
    assert b"".join(chunks) == b"hello world"
    # Verify chunks respect chunk_size
    assert all(len(c) <= 4 for c in chunks)


def test_iter_object_for_role_missing_raises_filenotfound(moto_s3):
    """B1: missing object surfaces as FileNotFoundError (not a raw ClientError)."""
    moto_s3.create_bucket(Bucket="missing-b")

    from another_s3_manager.s3_client import iter_object_for_role

    with pytest.raises(FileNotFoundError):
        iter_object_for_role(
            None,
            "missing-b",
            "absent.txt",
            {"username": "admin", "is_admin": True, "allowed_roles": []},
        )


def test_iter_object_for_role_increments_metric(moto_s3):
    """B1: s3_bytes_total (direction="download") increments exactly once with
    ContentLength, BEFORE the body iterator is consumed."""
    moto_s3.create_bucket(Bucket="metric-b")
    moto_s3.put_object(Bucket="metric-b", Key="m.bin", Body=b"a" * 50)

    from another_s3_manager.metrics import s3_bytes_total, safe_role_label
    from another_s3_manager.s3_client import iter_object_for_role

    labels = {"role": safe_role_label("unknown"), "bucket": "metric-b", "direction": "download"}
    before = s3_bytes_total.labels(**labels)._value.get()

    metadata, body_iter = iter_object_for_role(
        None,
        "metric-b",
        "m.bin",
        {"username": "admin", "is_admin": True, "allowed_roles": []},
    )

    # Metric already incremented before iterator consumption
    mid = s3_bytes_total.labels(**labels)._value.get()
    assert mid - before == 50, "metric must increment at metadata-fetch time"

    # consume iterator to exhaust the stream
    list(body_iter)

    after = s3_bytes_total.labels(**labels)._value.get()
    assert after - before == 50, "metric must increment exactly once per download"
    assert metadata["content_length"] == 50


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


# --- upload_fileobj_for_role (streaming web-upload helper) ---


def test_upload_fileobj_for_role_streams_with_extra_args(mocker):
    """Calls boto3's managed-multipart upload_fileobj with the fileobj itself
    (never bytes) and carries ContentType + ContentDisposition via ExtraArgs."""
    import io

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    fileobj = io.BytesIO(b"stream me")
    mod.upload_fileobj_for_role(
        "RoleA",
        "bucket",
        "key.txt",
        fileobj,
        _make_user(allowed_roles=["RoleA"]),
        content_type="text/plain",
        content_disposition="inline",
        size=9,
    )

    fake_client.upload_fileobj.assert_called_once()
    args, kwargs = fake_client.upload_fileobj.call_args
    assert args[0] is fileobj
    assert args[1] == "bucket"
    assert args[2] == "key.txt"
    assert kwargs["ExtraArgs"] == {"ContentType": "text/plain", "ContentDisposition": "inline"}


def test_upload_fileobj_for_role_omits_disposition_when_unset(mocker):
    """No content_disposition → ExtraArgs carries only ContentType (matching
    put_object_for_role's conditional ContentDisposition)."""
    import io

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.upload_fileobj_for_role(
        "RoleA", "bucket", "k.bin", io.BytesIO(b"x"), _make_user(allowed_roles=["RoleA"]), size=1
    )

    _, kwargs = fake_client.upload_fileobj.call_args
    assert kwargs["ExtraArgs"] == {"ContentType": "application/octet-stream"}


def test_upload_fileobj_for_role_increments_metrics_once(mocker):
    """s3_bytes_total(direction=upload) += size and s3_objects_total(operation=upload) += 1,
    exactly once, inside the helper (the route must never also increment them)."""
    import io

    import another_s3_manager.s3_client as mod
    from another_s3_manager.metrics import s3_bytes_total, s3_objects_total

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    bytes_labels = {"role": "RoleA", "bucket": "metric-b", "direction": "upload"}
    objects_labels = {"role": "RoleA", "bucket": "metric-b", "operation": "upload"}
    bytes_before = s3_bytes_total.labels(**bytes_labels)._value.get()
    objects_before = s3_objects_total.labels(**objects_labels)._value.get()

    mod.upload_fileobj_for_role(
        "RoleA", "metric-b", "k.bin", io.BytesIO(b"x" * 42), _make_user(allowed_roles=["RoleA"]), size=42
    )

    assert s3_bytes_total.labels(**bytes_labels)._value.get() - bytes_before == 42
    assert s3_objects_total.labels(**objects_labels)._value.get() - objects_before == 1


def test_upload_fileobj_for_role_reseeks_on_retry(mocker):
    """execute_with_s3_retry re-invokes the callback once after a credential
    refresh (s3_client._execute_with_retry_inner). The helper must seek(0)
    INSIDE the callback — without it, the retry uploads 0 bytes because the
    first attempt already consumed the fileobj."""
    import io

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)
    mocker.patch.object(mod, "_is_expired_credentials_error", return_value=True)
    mocker.patch.object(mod, "invalidate_s3_client")
    mocker.patch.object(mod, "_clear_boto3_cached_credentials")

    payload = b"full payload"
    fileobj = io.BytesIO(payload)
    uploads = []

    def fake_upload_fileobj(fobj, bucket, key, ExtraArgs=None):
        uploads.append(fobj.read())
        if len(uploads) == 1:
            raise RuntimeError("Token expired")

    fake_client.upload_fileobj.side_effect = fake_upload_fileobj

    mod.upload_fileobj_for_role(
        "RoleA", "bucket", "k.bin", fileobj, _make_user(allowed_roles=["RoleA"]), size=len(payload)
    )

    assert uploads == [payload, payload], "second invocation must re-read the FULL payload from offset 0"


def test_upload_fileobj_for_role_permission_denied():
    """Same PermissionError contract as put_object_for_role."""
    import io

    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.upload_fileobj_for_role("RoleX", "bucket", "key", io.BytesIO(b""), _make_user(allowed_roles=["RoleA"]))


# --- delete_object_for_role ---


def test_delete_object_for_role_single_file(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    # Single-key existence + exact-match check is now ONE list_objects_v2
    # call (Prefix=path, MaxKeys=1), not a paginated walk -- its lone result
    # is the exact key (an exact match, not merely a prefix match), which
    # triggers the single delete_object path.
    fake_client.list_objects_v2.return_value = {"Contents": [{"Key": "file.txt"}]}
    fake_client.delete_object.return_value = {}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.delete_object_for_role("RoleA", "bucket", "file.txt", _make_user(allowed_roles=["RoleA"]))
    assert result["count"] == 1
    fake_client.list_objects_v2.assert_called_once_with(Bucket="bucket", Prefix="file.txt", MaxKeys=1)
    fake_client.delete_object.assert_called_once_with(Bucket="bucket", Key="file.txt")


def test_delete_object_for_role_not_found(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    # Listing finds nothing at all -> the key does not exist. Real S3's
    # DeleteObject is idempotent (it does NOT raise for a missing key), so
    # existence must be established from the listing itself, not by hoping
    # delete_object errors.
    fake_client.list_objects_v2.return_value = {"Contents": []}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.delete_object_for_role("RoleA", "bucket", "gone.txt", _make_user(allowed_roles=["RoleA"]))
    fake_client.delete_object.assert_not_called()


def test_delete_object_for_role_single_file_prefix_match_not_exact(mocker):
    """The single-key list_objects_v2(MaxKeys=1) call can return a key that
    merely STARTS WITH the requested path (its lexicographically-nearest
    match) when the exact key doesn't exist -- e.g. deleting "gone.txt" in a
    bucket that only has "gone.txt.bak". That must still raise
    FileNotFoundError and must NOT delete the sibling it happened to see."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.list_objects_v2.return_value = {"Contents": [{"Key": "gone.txt.bak"}]}
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    with pytest.raises(FileNotFoundError):
        mod.delete_object_for_role("RoleA", "bucket", "gone.txt", _make_user(allowed_roles=["RoleA"]))
    fake_client.delete_object.assert_not_called()


def test_delete_object_for_role_permission_denied():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.delete_object_for_role("RoleX", "bucket", "f", _make_user(allowed_roles=["RoleA"]))


# --- delete_object_for_role: data-loss regression (prefix-match deleted siblings) ---


def test_delete_object_for_role_does_not_delete_prefix_siblings(moto_s3):
    """Reproduction: deleting 'notes.txt' must not also delete 'notes.txt.bak'
    or 'notes.txt.old' just because they start with the same string."""
    import another_s3_manager.s3_client as mod

    moto_s3.create_bucket(Bucket="siblings-b")
    moto_s3.put_object(Bucket="siblings-b", Key="notes.txt", Body=b"a")
    moto_s3.put_object(Bucket="siblings-b", Key="notes.txt.bak", Body=b"b")
    moto_s3.put_object(Bucket="siblings-b", Key="notes.txt.old", Body=b"c")
    moto_s3.put_object(Bucket="siblings-b", Key="reports/2026", Body=b"d")
    moto_s3.put_object(Bucket="siblings-b", Key="reports/2026-q1.csv", Body=b"e")
    moto_s3.put_object(Bucket="siblings-b", Key="reports/2026/jan.csv", Body=b"f")

    result = mod.delete_object_for_role("Default", "siblings-b", "notes.txt", _ADMIN)

    assert result["count"] == 1
    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="siblings-b").get("Contents", [])}
    assert remaining == {
        "notes.txt.bak",
        "notes.txt.old",
        "reports/2026",
        "reports/2026-q1.csv",
        "reports/2026/jan.csv",
    }


def test_delete_object_for_role_exact_key_that_looks_like_a_prefix(moto_s3):
    """'reports/2026' (no trailing slash) is a real object AND a prefix of two
    other keys. Deleting it must remove only the exact key."""
    import another_s3_manager.s3_client as mod

    moto_s3.create_bucket(Bucket="reports-b")
    moto_s3.put_object(Bucket="reports-b", Key="reports/2026", Body=b"d")
    moto_s3.put_object(Bucket="reports-b", Key="reports/2026-q1.csv", Body=b"e")
    moto_s3.put_object(Bucket="reports-b", Key="reports/2026/jan.csv", Body=b"f")

    result = mod.delete_object_for_role("Default", "reports-b", "reports/2026", _ADMIN)

    assert result["count"] == 1
    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="reports-b").get("Contents", [])}
    assert remaining == {"reports/2026-q1.csv", "reports/2026/jan.csv"}


def test_delete_object_for_role_folder_delete_still_recursive(moto_s3):
    """A trailing '/' still means 'recursive folder delete', and a
    lexically-similar sibling outside the folder must survive."""
    import another_s3_manager.s3_client as mod

    moto_s3.create_bucket(Bucket="folder-b")
    moto_s3.put_object(Bucket="folder-b", Key="reports/2026/jan.csv", Body=b"f")
    moto_s3.put_object(Bucket="folder-b", Key="reports/2026/feb.csv", Body=b"g")
    moto_s3.put_object(Bucket="folder-b", Key="reports/2026-q1.csv", Body=b"e")

    result = mod.delete_object_for_role("Default", "folder-b", "reports/2026/", _ADMIN)

    assert result["count"] == 2
    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="folder-b").get("Contents", [])}
    assert remaining == {"reports/2026-q1.csv"}


def test_delete_object_for_role_missing_key_raises_via_moto(moto_s3):
    """A genuinely non-existent single key raises FileNotFoundError, even
    though real S3's DeleteObject would otherwise succeed silently."""
    import another_s3_manager.s3_client as mod

    moto_s3.create_bucket(Bucket="missing-del-b")
    moto_s3.put_object(Bucket="missing-del-b", Key="unrelated.txt", Body=b"z")

    with pytest.raises(FileNotFoundError):
        mod.delete_object_for_role("Default", "missing-del-b", "gone.txt", _ADMIN)

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="missing-del-b").get("Contents", [])}
    assert remaining == {"unrelated.txt"}


def test_move_via_copy_then_delete_does_not_touch_siblings(moto_s3):
    """copy_object_for_role + delete_object_for_role (the MCP move path) must
    delete only the exact source key, not siblings sharing its prefix."""
    import another_s3_manager.s3_client as mod

    moto_s3.create_bucket(Bucket="move-b")
    moto_s3.put_object(Bucket="move-b", Key="notes.txt", Body=b"hello")
    moto_s3.put_object(Bucket="move-b", Key="notes.txt.bak", Body=b"backup")

    mod.copy_object_for_role("Default", "move-b", "notes.txt", "move-b", "archive/notes.txt", _ADMIN)
    mod.delete_object_for_role("Default", "move-b", "notes.txt", _ADMIN)

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="move-b").get("Contents", [])}
    assert remaining == {"notes.txt.bak", "archive/notes.txt"}


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


def test_list_objects_recursive_permission_denied_role():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.list_objects_recursive_for_role("RoleX", "bucket", "", _make_user(allowed_roles=["RoleA"]))


def test_list_objects_recursive_honours_max_page_size_parameter(mocker):
    """The safety ceiling comes from the caller, not a hardcoded 10_000:
    max_keys above max_page_size is clamped down to it."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    fake_client.list_objects_v2.return_value = {
        "Contents": [{"Key": f"f{i}.txt", "Size": i, "LastModified": dt} for i in range(8)],
        "IsTruncated": False,
    }
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_recursive_for_role(
        "RoleA", "bucket", "", _make_user(allowed_roles=["RoleA"]), max_keys=99, max_page_size=3
    )
    assert result["key_count"] == 3
    assert result["is_truncated"] is True


def test_list_objects_recursive_max_page_size_default_still_10000(mocker):
    """Without max_page_size the previous behaviour is preserved: a request of
    1500 keys (> the old per-page 1000, < the 10_000 ceiling) is honoured."""
    import datetime

    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    dt = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    fake_client = mocker.MagicMock()
    page1 = {
        "Contents": [{"Key": f"a{i:04d}.txt", "Size": 1, "LastModified": dt} for i in range(1000)],
        "IsTruncated": True,
        "NextContinuationToken": "TOKEN-B",
    }
    page2 = {
        "Contents": [{"Key": f"b{i:04d}.txt", "Size": 1, "LastModified": dt} for i in range(1000)],
        "IsTruncated": False,
    }
    fake_client.list_objects_v2.side_effect = [page1, page2]
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    result = mod.list_objects_recursive_for_role(
        "RoleA", "bucket", "", _make_user(allowed_roles=["RoleA"]), max_keys=1500
    )
    assert result["key_count"] == 1500
    assert result["is_truncated"] is True


# --- generate_presigned_url_for_role ---


def test_generate_presigned_url_for_role_returns_url(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://bucket.s3.amazonaws.com/file.txt?X-Amz-Signature=abc"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    # `.txt` is in the text-extension override list, so the call also gets a
    # `ResponseContentType: text/plain; charset=utf-8` param. Use a path
    # without a known text extension to verify the URL/params plumbing in
    # isolation; the charset override has its own dedicated tests below.
    url = mod.generate_presigned_url_for_role("RoleA", "bucket", "blob.bin", _make_user(allowed_roles=["RoleA"]))
    assert url.startswith("https://")
    assert "X-Amz-Signature" in url
    fake_client.generate_presigned_url.assert_called_once_with(
        "get_object",
        Params={"Bucket": "bucket", "Key": "blob.bin"},
        ExpiresIn=3600,
    )


def test_generate_presigned_url_for_role_custom_ttl(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://example/x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.generate_presigned_url_for_role(
        "RoleA", "bucket", "file.txt", _make_user(allowed_roles=["RoleA"]), expires_in=600
    )
    _, kwargs = fake_client.generate_presigned_url.call_args
    assert kwargs["ExpiresIn"] == 600


def test_generate_presigned_url_for_role_permission_denied_role():
    import another_s3_manager.s3_client as mod

    with pytest.raises(PermissionError):
        mod.generate_presigned_url_for_role("RoleX", "bucket", "f", _make_user(allowed_roles=["RoleA"]))


def test_generate_presigned_url_for_role_permission_denied_bucket(mocker):
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default", "allowed_buckets": ["allowed"]}]},
    )

    with pytest.raises(PermissionError):
        mod.generate_presigned_url_for_role("RoleA", "denied", "f", _make_user(allowed_roles=["RoleA"]))


def test_generate_presigned_url_for_role_overrides_content_type_for_markdown(mocker):
    """Markdown files get a UTF-8 charset override so Cyrillic renders inline."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.generate_presigned_url_for_role("RoleA", "bucket", "notes/2026-03-22.md", _make_user(allowed_roles=["RoleA"]))
    _, kwargs = fake_client.generate_presigned_url.call_args
    assert kwargs["Params"]["ResponseContentType"] == "text/markdown; charset=utf-8"


def test_generate_presigned_url_for_role_overrides_content_type_for_csv(mocker):
    """CSV gets text/csv; charset=utf-8 — same Cyrillic mojibake fix."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.generate_presigned_url_for_role("RoleA", "bucket", "data.csv", _make_user(allowed_roles=["RoleA"]))
    _, kwargs = fake_client.generate_presigned_url.call_args
    assert kwargs["Params"]["ResponseContentType"] == "text/csv; charset=utf-8"


def test_generate_presigned_url_for_role_no_override_for_binary(mocker):
    """Binary files (.png, .pdf, .zip) keep S3's stored Content-Type — no charset added."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    for binary_path in ("photo.png", "doc.pdf", "archive.zip", "video.mp4"):
        fake_client.reset_mock()
        mod.generate_presigned_url_for_role("RoleA", "bucket", binary_path, _make_user(allowed_roles=["RoleA"]))
        _, kwargs = fake_client.generate_presigned_url.call_args
        assert "ResponseContentType" not in kwargs["Params"], (
            f"binary file {binary_path!r} should not get a content-type override"
        )


def test_generate_presigned_url_for_role_charset_extension_case_insensitive(mocker):
    """`.MD` (uppercase) gets the same override as `.md` — extensions are case-insensitive."""
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    mod.generate_presigned_url_for_role("RoleA", "bucket", "README.MD", _make_user(allowed_roles=["RoleA"]))
    _, kwargs = fake_client.generate_presigned_url.call_args
    assert kwargs["Params"]["ResponseContentType"] == "text/markdown; charset=utf-8"


def test_generate_presigned_url_for_role_no_override_for_html_or_svg(mocker):
    """SECURITY: .html / .htm / .svg / .js / .css must NOT get a renderable
    Content-Type override. Otherwise an authenticated user could upload a
    malicious HTML/SVG file and share its presigned URL as a phishing page
    on the trusted *.s3.amazonaws.com origin.
    """
    import another_s3_manager.s3_client as mod

    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RoleA", "type": "default"}]},
    )
    fake_client = mocker.MagicMock()
    fake_client.generate_presigned_url.return_value = "https://x"
    mocker.patch.object(mod, "get_s3_client", return_value=fake_client)

    for risky_path in ("phish.html", "evil.htm", "icon.svg", "tracker.js", "style.css"):
        fake_client.reset_mock()
        mod.generate_presigned_url_for_role("RoleA", "bucket", risky_path, _make_user(allowed_roles=["RoleA"]))
        _, kwargs = fake_client.generate_presigned_url.call_args
        assert "ResponseContentType" not in kwargs["Params"], (
            f"renderable file {risky_path!r} must NOT get a content-type override "
            "— would enable phishing on the S3 origin"
        )


def test_role_uses_temporary_credentials(mocker):
    from another_s3_manager import s3_client

    mocker.patch.object(
        s3_client,
        "load_config",
        return_value={
            "roles": [
                {"name": "sts-role", "type": "assume_role", "role_arn": "arn:..."},
                {"name": "profile-role", "type": "profile", "profile_name": "p"},
                {"name": "key-role", "type": "credentials", "access_key_id": "AKIA..."},
                {"name": "compat-role", "type": "s3_compatible"},
            ]
        },
    )
    assert s3_client.role_uses_temporary_credentials("sts-role") is True
    assert s3_client.role_uses_temporary_credentials("profile-role") is True
    assert s3_client.role_uses_temporary_credentials("key-role") is False
    assert s3_client.role_uses_temporary_credentials("compat-role") is False
    assert s3_client.role_uses_temporary_credentials("nope") is False


# ---------------------------------------------------------------------------
# copy_object_for_role / get_object_metadata_for_role (v1.0.2 MCP tools)
# ---------------------------------------------------------------------------

_ADMIN = {"username": "admin", "is_admin": True, "allowed_roles": []}


def test_copy_object_for_role_copies_body(moto_s3):
    from another_s3_manager.s3_client import copy_object_for_role

    moto_s3.create_bucket(Bucket="copybkt")
    moto_s3.put_object(Bucket="copybkt", Key="src.txt", Body=b"hello")

    copy_object_for_role(None, "copybkt", "src.txt", "copybkt", "dst.txt", _ADMIN)

    assert moto_s3.get_object(Bucket="copybkt", Key="dst.txt")["Body"].read() == b"hello"
    # Copy (not move) — source is still there.
    assert moto_s3.get_object(Bucket="copybkt", Key="src.txt")["Body"].read() == b"hello"


def test_copy_object_for_role_missing_source_raises(moto_s3):
    from another_s3_manager.s3_client import copy_object_for_role

    moto_s3.create_bucket(Bucket="cp2")
    with pytest.raises(FileNotFoundError):
        copy_object_for_role(None, "cp2", "nope.txt", "cp2", "x.txt", _ADMIN)


def test_get_object_metadata_for_role_returns_fields(moto_s3):
    from another_s3_manager.s3_client import get_object_metadata_for_role

    moto_s3.create_bucket(Bucket="metabkt")
    moto_s3.put_object(Bucket="metabkt", Key="a.txt", Body=b"12345", ContentType="text/plain")

    meta = get_object_metadata_for_role(None, "metabkt", "a.txt", _ADMIN)
    assert meta["size"] == 5
    assert meta["content_type"] == "text/plain"
    assert meta["last_modified"] is not None
    assert meta["etag"]


def test_get_object_metadata_for_role_missing_raises(moto_s3):
    from another_s3_manager.s3_client import get_object_metadata_for_role

    moto_s3.create_bucket(Bucket="md2")
    with pytest.raises(FileNotFoundError):
        get_object_metadata_for_role(None, "md2", "nope.txt", _ADMIN)


# ---------------------------------------------------------------------------
# Concurrency: _s3_clients_cache under real multi-threaded access (R001
# moved every boto3 call onto a worker-thread pool, making this a genuine
# hazard instead of a theoretical one).
# ---------------------------------------------------------------------------


def test_get_s3_client_concurrent_threads_same_role_no_corruption(mocker):
    """N real threads race get_s3_client() for the same role at the same instant.

    Uses a threading.Barrier so every thread hits the cache-miss check at
    genuinely the same time, plus an artificial delay inside the client
    build to widen the race window well past the size of a dict lookup —
    without both, two threads could easily interleave "by luck" without
    ever exercising the lock. All threads must succeed, return the exact
    same client object, and the client must have been built exactly ONCE:
    with the double-checked lock, every thread but the first blocks on
    `_s3_clients_lock` and then finds the cache already populated. Without
    the lock, the injected delay makes it near-certain multiple threads
    pass the `cache_key in _s3_clients_cache` check before any of them
    finishes building+caching, so this discriminates for real (verified by
    temporarily reverting the lock and observing build_count > 1).
    """
    module = reload_s3_client()

    fake_client = mocker.MagicMock()
    fake_client.list_buckets.return_value = {"Buckets": []}

    build_count = {"n": 0}
    build_count_lock = threading.Lock()

    def slow_client(*_args, **_kwargs):
        with build_count_lock:
            build_count["n"] += 1
        # Widen the race window far past a dict lookup so concurrent misses
        # genuinely overlap instead of serializing incidentally.
        time.sleep(0.05)
        return fake_client

    session_mock = mocker.MagicMock()
    session_mock.client.side_effect = slow_client
    mocker.patch("boto3.Session", return_value=session_mock)

    n_threads = 20
    barrier = threading.Barrier(n_threads)
    results: list = [None] * n_threads
    errors: list = []

    def worker(idx: int) -> None:
        try:
            barrier.wait(timeout=5)
            results[idx] = module.get_s3_client()
        except Exception as exc:  # noqa: BLE001 - captured for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"get_s3_client raised under concurrency: {errors}"
    assert all(r is fake_client for r in results), "not every thread got the same cached client"
    assert build_count["n"] == 1, (
        f"expected exactly 1 client build across {n_threads} concurrent misses, got {build_count['n']} "
        "— the check-build-store sequence is not properly serialized"
    )


def test_get_s3_client_survives_concurrent_invalidate_no_keyerror(mocker):
    """A cached client read must never KeyError against a concurrent,
    unsynchronized `invalidate_s3_client`.

    Two layers, both real multi-threading:

    1. A background "invalidator" thread genuinely hammers
       `invalidate_s3_client()` for the role in a tight loop, concurrently
       with N "getter" threads hammering `get_s3_client()` for the same
       role — real organic concurrent traffic, released together via a
       `threading.Barrier`. This alone was tried first (plus dropping
       `sys.setswitchinterval` to widen GIL handoff frequency, up to 24
       getter + 3 invalidator threads x 1000 iterations): it produced ZERO
       crashes on the buggy pre-fix pattern in ~8s of wall time. The window
       between the `in` check and the `[]` subscript is a couple of
       bytecodes wide, and pure GIL-scheduling luck essentially never lands
       there — the same empirical finding the reviewer made for the sibling
       config-cache theatre test.
    2. So the cache dict is swapped for `_RaceForcingCache`, a `dict`
       subclass whose overridden `__contains__` — invoked by `key in
       cache`, which is exactly the first half of the old `if key in
       cache: return cache[key]` pattern — spins up a genuinely separate
       thread that calls `invalidate_s3_client` (a real pop on this same
       dict) and joins it BEFORE returning, forcing the precise
       interleaving the old pattern is vulnerable to on (effectively)
       every hit. Critically, `dict.get()` — what the fixed code uses — is
       a C-level method that bypasses a subclass's overridden
       `__contains__`/`__getitem__` entirely (verified directly: calling
       `.get()`/`.pop()` on an instrumented subclass does not invoke the
       overridden dunder methods), so this hook is fully inert against the
       fixed code — it neither triggers nor perturbs it.

    On the pre-fix `if cache_key in _s3_clients_cache: return
    _s3_clients_cache[cache_key]` pattern (both the lock-free fast path and
    the in-lock double-check use it), the forced pop between the `in`
    check and the subscript raises `KeyError`, which escapes
    `get_s3_client` uncaught — a getter thread crashes (in production: an
    uncaught 500). On the fixed code (`dict.get()`, a single atomic read),
    no `KeyError` is possible. Verified by reverting to the `in`/`[]`
    pattern and re-running this exact test (see fix-round-1 in the
    concurrent-caches report for the pasted failure).
    """
    module = reload_s3_client()

    fake_client = mocker.MagicMock()
    fake_client.list_buckets.return_value = {"Buckets": []}
    session_mock = mocker.MagicMock()
    session_mock.client.return_value = fake_client
    mocker.patch("boto3.Session", return_value=session_mock)
    mocker.patch(
        "another_s3_manager.config.load_config",
        return_value={"roles": [{"name": "RaceRole", "type": "default"}]},
    )

    cache_key = "RaceRole"

    class _RaceForcingCache(dict):
        """See the module-level test docstring above: forces the exact
        interleaving the old `in`/`[]` cache-read pattern is vulnerable to,
        via a genuinely separate thread — and is fully inert against the
        fixed `dict.get()` pattern.
        """

        def __contains__(self, key: object) -> bool:
            present = super().__contains__(key)
            if present and key == cache_key:
                racer = threading.Thread(target=module.invalidate_s3_client, args=(cache_key,))
                racer.start()
                racer.join(timeout=5)
            return present

    module._s3_clients_cache = _RaceForcingCache(module._s3_clients_cache)

    stop = threading.Event()
    n_getters = 8
    iterations = 50
    barrier = threading.Barrier(n_getters + 1)
    errors: list = []

    def getter() -> None:
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            return
        for _ in range(iterations):
            try:
                module.get_s3_client(cache_key)
            except Exception as exc:  # noqa: BLE001 - captured for the assertion below
                errors.append(exc)
                return

    def invalidator() -> None:
        # Real, independent concurrent invalidation traffic on top of the
        # deterministic hook above — exercises the fixed code's actual
        # locking discipline, not just the forced-race path.
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            return
        while not stop.is_set():
            module.invalidate_s3_client(cache_key)

    getters = [threading.Thread(target=getter) for _ in range(n_getters)]
    inv_thread = threading.Thread(target=invalidator)

    try:
        inv_thread.start()
        for t in getters:
            t.start()
        for t in getters:
            t.join(timeout=30)
    finally:
        stop.set()
        inv_thread.join(timeout=5)

    assert not errors, f"get_s3_client raised under concurrent invalidate: {errors!r}"


def test_create_s3_client_default_builds_explicit_session_not_default(mocker):
    """Client construction must NOT go through boto3's module-level default-session
    helper (`boto3.client(...)`) — boto3 documents that helper as sharing a
    process-wide, non-thread-safe session. It must build an explicit,
    unshared `boto3.Session()` per client instead (see _new_boto3_session).

    This discriminates directly against the pre-fix code, which called
    `boto3.client("s3", **client_kwargs)` here — `default_session_client`
    would have been called and this assertion would fail.
    """
    module = reload_s3_client()
    default_session_client = mocker.patch("boto3.client")
    session_mock = mocker.MagicMock()
    mocker.patch("boto3.Session", return_value=session_mock)

    module._create_s3_client_from_role({"type": "default"})

    default_session_client.assert_not_called()
    session_mock.client.assert_called_once()
