"""Tests for the probe-on-cache behaviour of get_s3_client.

The probe ensures that broken S3 clients (invalid region, unreachable
endpoint, bad credentials) surface immediately instead of getting cached
and silently failing every list/get operation downstream.
"""

from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError


def _client_error(code: str, message: str = "boom", http_status: int = 400) -> ClientError:
    return ClientError(
        error_response={
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": http_status},
        },
        operation_name="ListBuckets",
    )


def test_probe_failure_raises_typed_error_and_does_not_cache(monkeypatch, tmp_path):
    """An InvalidRegion at probe time raises S3ConfigError; client is not cached."""
    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3ConfigError

    # Write a config with an invalid R2 region.
    cfg = {
        "roles": [
            {
                "name": "R2-bad",
                "type": "s3_compatible",
                "access_key_id": "x",
                "secret_access_key": "y",
                "endpoint_url": "https://acct.r2.cloudflarestorage.com",
                "region": "eu-central-1",  # invalid for R2 — wnam/enam/weur/eeur/apac/oc/auto
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    # Force config reload — CONFIG_FILE is read at import time, so patch it.
    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    # Mock _create_s3_client_from_role: returns a client whose list_buckets()
    # raises InvalidRegion (mirrors the R2 failure mode — boto creates the
    # client fine, but the first API call hits the bad region).
    class _FakeClient:
        def list_buckets(self):
            raise _client_error("InvalidRegion", "Invalid region eu-central-1 for R2", http_status=400)

    def _fake_create(role):
        return _FakeClient()

    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", _fake_create)

    # Clear cache to ensure get_s3_client goes through creation+probe.
    s3_client_module._s3_clients_cache.clear()

    with pytest.raises(S3ConfigError) as exc_info:
        s3_client_module.get_s3_client("R2-bad")

    assert exc_info.value.code == "InvalidRegion"
    assert "eu-central-1" in str(exc_info.value)
    # Critical assertion: the broken client must NOT be cached.
    assert "R2-bad" not in s3_client_module._s3_clients_cache


def test_probe_success_caches_client(monkeypatch, tmp_path):
    """A successful probe caches the client for reuse."""
    from another_s3_manager import s3_client as s3_client_module

    cfg = {
        "roles": [
            {
                "name": "Healthy",
                "type": "default",
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    probe_calls: list[None] = []

    class _FakeClient:
        def list_buckets(self):
            probe_calls.append(None)
            return {"Buckets": []}

    fake_client = _FakeClient()
    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: fake_client)

    s3_client_module._s3_clients_cache.clear()

    client = s3_client_module.get_s3_client("Healthy")
    assert client is fake_client
    assert s3_client_module._s3_clients_cache.get("Healthy") is fake_client
    assert len(probe_calls) == 1, "probe must run once on cache miss"

    # Second call must hit the cache, not re-probe.
    client2 = s3_client_module.get_s3_client("Healthy")
    assert client2 is fake_client
    assert len(probe_calls) == 1, "cached client must NOT be re-probed"


def test_probe_access_denied_falls_back_to_head_bucket(monkeypatch, tmp_path):
    """If list_buckets returns 403 (R2/MinIO scoped tokens) but allowed_buckets
    is configured, the probe falls back to head_bucket(allowed_buckets[0]).
    Permission-scoped roles are valid even though they can't list all buckets."""
    from another_s3_manager import s3_client as s3_client_module

    cfg = {
        "roles": [
            {
                "name": "ScopedR2",
                "type": "s3_compatible",
                "access_key_id": "x",
                "secret_access_key": "y",
                "endpoint_url": "https://acct.r2.cloudflarestorage.com",
                "region": "auto",
                "allowed_buckets": ["my-bucket"],
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    head_calls: list[str] = []

    class _FakeClient:
        def list_buckets(self):
            raise _client_error("AccessDenied", "scoped token", http_status=403)

        def head_bucket(self, Bucket):
            head_calls.append(Bucket)
            return {}

    fake_client = _FakeClient()
    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: fake_client)
    s3_client_module._s3_clients_cache.clear()

    client = s3_client_module.get_s3_client("ScopedR2")
    assert client is fake_client
    assert head_calls == ["my-bucket"]
    assert "ScopedR2" in s3_client_module._s3_clients_cache


def test_probe_network_error_raises_s3networkerror(monkeypatch, tmp_path):
    """Endpoint unreachable at probe time raises S3NetworkError, no cache."""
    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3NetworkError

    cfg = {"roles": [{"name": "BadEndpoint", "type": "default"}]}
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    class _FakeClient:
        def list_buckets(self):
            raise EndpointConnectionError(endpoint_url="https://bogus.invalid")

    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: _FakeClient())
    s3_client_module._s3_clients_cache.clear()

    with pytest.raises(S3NetworkError):
        s3_client_module.get_s3_client("BadEndpoint")

    assert "BadEndpoint" not in s3_client_module._s3_clients_cache


def test_probe_iterates_allowed_buckets_until_one_succeeds(monkeypatch, tmp_path):
    """Probe must NOT brick the role when allowed_buckets[0] is gone — it must
    iterate ALL allowed_buckets and cache as long as ONE responds. Otherwise
    a single deleted/renamed bucket out-of-band makes the role unusable."""
    from another_s3_manager import s3_client as s3_client_module

    cfg = {
        "roles": [
            {
                "name": "MultiBucket",
                "type": "s3_compatible",
                "access_key_id": "x",
                "secret_access_key": "y",
                "endpoint_url": "https://acct.r2.cloudflarestorage.com",
                "region": "auto",
                # First bucket is gone (deleted out-of-band); second still works.
                "allowed_buckets": ["legacy-archive", "active-data"],
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    head_calls: list[str] = []

    class _FakeClient:
        def list_buckets(self):
            raise _client_error("AccessDenied", "scoped token", http_status=403)

        def head_bucket(self, Bucket):
            head_calls.append(Bucket)
            if Bucket == "legacy-archive":
                # Simulate out-of-band deletion.
                raise _client_error("NoSuchBucket", "gone", http_status=404)
            return {}

    fake_client = _FakeClient()
    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: fake_client)
    s3_client_module._s3_clients_cache.clear()

    client = s3_client_module.get_s3_client("MultiBucket")
    assert client is fake_client
    # Both buckets tried in order; second succeeded → loop broke → cached.
    assert head_calls == ["legacy-archive", "active-data"]
    assert "MultiBucket" in s3_client_module._s3_clients_cache


def test_probe_raises_when_all_allowed_buckets_fail(monkeypatch, tmp_path):
    """If list_buckets is denied AND every allowed_bucket fails head_bucket,
    the probe must raise — caching a totally unusable client is worse than
    failing loud."""
    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3OperationError

    cfg = {
        "roles": [
            {
                "name": "AllGone",
                "type": "s3_compatible",
                "access_key_id": "x",
                "secret_access_key": "y",
                "endpoint_url": "https://acct.r2.cloudflarestorage.com",
                "region": "auto",
                "allowed_buckets": ["a", "b"],
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    class _FakeClient:
        def list_buckets(self):
            raise _client_error("AccessDenied", "scoped token", http_status=403)

        def head_bucket(self, Bucket):
            raise _client_error("NoSuchBucket", "gone", http_status=404)

    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: _FakeClient())
    s3_client_module._s3_clients_cache.clear()

    with pytest.raises(S3OperationError) as exc_info:
        s3_client_module.get_s3_client("AllGone")

    # Message should list which buckets were tried so admins can debug.
    msg = str(exc_info.value)
    assert "a" in msg and "b" in msg
    assert "AllGone" not in s3_client_module._s3_clients_cache


def test_probe_access_denied_without_allowed_buckets_raises_actionable_error(monkeypatch, tmp_path):
    """If list_buckets returns 403 AND allowed_buckets is not configured,
    the probe surfaces an S3AccessDeniedError with an actionable message
    pointing the admin at the fix (configure allowed_buckets or grant
    ListAllMyBuckets)."""
    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3AccessDeniedError

    cfg = {
        "roles": [
            {
                "name": "ScopedNoBuckets",
                "type": "s3_compatible",
                "access_key_id": "x",
                "secret_access_key": "y",
                "endpoint_url": "https://acct.r2.cloudflarestorage.com",
                "region": "auto",
                # No `allowed_buckets` key — this is the path under test.
            }
        ]
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(cfg_path))

    from another_s3_manager import config as config_module

    monkeypatch.setattr(config_module, "CONFIG_FILE", cfg_path)
    config_module._config_cache = {}
    config_module._config_mtime = 0

    class _FakeClient:
        def list_buckets(self):
            raise _client_error("AccessDenied", "no perms", http_status=403)

    monkeypatch.setattr(s3_client_module, "_create_s3_client_from_role", lambda role: _FakeClient())
    s3_client_module._s3_clients_cache.clear()

    with pytest.raises(S3AccessDeniedError) as exc_info:
        s3_client_module.get_s3_client("ScopedNoBuckets")

    msg = str(exc_info.value)
    assert "allowed_buckets" in msg.lower() or "listallmybuckets" in msg.lower(), (
        "Error message must point the admin at the fix"
    )
    # Preserve the friendly copy from PR #14 so frontend keeps showing the
    # "scoped tokens (R2, MinIO, ...)" guidance — probe must NOT regress to
    # bare "Access Denied".
    assert "scoped token" in msg.lower(), "Friendly PR #14 copy must be preserved by probe"
    assert "ScopedNoBuckets" not in s3_client_module._s3_clients_cache


def test_assume_role_access_denied_includes_iam_trust_policy_hint(monkeypatch):
    """STS AccessDenied on assume_role must include the IRSA / pod-identity
    debugging hint. Boto's raw message names the principal but doesn't tell
    admins to check the trust policy — that hint is the actionable fix."""
    from botocore.exceptions import ClientError as BotoClientError

    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3AccessDeniedError

    role = {
        "name": "Bad",
        "type": "assume_role",
        "role_arn": "arn:aws:iam::000000000000:role/target",
    }

    class _FakeSTS:
        def assume_role(self, **kwargs):
            raise BotoClientError(
                error_response={
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "User: arn:aws:iam::000:user/x is not authorized to perform: sts:AssumeRole",
                    },
                    "ResponseMetadata": {"HTTPStatusCode": 403},
                },
                operation_name="AssumeRole",
            )

    def _fake_boto_client(service, **kwargs):
        if service == "sts":
            return _FakeSTS()
        raise NotImplementedError(f"Unexpected boto3.client('{service}')")

    monkeypatch.setattr(s3_client_module.boto3, "client", _fake_boto_client)

    with pytest.raises(S3AccessDeniedError) as exc_info:
        s3_client_module._create_s3_client_from_role(role)

    msg = str(exc_info.value)
    # The original boto principal/action context is preserved.
    assert "sts:AssumeRole" in msg
    # The actionable IAM trust-policy hint is added back (was lost in the
    # initial typed-exception conversion in this PR).
    assert "trust policy" in msg.lower() or "permission to assume" in msg.lower(), (
        "AssumeRole AccessDenied must include the IAM trust-policy / pod-identity hint"
    )


def test_assume_role_invalid_arn_raises_s3configerror(monkeypatch):
    """Bad assume_role config (InvalidArgument from STS) raises S3ConfigError
    instead of bare ValueError so the HTTP boundary returns 400 + boto code."""
    from botocore.exceptions import ClientError as BotoClientError

    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import S3ConfigError

    role = {
        "name": "Bad",
        "type": "assume_role",
        "role_arn": "arn:aws:iam::000000000000:role/does-not-exist",
    }

    class _FakeSTS:
        def assume_role(self, **kwargs):
            raise BotoClientError(
                error_response={
                    "Error": {"Code": "InvalidArgument", "Message": "bad arn"},
                    "ResponseMetadata": {"HTTPStatusCode": 400},
                },
                operation_name="AssumeRole",
            )

    def _fake_boto_client(service, **kwargs):
        if service == "sts":
            return _FakeSTS()
        raise NotImplementedError(f"Unexpected boto3.client('{service}')")

    monkeypatch.setattr(s3_client_module.boto3, "client", _fake_boto_client)

    with pytest.raises(S3ConfigError) as exc_info:
        s3_client_module._create_s3_client_from_role(role)

    # The classifier maps InvalidArgument → S3ConfigError. The role ARN is
    # preserved in the message so admins can identify which role is broken.
    assert "does-not-exist" in str(exc_info.value) or exc_info.value.code == "InvalidArgument"


def test_assume_role_expired_token_raises_credentials_expired(monkeypatch):
    """ExpiredToken from STS raises CredentialsExpiredError (HTTP 401)
    instead of bare ValueError (was HTTP 400)."""
    from botocore.exceptions import ClientError as BotoClientError

    from another_s3_manager import s3_client as s3_client_module
    from another_s3_manager.errors import CredentialsExpiredError

    role = {
        "name": "Bad",
        "type": "assume_role",
        "role_arn": "arn:aws:iam::000000000000:role/r",
    }

    class _FakeSTS:
        def assume_role(self, **kwargs):
            raise BotoClientError(
                error_response={
                    "Error": {"Code": "ExpiredToken", "Message": "token expired"},
                    "ResponseMetadata": {"HTTPStatusCode": 403},
                },
                operation_name="AssumeRole",
            )

    def _fake_boto_client(service, **kwargs):
        if service == "sts":
            return _FakeSTS()
        raise NotImplementedError(f"Unexpected boto3.client('{service}')")

    monkeypatch.setattr(s3_client_module.boto3, "client", _fake_boto_client)

    with pytest.raises(CredentialsExpiredError):
        s3_client_module._create_s3_client_from_role(role)
