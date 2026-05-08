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
    assert "allowed_buckets" in msg or "ListAllMyBuckets" in msg, "Error message must point the admin at the fix"
    assert "ScopedNoBuckets" not in s3_client_module._s3_clients_cache
