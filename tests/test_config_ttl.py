"""Unit tests for resolve_presigned_ttls (pure, config→env→default + clamp)."""

import importlib

import pytest

from another_s3_manager.config import resolve_presigned_ttls


def test_defaults_when_empty_config_and_no_env(monkeypatch):
    monkeypatch.delenv("PRESIGNED_URL_DEFAULT_TTL", raising=False)
    monkeypatch.delenv("PRESIGNED_URL_MAX_TTL", raising=False)
    default_ttl, max_ttl = resolve_presigned_ttls({})
    assert default_ttl == 3600
    assert max_ttl == 604800


def test_config_values_take_precedence(monkeypatch):
    monkeypatch.delenv("PRESIGNED_URL_DEFAULT_TTL", raising=False)
    monkeypatch.delenv("PRESIGNED_URL_MAX_TTL", raising=False)
    default_ttl, max_ttl = resolve_presigned_ttls(
        {"presigned_url_default_ttl": 900, "presigned_url_max_ttl": 86400}
    )
    assert default_ttl == 900
    assert max_ttl == 86400


def test_env_used_when_config_missing(monkeypatch):
    monkeypatch.setenv("PRESIGNED_URL_DEFAULT_TTL", "1800")
    monkeypatch.setenv("PRESIGNED_URL_MAX_TTL", "172800")
    default_ttl, max_ttl = resolve_presigned_ttls({})
    assert default_ttl == 1800
    assert max_ttl == 172800


def test_max_clamped_to_hard_ceiling(monkeypatch):
    monkeypatch.delenv("PRESIGNED_URL_DEFAULT_TTL", raising=False)
    monkeypatch.delenv("PRESIGNED_URL_MAX_TTL", raising=False)
    _, max_ttl = resolve_presigned_ttls({"presigned_url_max_ttl": 9_999_999})
    assert max_ttl == 604800


def test_default_clamped_to_max(monkeypatch):
    monkeypatch.delenv("PRESIGNED_URL_DEFAULT_TTL", raising=False)
    monkeypatch.delenv("PRESIGNED_URL_MAX_TTL", raising=False)
    default_ttl, max_ttl = resolve_presigned_ttls(
        {"presigned_url_default_ttl": 86400, "presigned_url_max_ttl": 3600}
    )
    assert max_ttl == 3600
    assert default_ttl == 3600


def test_garbage_values_fall_back_to_defaults(monkeypatch):
    monkeypatch.delenv("PRESIGNED_URL_DEFAULT_TTL", raising=False)
    monkeypatch.delenv("PRESIGNED_URL_MAX_TTL", raising=False)
    default_ttl, max_ttl = resolve_presigned_ttls(
        {"presigned_url_default_ttl": "abc", "presigned_url_max_ttl": None}
    )
    assert default_ttl == 3600
    assert max_ttl == 604800
