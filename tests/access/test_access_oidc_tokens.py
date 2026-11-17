import json
import time

import pytest
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from tests.oidc.fake_op import FakeOP

from another_s3_manager import access
from another_s3_manager.access.oidc.client import InvalidIdToken, validate_id_token
from another_s3_manager.access.oidc.discovery import Snapshot


def signed(op, claims):
    return jwt.encode(
        {"alg": "RS256", "kid": "fixture"},
        claims,
        op.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    ).decode()


@pytest.mark.parametrize(
    "change",
    [
        {"sub": None},
        {"sub": ""},
        {"sub": 123},
        {"sub": "a" * 256},
        {"sub": "é"},
        {"aud": "asm-evil"},
        {"aud": ["asm", 1]},
        {"aud": []},
        {"azp": "wrong"},
        {"aud": ["asm", "other"]},
        {"iat": 99999999999},
        {"nbf": 99999999999},
        {"exp": 1},
        {"nonce": "wrong"},
        {"iss": "https://foreign"},
        *[{name: None} for name in ("iss", "aud", "exp", "iat", "nonce")],
    ],
)
def test_signed_token_subject_audience_azp_and_required_claims(monkeypatch, change):
    monkeypatch.setenv("OIDC_ISSUER", "https://op.example")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    settings = access.oidc_settings({})
    op = FakeOP()
    snapshot = Snapshot(json.dumps(op.metadata), json.dumps({"keys": [op.jwk]}), 0, 0)
    claims = {
        "iss": op.issuer,
        "sub": "123",
        "aud": "asm",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "nonce": "nonce",
    }
    assert validate_id_token(signed(op, claims), snapshot, settings, "nonce")["sub"] == "123"
    with pytest.raises(InvalidIdToken):
        validate_id_token(signed(op, {**claims, **change}), snapshot, settings, "nonce")


def test_foreign_key_and_ambiguous_key_refused(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://op.example")
    monkeypatch.setenv("PUBLIC_URL", "https://asm.example")
    monkeypatch.setenv("OIDC_CLIENT_ID", "asm")
    monkeypatch.setenv("COOKIE_SECURE", "true")
    op, foreign = FakeOP(), FakeOP()
    claims = {
        "iss": op.issuer,
        "sub": "reader",
        "aud": "asm",
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "nonce": "n",
    }
    for keys in ([foreign.jwk], [op.jwk, op.jwk], []):
        snapshot = Snapshot(json.dumps(op.metadata), json.dumps({"keys": keys}), 0, 0)
        with pytest.raises(InvalidIdToken):
            validate_id_token(signed(op, claims), snapshot, access.oidc_settings({}), "n")
