"""The CI OIDC log sanitizer never prints auth material."""

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "oidc_sanitize", Path(__file__).resolve().parents[1] / "scripts" / "ci" / "oidc_sanitize.py"
)
sanitizer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sanitizer)

SECRET = "opaque-secret-Value_123"


@pytest.mark.parametrize(
    "line",
    [
        f"GET /api/auth/oidc/callback?code={SECRET}&state={SECRET} HTTP/1.1",
        f"{{'code': '{SECRET}'}}",
        f'{{"code_verifier": "{SECRET}"}}',
        f"state='{SECRET}'",
        f"client_secret: {SECRET}",
        f"Authorization: Bearer {SECRET}",
        "id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
        f"refresh_token={SECRET}",
        f"nonce {SECRET}XXXXXXXXXXXXXXX",
    ],
)
def test_sanitizer_removes_auth_values(line):
    out = sanitizer.sanitize(line)
    assert SECRET not in out
    assert "eyJ" not in out


def test_sanitizer_keeps_ordinary_diagnostics():
    line = "Error: expect(received).toBe(expected) at oidc-login.spec.ts:80:5"
    assert sanitizer.sanitize(line) == line
