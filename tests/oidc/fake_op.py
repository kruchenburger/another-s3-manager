"""Fixture-only OP with real RSA signatures and one-use PKCE-bound codes."""

import base64
import hashlib
import secrets
import threading
import time
from urllib.parse import parse_qs, urlencode

import httpx
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class FakeOP:
    def __init__(
        self, issuer="https://op.example", client_id="asm", redirect_uri="https://asm.example/api/auth/oidc/callback"
    ):
        self.issuer, self.client_id, self.redirect_uri = issuer, client_id, redirect_uri
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = JsonWebKey.import_key(
            self.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            {"kid": "fixture", "use": "sig", "alg": "RS256"},
        ).as_dict()
        self.codes = {}
        self.calls = 0
        self.lock = threading.Lock()
        self.claims = {"sub": "reader", "preferred_username": "reader", "groups": ["data-team"]}
        self.token_changes = {}

    @property
    def metadata(self):
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "jwks_uri": self.issuer + "/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }

    def authorize(self, query, *, claims=None):
        if (
            query.get("client_id") != self.client_id
            or query.get("redirect_uri") != self.redirect_uri
            or query.get("code_challenge_method") != "S256"
            or not query.get("code_challenge")
            or not query.get("nonce")
        ):
            raise ValueError("Invalid authorization request")
        code = secrets.token_urlsafe(32)
        with self.lock:
            self.codes[code] = {**query, "claims": dict(self.claims if claims is None else claims)}
        return self.redirect_uri + "?" + urlencode({"code": code, "state": query["state"]})

    def handle(self, request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=self.metadata)
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk]})
        if request.url.path != "/token":
            return httpx.Response(404)
        data = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        with self.lock:
            self.calls += 1
            tx = self.codes.pop(data.get("code"), None)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(data.get("code_verifier", "").encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        if (
            tx is None
            or data.get("client_id") != tx["client_id"]
            or data.get("redirect_uri") != tx["redirect_uri"]
            or not data.get("code_verifier")
            or challenge != tx["code_challenge"]
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "iat": now,
            "exp": now + 300,
            "nonce": tx["nonce"],
            **tx["claims"],
            **self.token_changes,
        }
        token = jwt.encode(
            {"alg": "RS256", "kid": "fixture"},
            claims,
            self.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ).decode()
        return httpx.Response(
            200, json={"id_token": token, "token_type": "Bearer", "access_token": "fixture-discarded"}
        )


def browser_app():
    """Runnable only from the test module, never imported by production routes."""
    import os

    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, RedirectResponse, Response

    provider = FakeOP(
        os.environ["OIDC_ISSUER"], os.environ["OIDC_CLIENT_ID"], os.environ["PUBLIC_URL"] + "/api/auth/oidc/callback"
    )
    app = FastAPI()

    @app.get("/.well-known/openid-configuration")
    def discovery():
        return provider.metadata

    @app.get("/jwks")
    def keys():
        return {"keys": [provider.jwk]}

    @app.get("/authorize")
    def authorize(request: Request):
        from html import escape

        query = dict(request.query_params)
        subject = query.pop("fixture_subject", None)
        if subject is None:
            fields = "".join(
                '<input type="hidden" name="' + escape(k, quote=True) + '" value="' + escape(v, quote=True) + '">'
                for k, v in query.items()
            )
            return HTMLResponse(
                "<form>"
                + fields
                + '<label>Fixture subject<input name="fixture_subject" value="reader"></label><button>Continue</button></form>'
            )
        claims = {"sub": subject, "preferred_username": subject, "groups": ["data-team"]}
        return RedirectResponse(provider.authorize(query, claims=claims), status_code=302)

    @app.post("/token")
    async def token(request: Request):
        result = provider.handle(
            httpx.Request(
                "POST", provider.issuer + "/token", content=await request.body(), headers=dict(request.headers)
            )
        )
        return Response(result.content, status_code=result.status_code, media_type="application/json")

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(browser_app(), host="127.0.0.1", port=8091, access_log=False)
