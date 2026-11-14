"""Code exchange and explicitly validated asymmetric OIDC ID tokens."""

import base64
import json
import math
import secrets
import time

from authlib.jose import JsonWebToken
from authlib.jose.errors import BadSignatureError, JoseError
from authlib.oidc.core import CodeIDToken
from joserfc.errors import JoseError as ClaimsError

from .discovery import OidcUnavailable

ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"})


class InvalidIdToken(Exception):
    pass


class UntrustedSigningKey(InvalidIdToken):
    pass


def validate_id_token(token, snapshot, settings, nonce):
    try:
        if not isinstance(token, str) or len(token) > 1024 * 1024:
            raise InvalidIdToken()
        encoded_header = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(encoded_header + "=" * (-len(encoded_header) % 4)))
        advertised = snapshot.metadata.get("id_token_signing_alg_values_supported", [])
        allowed = ALGORITHMS.intersection(advertised) if isinstance(advertised, list) else set()
        algorithm = header.get("alg")
        if algorithm not in allowed or any(key in header for key in ("jku", "jwk", "x5u")):
            raise InvalidIdToken()
        expected_type = "EC" if algorithm.startswith("ES") else "RSA"
        keys = [
            key
            for key in snapshot.jwks["keys"]
            if isinstance(key, dict)
            and key.get("kty") == expected_type
            and key.get("use", "sig") == "sig"
            and key.get("alg", algorithm) == algorithm
            and ("kid" not in header or key.get("kid") == header["kid"])
            and ("key_ops" not in key or key["key_ops"] == ["verify"])
        ]
        if not keys:
            raise UntrustedSigningKey()
        if len(keys) != 1:
            raise InvalidIdToken()
        claims = JsonWebToken(sorted(allowed)).decode(
            token,
            keys[0],
            claims_cls=CodeIDToken,
            claims_options={name: {"essential": True} for name in ("iss", "sub", "aud", "exp", "iat", "nonce")},
            claims_params={"nonce": nonce, "client_id": settings.client_id},
        )
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 255 or not subject.isascii():
            raise InvalidIdToken()
        if (
            claims.get("iss") != settings.issuer
            or not isinstance(claims.get("nonce"), str)
            or not secrets.compare_digest(claims["nonce"], nonce)
        ):
            raise InvalidIdToken()
        audience = claims.get("aud")
        if isinstance(audience, str):
            if audience != settings.client_id:
                raise InvalidIdToken()
        elif type(audience) is list and audience and all(isinstance(item, str) and item for item in audience):
            if settings.client_id not in audience or (len(audience) > 1 and "azp" not in claims):
                raise InvalidIdToken()
        else:
            raise InvalidIdToken()
        if "azp" in claims and (not isinstance(claims["azp"], str) or claims["azp"] != settings.client_id):
            raise InvalidIdToken()
        for name in ("exp", "iat", "nbf"):
            if name in claims and (type(claims[name]) not in (int, float) or not math.isfinite(claims[name])):
                raise InvalidIdToken()
        if claims.get("iat", float("inf")) > time.time() + 60:
            raise InvalidIdToken()
        claims.validate(now=time.time(), leeway=60)
        return dict(claims)
    except BadSignatureError:
        raise UntrustedSigningKey() from None
    except (JoseError, ClaimsError, ValueError, TypeError, KeyError, AttributeError):
        raise InvalidIdToken() from None


def exchange_code(discovery, snapshot, settings, code, transaction):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "code_verifier": transaction["cv"],
    }
    auth = None
    if settings.client_secret:
        # OAuth Basic credentials are form-urlencoded before base64 encoding.
        from urllib.parse import quote_plus

        auth = (quote_plus(settings.client_id), quote_plus(settings.client_secret))
    else:
        data["client_id"] = settings.client_id
    response = discovery.outbound.json("POST", snapshot.metadata["token_endpoint"], data=data, auth=auth)
    token = response.get("id_token")
    try:
        return validate_id_token(token, snapshot, settings, transaction["nonce"])
    except UntrustedSigningKey:
        try:
            refreshed = discovery.retry_keys()
        except OidcUnavailable:
            raise InvalidIdToken() from None
        return validate_id_token(token, refreshed, settings, transaction["nonce"])
