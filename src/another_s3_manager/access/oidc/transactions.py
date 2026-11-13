"""Durable, hash-only, single-use OIDC transaction ledger."""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jose import JWTError, jwt
from sqlalchemy import delete, select, update

from another_s3_manager.access.sessions import get_jwt_secret_key
from another_s3_manager.access.users import write_scope
from another_s3_manager.models import OidcLoginTransaction


@dataclass(frozen=True)
class CookieOperation:
    name: str
    value: str = field(default="", repr=False)
    max_age: int = 0


@dataclass(frozen=True)
class OidcStart:
    redirect: str = field(repr=False)
    cookies: tuple[CookieOperation, ...] = ()
    code: str | None = None


@dataclass(frozen=True)
class OidcCompletion:
    redirect: str
    cookies: tuple[CookieOperation, ...] = ()
    code: str | None = None
    session: str | None = field(default=None, repr=False)
    lifetime_minutes: int = 0


def safe_return_to(value):
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 2048
        or not value.startswith("/")
        or value.startswith(("//", "/\\"))
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        return "/"
    return value


def transaction_key():
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"asm-oidc-tx-v1").derive(
        get_jwt_secret_key().encode()
    )


def decode_transaction(token):
    try:
        payload = jwt.decode(token, transaction_key(), algorithms=["HS256"])
        if payload.get("typ") != "oidc_tx" or payload.get("intent") != "login" or type(payload.get("exp")) is not int:
            return None
        if any(not isinstance(payload.get(key), str) or not payload[key] for key in ("state", "nonce", "cv", "rt")):
            return None
        return payload
    except (JWTError, ValueError, TypeError):
        return None


def new_transaction(return_to, cookies, settings, metadata):
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    now = int(time.time())
    payload = {
        "typ": "oidc_tx",
        "intent": "login",
        "state": state,
        "nonce": nonce,
        "cv": verifier,
        "rt": safe_return_to(return_to),
        "iat": now,
        "exp": now + 600,
    }
    existing = []
    operations = []
    for name, value in cookies.items():
        if name.startswith("oidc_tx_"):
            tx = decode_transaction(value)
            if tx:
                existing.append((tx.get("iat", 0), name))
            else:
                operations.append(CookieOperation(name))
    for _, name in sorted(existing, key=lambda item: item[0])[: max(0, len(existing) - 2)]:
        operations.append(CookieOperation(name))
    register_login_transaction(state, datetime.fromtimestamp(now + 600, UTC))
    operations.append(
        CookieOperation("oidc_tx_" + state[:8], jwt.encode(payload, transaction_key(), algorithm="HS256"), 600)
    )
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "scope": " ".join(settings.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    endpoint = metadata["authorization_endpoint"]
    return OidcStart(endpoint + ("&" if "?" in endpoint else "?") + query, tuple(operations))


def consume_transaction(query, cookies):
    state = query.get("state", "")
    if (
        not isinstance(state, str)
        or not state
        or len(state) > 128
        or not all(c.isascii() and (c.isalnum() or c in "-_") for c in state)
    ):
        return None, ()
    name = "oidc_tx_" + state[:8]
    operations = (CookieOperation(name),)
    tx = decode_transaction(cookies.get(name, ""))
    if tx is None or not secrets.compare_digest(state, tx["state"]) or not consume_login_transaction(state):
        return None, operations
    return tx, operations


def _purge(session, now):
    expired = (
        select(OidcLoginTransaction.state_hash)
        .where(OidcLoginTransaction.expires_at <= now)
        .order_by(OidcLoginTransaction.expires_at)
        .limit(100)
    )
    session.execute(
        delete(OidcLoginTransaction).where(OidcLoginTransaction.state_hash.in_(expired)),
        execution_options={"synchronize_session": False},
    )


def register_login_transaction(state: str, expires_at: datetime, *, now=None):
    now = now or datetime.now(UTC)
    with write_scope() as session:
        _purge(session, now)
        session.add(OidcLoginTransaction(state_hash=hashlib.sha256(state.encode()).hexdigest(), expires_at=expires_at))


def consume_login_transaction(state: str, *, now=None) -> bool:
    now = now or datetime.now(UTC)
    with write_scope() as session:
        _purge(session, now)
        result = session.execute(
            update(OidcLoginTransaction)
            .where(
                OidcLoginTransaction.state_hash == hashlib.sha256(state.encode()).hexdigest(),
                OidcLoginTransaction.consumed_at.is_(None),
                OidcLoginTransaction.expires_at > now,
            )
            .values(consumed_at=now)
        )
        return result.rowcount == 1
