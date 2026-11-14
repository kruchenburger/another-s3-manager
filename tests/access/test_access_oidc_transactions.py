import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import func, select
from tests.test_oidc_login_integration import begin

from another_s3_manager import access
from another_s3_manager.access.oidc.transactions import safe_return_to, transaction_key
from another_s3_manager.database import reset_engine_for_tests, session_scope
from another_s3_manager.models import OidcLoginTransaction


@given(st.text(max_size=2200))
def test_safe_return_property(value):
    result = safe_return_to(value)
    assert result == "/" or (
        result.startswith("/")
        and not result.startswith(("//", "/\\"))
        and len(result.encode()) <= 2048
        and all(ord(c) >= 32 and ord(c) != 127 for c in result)
    )


def test_derived_key_cannot_issue_session():
    from jose import jwt

    token = jwt.encode({"typ": "oidc_tx", "exp": 9999999999}, transaction_key(), algorithm="HS256")
    assert access.decode_session_payload(token) is None


def test_entropy_pkce_and_three_independent_cookie_limit(oidc, monkeypatch):
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlsplit

    from another_s3_manager.access.oidc.transactions import decode_transaction

    cookies, seen = {}, set()
    first_name = None
    for index in range(4):
        result = access.start_oidc_login("/files?q=1", cookies)
        params = {key: values[0] for key, values in parse_qs(urlsplit(result.redirect).query).items()}
        for operation in result.cookies:
            if operation.max_age:
                cookies[operation.name] = operation.value
                first_name = first_name or operation.name
            else:
                cookies.pop(operation.name, None)
        tx = decode_transaction(next(op.value for op in result.cookies if op.max_age))
        assert len(tx["state"]) == 43 and len(tx["nonce"]) == 43 and len(tx["cv"]) == 86
        assert tx["state"] not in seen
        seen.add(tx["state"])
        assert (
            params["code_challenge"]
            == base64.urlsafe_b64encode(hashlib.sha256(tx["cv"].encode()).digest()).rstrip(b"=").decode()
        )
        assert params["code_challenge_method"] == "S256"
        assert tx["rt"] == "/files?q=1"
        assert tx["exp"] - tx["iat"] == 600
        assert len(cookies) == min(index + 1, 3)
    assert first_name not in cookies


def test_atomic_consume_has_one_winner():
    now = datetime.now(UTC)
    access.register_login_transaction("state", now + timedelta(minutes=5), now=now)
    start = Barrier(2)

    def consume():
        start.wait(timeout=10)
        return access.consume_login_transaction("state", now=now)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(consume), pool.submit(consume)
        assert sorted([a.result(timeout=10), b.result(timeout=10)]) == [False, True]


def test_consumed_transaction_survives_restart():
    now = datetime.now(UTC)
    access.register_login_transaction("state", now + timedelta(minutes=5), now=now)
    assert access.consume_login_transaction("state", now=now)
    reset_engine_for_tests()
    assert not access.consume_login_transaction("state", now=now)


def test_expired_transaction_cannot_consume():
    now = datetime.now(UTC)
    access.register_login_transaction("state", now, now=now)
    assert not access.consume_login_transaction("state", now=now)
    assert not access.consume_login_transaction("unknown", now=now)


def test_purge_is_bounded_and_preserves_live_transactions():
    now = datetime.now(UTC)
    with session_scope() as session:
        session.add_all(
            [OidcLoginTransaction(state_hash=f"{i:064x}", expires_at=now - timedelta(seconds=1)) for i in range(250)]
        )
    access.register_login_transaction("live", now + timedelta(minutes=5), now=now)
    with session_scope() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginTransaction)) == 151
    assert access.consume_login_transaction("live", now=now)
    with session_scope() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginTransaction)) == 51


def test_ledger_consume_precedes_exchange_and_survives_restart(oidc):
    from concurrent.futures import ThreadPoolExecutor

    from another_s3_manager.database import reset_engine_for_tests

    query, cookies = begin(oidc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: asyncio.run(access.complete_oidc_login(query, cookies)), range(2)))
    assert sum(bool(result.session) for result in results) == 1
    assert oidc.calls == 1
    reset_engine_for_tests()
    assert asyncio.run(access.complete_oidc_login(query, cookies)).session is None
    assert oidc.calls == 1
