from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

from sqlalchemy import func, select

from another_s3_manager import access
from another_s3_manager.database import reset_engine_for_tests, session_scope
from another_s3_manager.models import OidcLoginTransaction


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
