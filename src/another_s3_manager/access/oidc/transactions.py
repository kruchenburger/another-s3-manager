"""Durable, hash-only, single-use OIDC transaction ledger."""

import hashlib
from datetime import UTC, datetime

from sqlalchemy import delete, select, update

from another_s3_manager.access.users import write_scope
from another_s3_manager.models import OidcLoginTransaction


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
