import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy import and_, func, or_, select, update

from another_s3_manager.database import session_scope
from another_s3_manager.models import ApiToken, User

logger = logging.getLogger(__name__)

PER_USER_TOKEN_LIMIT = 10
TOKEN_PREFIX = "as3m_"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def generate_token() -> Tuple[str, str]:
    """Returns (plaintext, sha256_hex_digest). Plaintext format: as3m_<43 base64url chars>."""
    raw = secrets.token_urlsafe(32)
    plaintext = f"{TOKEN_PREFIX}{raw}"
    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    return plaintext, digest


def create_token(
    user_id: int,
    name: str,
    is_read_only: bool,
    max_read_bytes: int,
) -> Tuple[ApiToken, str]:
    """Create a new token. Returns (orm row detached from session, plaintext).

    Plaintext is returned ONLY here. Caller must persist it (response to client) immediately.
    Raises ValueError if the per-user active limit is reached.
    Raises sqlalchemy.exc.IntegrityError on duplicate name (caught at endpoint layer -> 409).
    """
    with session_scope() as session:
        active = session.execute(
            select(func.count(ApiToken.id)).where(and_(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None)))
        ).scalar_one()
        if active >= PER_USER_TOKEN_LIMIT:
            raise ValueError(f"Token limit reached ({PER_USER_TOKEN_LIMIT}). Revoke unused tokens first.")
        plaintext, digest = generate_token()
        token = ApiToken(
            user_id=user_id,
            token_hash=digest,
            name=name,
            is_read_only=is_read_only,
            max_read_bytes=max_read_bytes,
        )
        session.add(token)
        session.flush()
        # Detach from session so caller can read attributes after commit
        session.expunge(token)
        return token, plaintext


def list_tokens_for_user(user_id: int, include_revoked: bool = False) -> list[ApiToken]:
    with session_scope() as session:
        stmt = select(ApiToken).where(ApiToken.user_id == user_id)
        if not include_revoked:
            stmt = stmt.where(ApiToken.revoked_at.is_(None))
        stmt = stmt.order_by(ApiToken.created_at.desc())
        rows = session.execute(stmt).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)


def list_all_tokens(include_revoked: bool = False) -> list[Tuple[ApiToken, User]]:
    """Admin view: every token + its owning user."""
    with session_scope() as session:
        stmt = select(ApiToken, User).join(User, ApiToken.user_id == User.id)
        if not include_revoked:
            stmt = stmt.where(ApiToken.revoked_at.is_(None))
        stmt = stmt.order_by(ApiToken.created_at.desc())
        rows = session.execute(stmt).all()
        result: list[Tuple[ApiToken, User]] = []
        for token, user in rows:
            session.expunge(token)
            session.expunge(user)
            result.append((token, user))
        return result


def revoke_token(token_id: int, by_user_id: int, by_is_admin: bool) -> None:
    """Set revoked_at = now() if authorized.

    Authorization: token owner OR admin. Raises PermissionError otherwise.
    Raises ValueError if token not found.
    """
    with session_scope() as session:
        token = session.get(ApiToken, token_id)
        if token is None:
            raise ValueError(f"Token {token_id} not found")
        if not by_is_admin and token.user_id != by_user_id:
            raise PermissionError("Only the token owner or an admin can revoke")
        if token.revoked_at is None:
            token.revoked_at = _utcnow()


def find_active_token_by_hash(token_hash: str) -> Optional[ApiToken]:
    """Hot path. SELECT ... WHERE token_hash = :h AND revoked_at IS NULL."""
    with session_scope() as session:
        token = session.execute(
            select(ApiToken).where(and_(ApiToken.token_hash == token_hash, ApiToken.revoked_at.is_(None)))
        ).scalar_one_or_none()
        if token is not None:
            session.expunge(token)
        return token


def touch_last_used(token_id: int, throttle_seconds: int = 60) -> None:
    """Atomic conditional UPDATE.

    Sets last_used_at = now() only if (last_used_at IS NULL OR last_used_at < now() - throttle_seconds).
    Reduces write amplification under burst load (98% reduction at 1 req/sec sustained).
    """
    now = _utcnow()
    cutoff = now - timedelta(seconds=throttle_seconds)
    with session_scope() as session:
        session.execute(
            update(ApiToken)
            .where(
                and_(
                    ApiToken.id == token_id,
                    or_(ApiToken.last_used_at.is_(None), ApiToken.last_used_at < cutoff),
                )
            )
            .values(last_used_at=now)
        )


def count_active_tokens_for_user(user_id: int) -> int:
    with session_scope() as session:
        return session.execute(
            select(func.count(ApiToken.id)).where(and_(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None)))
        ).scalar_one()
