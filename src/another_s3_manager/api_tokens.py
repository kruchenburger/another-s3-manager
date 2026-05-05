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
# Mirrors the CHECK constraint on api_tokens.max_read_bytes (1..10MB).
_MAX_READ_BYTES_CEILING = 10 * 1024 * 1024


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

    Concurrency note: the COUNT-then-INSERT pair is not strictly serializable —
    two concurrent transactions can both see N<LIMIT and both INSERT, ending
    up at LIMIT+1 active tokens. Safe in our deployment because:
      - SQLite enforces a database-level write lock (only one writer at a time)
      - Default uvicorn config is single-worker, so within-process async tasks
        are scheduled cooperatively rather than truly concurrent
      - Per-user limit (10) is a soft cap, not a security boundary; over by 1-2
        is harmless
    If we ever move to multi-worker uvicorn or Postgres, revisit with a
    SELECT...FOR UPDATE or a unique partial index.
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
        # Materialize attributes BEFORE expunge_all so detached access works.
        # We can't expunge token AND user separately when they share a session
        # — expunging the token via its FK relationship cascades to the user
        # in some configurations. Just expunge_all once at the end.
        result: list[Tuple[ApiToken, User]] = list(rows)
        for token, user in result:
            # Force-load the columns the caller will read after expunge.
            _ = (
                token.id,
                token.name,
                token.is_read_only,
                token.max_read_bytes,
                token.created_at,
                token.last_used_at,
                token.revoked_at,
            )
            _ = (user.id, user.username)
        session.expunge_all()
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


def update_token(
    token_id: int,
    by_user_id: int,
    by_is_admin: bool,
    name: Optional[str] = None,
    is_read_only: Optional[bool] = None,
    max_read_bytes: Optional[int] = None,
) -> ApiToken:
    """Update editable metadata on an active token. Owner or admin only.

    Returns the updated detached ApiToken instance.
    Raises:
        ValueError("no fields to update") when all editable fields are None.
        ValueError("max_read_bytes out of range") when not in 1..10MB.
        ValueError("Token {id} not found") when missing.
        ValueError("Token {id} is revoked") when token is already revoked.
        PermissionError when actor is neither owner nor admin.
        IntegrityError when name collides with another token of the same user.
    """
    if name is None and is_read_only is None and max_read_bytes is None:
        raise ValueError("no fields to update")

    if max_read_bytes is not None and not (1 <= max_read_bytes <= _MAX_READ_BYTES_CEILING):
        raise ValueError("max_read_bytes out of range")

    with session_scope() as session:
        token = session.get(ApiToken, token_id)
        if token is None:
            raise ValueError(f"Token {token_id} not found")

        if not by_is_admin and token.user_id != by_user_id:
            raise PermissionError("Only the token owner or an admin can update")

        if token.revoked_at is not None:
            raise ValueError(f"Token {token_id} is revoked")

        if name is not None:
            token.name = name
        if is_read_only is not None:
            token.is_read_only = is_read_only
        if max_read_bytes is not None:
            token.max_read_bytes = max_read_bytes

        session.flush()
        # `session.refresh(token)` is REQUIRED before `expunge` — it materializes
        # every column attribute (including `user_id`, which the admin endpoint
        # reads after the session closes to look up `owner_username`). Removing
        # the refresh would re-introduce the `DetachedInstanceError` bug class
        # fixed in commit d844e2a (`list_all_tokens` shared-identity expunge).
        # Likewise: do NOT access `token.user` (the relationship) outside the
        # session — only column attributes survive expunge. Use `token.user_id`
        # and look up the User in a fresh session, like `admin_update_token` does.
        session.refresh(token)
        session.expunge(token)
        return token


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
