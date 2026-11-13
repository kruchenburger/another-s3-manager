"""Identity persistence only; provisioning and mapping belong to PR 3."""

from sqlalchemy import select

from another_s3_manager.database import session_scope
from another_s3_manager.models import UserIdentity


def find_identity(issuer: str, subject: str):
    with session_scope() as session:
        row = session.scalar(select(UserIdentity).where(UserIdentity.issuer == issuer, UserIdentity.subject == subject))
        if row is None:
            return None
        return {
            name: getattr(row, name)
            for name in ("id", "user_id", "issuer", "subject", "email_at_link", "created_at", "last_login_at")
        }


def insert_identity(session, *, user_id, issuer, subject, email_at_link=None):
    """Participate in the caller's transaction so future JIT is atomic."""
    row = UserIdentity(user_id=user_id, issuer=issuer, subject=subject, email_at_link=email_at_link)
    session.add(row)
    session.flush()
    return row.id
