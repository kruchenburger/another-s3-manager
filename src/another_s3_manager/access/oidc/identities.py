"""Atomic identity provisioning and accepted-login persistence."""

import re
import unicodedata
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from another_s3_manager.access import users
from another_s3_manager.access.errors import AuthenticationError
from another_s3_manager.access.principal import Principal
from another_s3_manager.access.sessions import issue_session
from another_s3_manager.database import session_scope
from another_s3_manager.models import User, UserIdentity, UserRole

from .mapping import claim_at, evaluate_mapping


def normalized_username(value):
    text = unicodedata.normalize("NFKC", value).strip().lower() if isinstance(value, str) else ""
    return re.sub(r"[^a-z0-9._@-]", "-", text)[:64] or "sso-user"


def login_snapshot(issuer, subject):
    identity = find_identity(issuer, subject)
    if identity is None:
        return None
    return users.get_user_by_id(identity["user_id"])


def commit_login(claims, config, settings, expected, seed_hash=None, *, now=None):
    """Commit acceptance or denial under caller-held publication coordination."""
    now = now or datetime.now(UTC)
    result = evaluate_mapping(claims, config)
    refusal = None
    token = None
    with users.write_scope() as session:
        identity = session.scalar(
            select(UserIdentity).where(UserIdentity.issuer == claims["iss"], UserIdentity.subject == claims["sub"])
        )
        row = session.get(User, identity.user_id) if identity else None
        if row is not None:
            if row.is_disabled:
                return None, "disabled", result
            if row.auth_source != "oidc":
                return None, "no_access", result
            if expected is not None and (row.id, row.auth_generation, row.session_epoch) != (
                expected["id"],
                expected["auth_generation"],
                expected["session_epoch"],
            ):
                return None, "expired", result
        elif expected is not None:
            return None, "expired", result
        if not result.eligible:
            if row is not None:
                if settings.mode == "sync":
                    row.roles.clear()
                    row.is_admin = False
                    row.default_role = users._reconcile_default_role(row.default_role, [])
                    row.sso_authz_valid_until = now
                row.session_epoch += 1
            refusal = "no_access"
        else:
            creating = row is None
            if creating:
                if seed_hash is not None and session.scalar(select(User.id).limit(1)) is None:
                    # Hashing happened before publication/SQLite locks were acquired.
                    session.add(
                        User(
                            username="admin",
                            password_hash=seed_hash,
                            is_admin=True,
                            password_set_via="env",
                            must_change_password=False,
                        )
                    )
                    session.flush()
                value = next(
                    (
                        candidate
                        for candidate in (claim_at(claims, settings.username_claim), claims.get("email"), claims["sub"])
                        if isinstance(candidate, str) and candidate.strip()
                    ),
                    "sso-user",
                )
                base = normalized_username(value)
                for attempt in range(11):
                    suffix = "" if attempt == 0 else "-sso" if attempt == 1 else f"-sso-{attempt}"
                    username = base[: 64 - len(suffix)] + suffix
                    if session.scalar(select(User.id).where(func.lower(User.username) == username)) is not None:
                        continue
                    try:
                        with session.begin_nested():
                            row = User(
                                username=username,
                                password_hash="!",
                                auth_source="oidc",
                                must_change_password=False,
                                is_admin=False,
                                password_set_via="unknown",
                            )
                            session.add(row)
                            session.flush()
                            identity = UserIdentity(user_id=row.id, issuer=claims["iss"], subject=claims["sub"])
                            session.add(identity)
                            session.flush()
                        break
                    except IntegrityError:
                        identity = session.scalar(
                            select(UserIdentity).where(
                                UserIdentity.issuer == claims["iss"], UserIdentity.subject == claims["sub"]
                            )
                        )
                        if identity:
                            row = session.get(User, identity.user_id)
                            creating = False
                            break
                else:
                    raise AuthenticationError("username_conflict", "SSO username unavailable")
            if row.auth_source != "oidc" or row.is_disabled:
                return None, "disabled" if row.is_disabled else "no_access", result
            if creating or settings.mode == "sync":
                row.roles.clear()
                session.flush()
                row.roles.extend(UserRole(role_name=name) for name in result.roles)
                row.is_admin = result.admin
                row.default_role = users._reconcile_default_role(row.default_role, list(result.roles))
            row.mapping_mode_applied = settings.mode
            row.sso_authz_valid_until = now + timedelta(days=7) if settings.mode == "sync" else None
            identity.last_login_at = now
            session.flush()
            token = issue_session(
                Principal(users._user_to_dict(row)), method="oidc", lifetime_minutes=settings.lifetime_minutes
            )
    return token, refusal, result


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
