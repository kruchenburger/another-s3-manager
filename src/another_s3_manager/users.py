"""User and ban management — SQLAlchemy-backed.

Public API surface (load_users, save_users, load_bans, save_bans, create_user,
update_user, delete_user, get_user_by_username, get_all_users, get_available_roles)
is preserved unchanged so callers in auth.py and main.py need no edits.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from another_s3_manager.database import session_scope
from another_s3_manager.models import Ban, User, UserRole

logger = logging.getLogger(__name__)


def _user_to_dict(user: User) -> Dict[str, Any]:
    """Render a User row to the dict shape that the rest of the app expects."""
    return {
        "username": user.username,
        "password_hash": user.password_hash,
        "is_admin": user.is_admin,
        "allowed_roles": [r.role_name for r in user.roles],
        "theme": user.theme,
        "default_role": user.default_role,
        "must_change_password": user.must_change_password,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def _seed_default_admin_if_empty(session) -> Optional[User]:
    """If the users table is empty, create the default admin from ADMIN_PASSWORD env. Returns the new admin or None.

    Caller must commit the session (we use session.flush() to assign an id without committing).
    """
    from another_s3_manager.auth import hash_password

    existing = session.execute(select(User).limit(1)).scalar_one_or_none()
    if existing is not None:
        return None
    admin_password = os.getenv("ADMIN_PASSWORD", "change_me_pls")
    admin = User(
        username="admin",
        password_hash=hash_password(admin_password),
        is_admin=True,
        theme="auto",
        must_change_password=False,
    )
    session.add(admin)
    session.flush()
    return admin


def load_users() -> Dict[str, Any]:
    """Load all users. If the table is empty, seed a default admin from env."""
    with session_scope() as session:
        users = session.execute(select(User).options(selectinload(User.roles))).scalars().all()
        if not users:
            admin = _seed_default_admin_if_empty(session)
            if admin is not None:
                return {"users": [_user_to_dict(admin)]}
            # Race: someone else seeded between our check and now — re-fetch
            users = session.execute(select(User).options(selectinload(User.roles))).scalars().all()
        return {"users": [_user_to_dict(u) for u in users]}


def _reconcile_default_role(current: Optional[str], new_roles: List[str]) -> Optional[str]:
    """Return a `default_role` value consistent with `new_roles`.

    If `current` is in `new_roles` (or is None), keep it. Otherwise fall back
    to the first of `new_roles`, or None if the list is empty. Used by both
    `update_user` (single-user kwarg path) and `save_users` (admin bulk-upsert
    path) so a removed allowed_role never leaves a dangling default behind.
    """
    if current is None or current in new_roles:
        return current
    return new_roles[0] if new_roles else None


def compute_default_role(
    explicit_default: Optional[str],
    allowed_roles: List[str],
) -> Optional[str]:
    """Pick the effective default role for a user.

    Resolution order:
      1. `explicit_default` if it's still in `allowed_roles`
      2. first of `allowed_roles`
      3. None (no allowed roles)
    """
    if explicit_default and explicit_default in allowed_roles:
        return explicit_default
    if allowed_roles:
        return allowed_roles[0]
    return None


def validate_default_role_choice(role: Optional[str], allowed_roles: List[str]) -> None:
    """Raise ValueError if `role` is not None and not in `allowed_roles`.

    Centralises the validation used by `PUT /api/me/default-role` so the
    router stays a thin HTTP wrapper.
    """
    if role is not None and role not in allowed_roles:
        raise ValueError(f"Role '{role}' is not in the allowed roles")


def save_users(users_data: Dict[str, Any]) -> None:
    """Replace the user set with the given list using upsert semantics.

    For each incoming user:
      - If username exists, UPDATE the row in place (preserves id, created_at, bans).
      - If new, INSERT it.
    Users in the DB but absent from the incoming list are DELETED (cascade clears their roles + bans).

    All in a single transaction. This preserves bans and timestamps for unaffected users —
    matching the legacy JSON behavior where save_users only touched users.json.
    """
    incoming: List[Dict[str, Any]] = users_data.get("users", [])
    incoming_by_username = {u["username"]: u for u in incoming}

    with session_scope() as session:
        existing_users = session.execute(select(User).options(selectinload(User.roles))).scalars().all()
        existing_by_username = {u.username: u for u in existing_users}

        # Delete users that are no longer in the incoming list
        for username, user in existing_by_username.items():
            if username not in incoming_by_username:
                session.delete(user)
        session.flush()

        # Upsert: update existing in place, insert new
        for user_dict in incoming:
            existing = existing_by_username.get(user_dict["username"])
            if existing is not None:
                # In-place update preserves id, created_at, and bans (no cascade)
                existing.password_hash = user_dict["password_hash"]
                existing.is_admin = user_dict.get("is_admin", False)
                existing.theme = user_dict.get("theme", "auto")
                if "must_change_password" in user_dict:
                    existing.must_change_password = bool(user_dict["must_change_password"])
                # Replace roles atomically.
                # Flush after clear() so the orphan DELETEs hit the DB before
                # the new INSERTs — otherwise a no-op edit (set Default → clear,
                # or set Default → set Default) collides on the
                # uq_user_role(user_id, role_name) UNIQUE constraint because
                # SQLAlchemy emits INSERTs before processing the orphan-disconnect.
                existing.roles.clear()
                session.flush()
                new_roles = user_dict.get("allowed_roles", [])
                for role_name in new_roles:
                    existing.roles.append(UserRole(role_name=role_name))
                # If the previous default_role is no longer in the new role
                # set, reset to the first of the new set (or None). Matches
                # the behavior of update_user() so admin bulk-upsert doesn't
                # leave dangling defaults behind.
                existing.default_role = _reconcile_default_role(existing.default_role, new_roles)
            else:
                user = User(
                    username=user_dict["username"],
                    password_hash=user_dict["password_hash"],
                    is_admin=user_dict.get("is_admin", False),
                    theme=user_dict.get("theme", "auto"),
                    must_change_password=bool(user_dict.get("must_change_password", False)),
                )
                for role_name in user_dict.get("allowed_roles", []):
                    user.roles.append(UserRole(role_name=role_name))
                session.add(user)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user by username, or None if not found."""
    with session_scope() as session:
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        return _user_to_dict(user) if user else None


def get_all_users() -> List[Dict[str, Any]]:
    """Read all users. Does NOT seed — read operations are pure reads."""
    with session_scope() as session:
        users = session.execute(select(User).options(selectinload(User.roles))).scalars().all()
        return [_user_to_dict(u) for u in users]


def get_users_for_admin() -> List[Dict[str, Any]]:
    """Return users with id included for admin API responses. Does NOT seed."""
    with session_scope() as session:
        users = session.execute(select(User).options(selectinload(User.roles))).scalars().all()
        return [
            {
                "id": u.id,
                "username": u.username,
                "is_admin": u.is_admin,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "allowed_roles": [r.role_name for r in u.roles],
            }
            for u in users
        ]


def create_user(
    username: str,
    password_hash: str,
    is_admin: bool = False,
    allowed_roles: Optional[List[str]] = None,
    must_change_password: bool = True,
) -> Dict[str, Any]:
    """Create a single user. Does NOT seed default admin (that's load_users's job).

    Single-allowed-role users get `default_role` auto-set to that role — the
    picker would be degenerate otherwise. Multi-role users start with
    default_role=NULL; the computed fallback (first of allowed_roles) applies
    until they pick explicitly.

    `must_change_password` defaults to True (paranoid default — admin generated
    the password, user must change it on first login). Admin can opt out via
    the UserDrawer checkbox or by passing False explicitly. The seed admin
    bootstrap path (_seed_default_admin_if_empty) bypasses this with False.
    """
    with session_scope() as session:
        existing = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if existing:
            raise ValueError(f"User {username} already exists")

        roles = list(allowed_roles or [])
        auto_default = roles[0] if len(roles) == 1 else None

        user = User(
            username=username,
            password_hash=password_hash,
            is_admin=is_admin,
            theme="auto",
            default_role=auto_default,
            must_change_password=must_change_password,
        )
        for role_name in roles:
            user.roles.append(UserRole(role_name=role_name))
        session.add(user)
        session.flush()
        return _user_to_dict(user)


def update_user(username: str, **kwargs: Any) -> Dict[str, Any]:
    """Update user properties. Raises ValueError if the user doesn't exist.

    `default_role`:
      - explicit: pass `default_role=<role>` or `default_role=None`
      - implicit reset: if `allowed_roles` changes such that the current
        default is no longer in the new set, reset to the first of the new
        set (or NULL if the new set is empty)
    """
    with session_scope() as session:
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not user:
            raise ValueError(f"User {username} not found")

        if "password_hash" in kwargs:
            user.password_hash = kwargs["password_hash"]
        if "is_admin" in kwargs:
            user.is_admin = kwargs["is_admin"]
        if "theme" in kwargs:
            user.theme = kwargs["theme"]
        if "must_change_password" in kwargs:
            user.must_change_password = bool(kwargs["must_change_password"])
        if "default_role" in kwargs:
            user.default_role = kwargs["default_role"]
        if "allowed_roles" in kwargs:
            new_roles = list(kwargs["allowed_roles"])
            user.roles.clear()
            for role_name in new_roles:
                user.roles.append(UserRole(role_name=role_name))
            user.default_role = _reconcile_default_role(user.default_role, new_roles)

        session.flush()
        return _user_to_dict(user)


def delete_user(username: str) -> None:
    """Delete a user (no-op if missing). Cascades to roles and bans."""
    with session_scope() as session:
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user:
            session.delete(user)


def load_bans() -> Dict[str, Any]:
    """Return bans as {username: {banned_until, banned_at, reason}}. Filters and removes expired bans."""
    current_time = time.time()
    with session_scope() as session:
        rows = session.execute(select(Ban, User).join(User, Ban.user_id == User.id)).all()
        active: Dict[str, Any] = {}
        for ban, user in rows:
            if ban.banned_until > current_time:
                active[user.username] = {
                    "banned_until": ban.banned_until,
                    "banned_at": ban.banned_at,
                    "reason": ban.reason,
                }
            else:
                # Auto-cleanup expired
                session.delete(ban)
        return active


def save_bans(bans_data: Dict[str, Any]) -> None:
    """Replace all bans with the given dict. Skips bans for unknown usernames (with warning log)."""
    with session_scope() as session:
        # Wipe existing bans
        for b in session.execute(select(Ban)).scalars().all():
            session.delete(b)
        session.flush()

        for username, ban_dict in bans_data.items():
            user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None:
                logger.warning(
                    "save_bans: dropped ban for unknown user %r (FK constraint requires existing user)",
                    username,
                )
                continue
            session.add(
                Ban(
                    user_id=user.id,
                    banned_until=ban_dict.get("banned_until", 0),
                    banned_at=ban_dict.get("banned_at", time.time()),
                    reason=ban_dict.get("reason"),
                )
            )


def get_available_roles() -> List[str]:
    """Get list of available role names from config."""
    # Import here to avoid circular dependency
    try:
        from another_s3_manager.config import load_config

        config = load_config(force_reload=False)
        return [role.get("name") for role in config.get("roles", []) if role.get("name")]
    except ImportError:
        return []
