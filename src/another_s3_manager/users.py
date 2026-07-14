"""User and ban management — SQLAlchemy-backed.

Public API surface (load_users, save_users, load_bans, save_bans, create_user,
update_user, delete_user, get_user_by_username, get_all_users, get_available_roles)
is preserved unchanged so callers in auth.py and main.py need no edits.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from another_s3_manager.constants import (
    DEFAULT_ADMIN_PASSWORD,
    PASSWORD_SET_VIA_CLI,
    PASSWORD_SET_VIA_ENV,
    PASSWORD_SET_VIA_UI,
    PASSWORD_SET_VIA_UNKNOWN,
)
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
        "password_set_via": user.password_set_via,
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
    admin_password = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    admin = User(
        username="admin",
        password_hash=hash_password(admin_password),
        is_admin=True,
        theme="auto",
        must_change_password=False,
        # Bootstrapped from the environment -> ADMIN_PASSWORD keeps governing this
        # password until someone changes it in the UI or via the reset CLI.
        #
        # Note this stamps "env" even when ADMIN_PASSWORD is unset (falls back to
        # DEFAULT_ADMIN_PASSWORD) -- intentional, so an operator who adds ADMIN_PASSWORD
        # to their compose file *after* first boot can still rotate it. Task 3's startup
        # sync MUST condition on `os.getenv("ADMIN_PASSWORD") is not None`, never on the
        # DEFAULT_ADMIN_PASSWORD-fallback value -- otherwise an operator who later removes
        # the var resets the admin password back to the publicly known default.
        password_set_via=PASSWORD_SET_VIA_ENV,
    )
    session.add(admin)
    session.flush()
    return admin


def _admin_password_force_enabled() -> bool:
    """The ONE truthiness rule for ADMIN_PASSWORD_FORCE: "1" / "true" / "yes", case-insensitive.

    Everything else — including "0", "false", "no", "off", "" and any typo — is False. No clever
    parsing: an ADMIN_PASSWORD_FORCE=0 that force-overwrote an admin password would be a vicious
    surprise, so the rule is a closed allow-list. The CLI imports this helper rather than
    re-parsing the variable, so there is exactly one definition of "force is on".
    """
    return os.getenv("ADMIN_PASSWORD_FORCE", "").strip().lower() in ("1", "true", "yes")


def _classify_legacy_admin(password_hash: str, env_password: str) -> tuple[str, bool]:
    """Decide the provenance of a pre-provenance ('unknown') admin row -- but only once it CAN prove one.

    The migration deliberately cannot do this (it must stay deterministic and env-free), so the
    classification lives here, where bcrypt and the environment are both available.

      1. hash verifies against the built-in default -> "env": the row still holds the bootstrap
         password; there is no operator-chosen password to lose.
      2. ADMIN_PASSWORD is absent (or resolves to the built-in default) and the hash does NOT match
         the default -> stay "unknown". There is nothing in the environment to prove or disprove
         "env" with; classifying "ui" here would be permanent and wrong on the strength of an
         environment that said nothing. A later, informed boot (ADMIN_PASSWORD set to something
         else) can bcrypt-*prove* "env" and classify correctly then.
      3. hash verifies against the current ADMIN_PASSWORD -> "env": the stored password IS the env
         value, so it was seeded from env; re-applying it now is a no-op and future rotation works.
      4. otherwise (ADMIN_PASSWORD IS present and matches neither) -> "ui": an unknown, human-chosen
         password. NEVER touch it.

    Failing to "ui" is the safe direction: env stops governing, no password is lost. Staying
    "unknown" is even safer — it costs nothing (an "unknown" row is never acted upon) and preserves
    the option to classify correctly once the environment actually says something.
    ADMIN_PASSWORD_FORCE is the documented way back for an operator who wanted env management
    after all.

    Note: a legacy admin migrated from users.json is stamped "ui" directly by migration.py, not
    "unknown" — this classifier only ever sees rows backfilled by the Alembic migration. That is
    a deliberate split: JSON-origin rows have no reliable way to distinguish "seeded from env" from
    "operator changed it", so migration.py conservatively calls all of them "ui" up front, and this
    function never runs against them.

    Returns (provenance, hash_matches_env_password). The second element is True only when
    provenance was proven "env" via case 3 above (a direct bcrypt match against `env_password`) —
    the caller can then skip re-running that same verify to decide whether a write is needed.
    """
    from another_s3_manager.auth import verify_password

    if verify_password(DEFAULT_ADMIN_PASSWORD, password_hash):
        return PASSWORD_SET_VIA_ENV, False
    if env_password == DEFAULT_ADMIN_PASSWORD:
        return PASSWORD_SET_VIA_UNKNOWN, False
    if verify_password(env_password, password_hash):
        return PASSWORD_SET_VIA_ENV, True
    return PASSWORD_SET_VIA_UI, False


def sync_admin_password_from_env() -> bool:
    """Apply ADMIN_PASSWORD to the 'admin' user when the environment governs its password.

    Runs once per startup (see main.lifespan). Rules:
      - no 'admin' row -> no-op. Startup never creates or resurrects users; the reset_admin_password
        CLI is the explicit tool for that. (The first-boot seed is lazy — it fires from load_users()
        on the first request, and stamps "env".)
      - ADMIN_PASSWORD unset or equal to the built-in default -> no-op, even under FORCE. Applying it
        would DOWNGRADE a deployed password back to a publicly-known default when someone removes the
        variable from their compose file.
      - ADMIN_PASSWORD_FORCE truthy -> apply the env password regardless of provenance (including
        "ui" and "cli"), reset provenance to "env", and log it LOUDLY. This is the operator's explicit
        escape hatch out of any provenance dead-end; it cannot fire by accident because it needs a
        second, purpose-built variable.
      - provenance "unknown" (row predates this feature) -> classify once IF the environment can
        prove something; otherwise stay "unknown" and let a later, more-informed boot classify.
      - provenance "ui"/"cli" -> the operator set this password deliberately. Never touched.
      - provenance "env" and the env value differs from the stored hash -> apply it, and clear
        must_change_password (the operator chose this password; forcing a change would be hostile).

    "Differs from the stored hash" is one bcrypt verify: when provenance is "env", the stored hash IS
    a salted fingerprint of the last-applied env value, so no separate fingerprint column is needed
    (and storing one would be a second place a password could leak from).

    Deliberately NOT subject to the UI password policy (password_min_length etc.): the seeded admin
    password is already exempt from it, and the built-in "change_me_pls" default would itself fail
    a shipped policy — a bootstrap/sync path must never be able to brick startup by rejecting its
    own input. This also means a policy-violating env password lands with must_change_password
    cleared (no forced change at next login), matching the seed's posture.

    Returns True iff the password was rewritten.
    """
    from another_s3_manager.auth import hash_password, verify_password

    env_password = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    force = _admin_password_force_enabled()

    if force and env_password == DEFAULT_ADMIN_PASSWORD:
        logger.warning(
            "ADMIN_PASSWORD_FORCE is set but ADMIN_PASSWORD is unset (or is the built-in default) — "
            "the force override is IGNORED. Set ADMIN_PASSWORD to the password you want installed."
        )
        force = False

    with session_scope() as session:
        admin = session.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
        if admin is None:
            return False

        if force:
            if verify_password(env_password, admin.password_hash):
                # Already matches — nothing to write. Nag: while FORCE stays set, the environment is
                # authoritative and would revert any password later set through the UI.
                admin.password_set_via = PASSWORD_SET_VIA_ENV
                logger.warning(
                    "ADMIN_PASSWORD_FORCE is still set; the admin password already matches ADMIN_PASSWORD. "
                    "Remove ADMIN_PASSWORD_FORCE — while it is set, the environment overrides any password "
                    "set through the UI on every restart."
                )
                return False
            previous = admin.password_set_via
            admin.password_hash = hash_password(env_password)
            admin.must_change_password = False
            admin.password_set_via = PASSWORD_SET_VIA_ENV
            logger.warning(
                "ADMIN_PASSWORD_FORCE: OVERWROTE the password of user 'admin' with ADMIN_PASSWORD "
                "(previous provenance: %s; provenance reset to 'env'). Remove ADMIN_PASSWORD_FORCE from "
                "the environment — it is a one-shot override, not a mode.",
                previous,
            )
            return True

        already_synced = False
        if admin.password_set_via == PASSWORD_SET_VIA_UNKNOWN:
            classified, hash_matches_env = _classify_legacy_admin(admin.password_hash, env_password)
            if classified == PASSWORD_SET_VIA_ENV:
                admin.password_set_via = classified
                already_synced = hash_matches_env
                logger.info("Admin password provenance recorded as 'env'; ADMIN_PASSWORD governs it on restart.")
            elif classified == PASSWORD_SET_VIA_UI:
                admin.password_set_via = classified
                logger.warning(
                    "Admin password provenance recorded as 'ui' (the stored password is neither the built-in "
                    "default nor the current ADMIN_PASSWORD). ADMIN_PASSWORD is now ignored for this user — "
                    "change the password in the UI, run 'python -m another_s3_manager.reset_admin_password', "
                    "or set ADMIN_PASSWORD_FORCE=1 once to hand the password back to the environment."
                )
            else:
                # ADMIN_PASSWORD said nothing this boot (unset, or the built-in default), so there is
                # nothing to classify WITH. Leave the row 'unknown' and let a later, informed boot
                # decide -- burning the classification now would permanently strand the likely
                # upgrade path (an operator who set ADMIN_PASSWORD long ago, then dropped it from
                # compose because the docs called it first-boot-only). Say so: the row is inert
                # until then, and silence would make that indistinguishable from working.
                logger.info(
                    "Admin password provenance left as 'unknown': ADMIN_PASSWORD is not set, so there is "
                    "nothing to classify it against. ADMIN_PASSWORD does not govern this user yet — set it "
                    "and restart, and a boot that can prove the match will record the provenance."
                )

        if admin.password_set_via != PASSWORD_SET_VIA_ENV:
            # "ui"/"cli" (or "unknown" that just got classified as "ui" above) is silent by
            # design -- but silent forever, with ADMIN_PASSWORD actually set to something real,
            # is exactly what made a JSON-origin admin (migration.py stamps every imported row
            # "ui", including one still on the built-in default) undiagnosable: the operator sets
            # ADMIN_PASSWORD, restarts, sees no error, and concludes rotation is broken.
            #
            # Narrowed to ADMIN_PASSWORD != the built-in default so the common, unremarkable case
            # (no ADMIN_PASSWORD in the compose file at all, admin password changed through the
            # UI) stays quiet on every boot -- that case needs no explanation and would otherwise
            # make this fire for the majority of "ui" deployments.
            if env_password != DEFAULT_ADMIN_PASSWORD and admin.password_set_via in (
                PASSWORD_SET_VIA_UI,
                PASSWORD_SET_VIA_CLI,
            ):
                logger.info(
                    "ADMIN_PASSWORD is set but does not govern the 'admin' password (provenance: %s) -- "
                    "it was set through the UI, the reset CLI, or migrated from a legacy users.json. "
                    "Set ADMIN_PASSWORD_FORCE=1 once to hand it back to the environment.",
                    admin.password_set_via,
                )
            return False
        if env_password == DEFAULT_ADMIN_PASSWORD:
            return False
        if already_synced or verify_password(env_password, admin.password_hash):
            return False  # env value unchanged since it was last applied

        admin.password_hash = hash_password(env_password)
        admin.must_change_password = False
        # Security-relevant event: say WHAT happened, never the password itself.
        logger.warning(
            "Applied ADMIN_PASSWORD from the environment to user 'admin' (password provenance: env). "
            "Change the password in the UI (or via the reset CLI) to make the database authoritative."
        )
        return True


def reset_admin_password(new_password_hash: str) -> str:
    """Break-glass reset of the 'admin' user — used by the reset_admin_password CLI.

    Updates the stored hash in place, or creates the user (is_admin=True, no roles) if it was
    deleted. Stamps password_set_via="cli": the ordinary startup env sync will never overwrite it.
    An operator who just recovered access at the console must not have that undone by the next
    `docker compose up -d` — that restart is inevitable, and clobbering the reset would drop them
    back into the lockout this CLI exists to break. (The one thing that CAN override it is an
    explicit ADMIN_PASSWORD_FORCE — a deliberate human act, not a stale variable.)

    Clears must_change_password: the operator chose this password.

    Takes a HASH — plaintext handling (prompting, policy validation, hashing) is the CLI's job.
    Deliberately does not log: the CLI runs in its own process (docker compose exec), so its
    printed output — not container logs — is the audit surface the operator sees.

    Returns "updated" or "created".
    """
    with session_scope() as session:
        admin = session.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
        if admin is None:
            session.add(
                User(
                    username="admin",
                    password_hash=new_password_hash,
                    is_admin=True,
                    theme="auto",
                    must_change_password=False,
                    password_set_via=PASSWORD_SET_VIA_CLI,
                )
            )
            return "created"
        admin.password_hash = new_password_hash
        admin.must_change_password = False
        admin.password_set_via = PASSWORD_SET_VIA_CLI
        return "updated"


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


def count_users() -> int:
    """Number of registered users. Used by the as3m_users gauge."""
    with session_scope() as session:
        return session.execute(select(func.count(User.id))).scalar_one()


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
                new_hash = user_dict["password_hash"]
                if new_hash != existing.password_hash:
                    # Fail CLOSED. Every dict reaching save_users round-trips through
                    # load_users() -> _user_to_dict(), so it ALWAYS carries a
                    # password_set_via key -- a value that merely survived the
                    # round-trip is not a statement of intent, it's leftover state.
                    # A hash change is the only reliable signal: it means some HTTP
                    # write-site just mutated this dict in place, and every such site
                    # is UI/admin-driven. env/cli provenance is written through their
                    # own sessions (the seed, Task 3's sync, Task 5's CLI), never
                    # through save_users, so this can never wrongly downgrade them.
                    existing.password_set_via = PASSWORD_SET_VIA_UI
                elif "password_set_via" in user_dict:
                    existing.password_set_via = user_dict["password_set_via"]
                existing.password_hash = new_hash
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
                    password_set_via=user_dict.get("password_set_via", PASSWORD_SET_VIA_UI),
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
    password_set_via: str = PASSWORD_SET_VIA_UI,
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
            password_set_via=password_set_via,
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
            # Safety net (fails CLOSED): a password write with no stated provenance is
            # assumed human-driven, so the startup env sync will never overwrite it.
            # Callers that mean something else (the seed, the CLI) pass password_set_via.
            #
            # No standalone `elif "password_set_via" in kwargs` branch here on purpose:
            # a value-only stamp with no accompanying password_hash change has no real
            # caller today, and it would be a dormant fail-open -- a future
            # `update_user(username, **user_dict)` could carry a stale round-tripped
            # "env"/"cli" through it without ever proving a password actually changed.
            # If Task 3/5 need to set provenance without touching the hash, they should
            # write it directly (or extend this call explicitly, not resurrect this elif).
            user.password_set_via = kwargs.get("password_set_via", PASSWORD_SET_VIA_UI)
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
