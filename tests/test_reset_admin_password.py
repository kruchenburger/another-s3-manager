"""Break-glass admin password reset: service function + CLI."""

import sys  # noqa: F401 -- used by tests appended in Task 6 (CLI TTY paths)

import pytest  # noqa: F401 -- used by tests appended in Task 6 (pytest.raises(SystemExit))


def _seed_admin(password: str, provenance: str = "env", must_change_password: bool = False) -> None:
    from another_s3_manager.auth import hash_password
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as session:
        session.add(
            User(
                username="admin",
                password_hash=hash_password(password),
                is_admin=True,
                theme="auto",
                must_change_password=must_change_password,
                password_set_via=provenance,
            )
        )


def _admin() -> dict:
    from another_s3_manager.users import get_user_by_username

    user = get_user_by_username("admin")
    assert user is not None
    return user


class _FakeTtyStdin:
    """Stands in for an interactive terminal: isatty() -> True."""

    def isatty(self) -> bool:
        return True


# --- service function -------------------------------------------------------


def test_reset_updates_admin_stamps_cli_and_clears_must_change():
    from another_s3_manager.auth import hash_password, verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI
    from another_s3_manager.users import reset_admin_password

    _seed_admin("OldPassword1", provenance="env", must_change_password=True)

    outcome = reset_admin_password(hash_password("NewPassword1"))

    assert outcome == "updated"
    admin = _admin()
    assert verify_password("NewPassword1", admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_CLI  # a stale env must not clobber it
    assert admin["must_change_password"] is False


def test_reset_creates_admin_when_missing():
    """The CLI is the escape hatch for a deleted admin — startup never resurrects users."""
    from another_s3_manager.auth import hash_password, verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI
    from another_s3_manager.users import reset_admin_password

    outcome = reset_admin_password(hash_password("NewPassword1"))

    assert outcome == "created"
    admin = _admin()
    assert admin["is_admin"] is True
    assert admin["must_change_password"] is False
    assert admin["password_set_via"] == PASSWORD_SET_VIA_CLI
    assert verify_password("NewPassword1", admin["password_hash"])


def test_reset_survives_a_restart_with_a_stale_env(monkeypatch):
    """The point of provenance 'cli': the restart that follows the reset must not undo it.
    (ADMIN_PASSWORD_FORCE is the only thing that may — see tests/test_admin_password_sync.py.)"""
    from another_s3_manager.auth import hash_password, verify_password
    from another_s3_manager.users import reset_admin_password, sync_admin_password_from_env

    _seed_admin("change_me_pls", provenance="env")
    reset_admin_password(hash_password("RecoveredPw1"))

    monkeypatch.setenv("ADMIN_PASSWORD", "StaleEnvPw123")
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
    assert sync_admin_password_from_env() is False
    assert verify_password("RecoveredPw1", _admin()["password_hash"])


def test_reset_leaves_other_users_untouched():
    from another_s3_manager import users
    from another_s3_manager.auth import hash_password, verify_password

    users.create_user(username="bystander", password_hash=hash_password("Bystander1"), is_admin=False)
    _seed_admin("change_me_pls")

    users.reset_admin_password(hash_password("NewPassword1"))

    bystander = users.get_user_by_username("bystander")
    assert bystander is not None
    assert verify_password("Bystander1", bystander["password_hash"])
