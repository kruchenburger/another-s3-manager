"""Break-glass admin password reset: service function + CLI."""

import sys

import pytest


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


class _FakeNonTtyStdin:
    """Stands in for a non-interactive session (docker compose exec -T, CI): isatty() -> False.

    Used explicitly by the non-TTY tests instead of relying on pytest's own stdin capture
    (which happens to be a non-TTY under the default capture mode, but is the REAL terminal
    — and thus a TTY — under `pytest -s`). Without this explicit monkeypatch, running the
    suite with `-s` would make input()/getpass() block on the real terminal, hanging exactly
    the tests written to prove the CLI can't hang.
    """

    def isatty(self) -> bool:
        return False


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


# --- CLI --------------------------------------------------------------------
# Every non-TTY path below monkeypatches sys.stdin with _FakeNonTtyStdin EXPLICITLY, and this
# must stay that way: pytest's own stdin capture is NOT a reliable source of "not a TTY" — under
# `pytest -s` (capture disabled) sys.stdin IS the real terminal, so relying on it would make the
# very tests written to prove the CLI can't hang, hang instead. The TTY paths monkeypatch
# sys.stdin with _FakeTtyStdin for the same reason: explicit over implicit, either way.


def test_cli_help_is_self_sufficient(capsys):
    """Nothing else pins `formatter_class=RawDescriptionHelpFormatter, epilog=__doc__` on the
    parser — drop either kwarg and the suite stays green, but --help silently regresses to just
    the description + two arg helps. Docs for this tool land in a later task, so --help is the
    operator's only reference right now; assert the things they actually need are in there."""
    from another_s3_manager.reset_admin_password import main

    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "docker compose exec" in out
    assert "Exit codes" in out


def test_cli_resets_with_arg_and_yes(capsys):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    assert main(["NewPassword1", "--yes"]) == 0

    assert verify_password("NewPassword1", _admin()["password_hash"])
    captured = capsys.readouterr()
    assert "reset" in captured.out
    assert "NewPassword1" not in captured.out + captured.err  # never echo the password


def test_cli_warns_when_admin_password_env_is_set(monkeypatch, capsys):
    """The operator must learn that their env var is now inert for this user (plan D4)."""
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setenv("ADMIN_PASSWORD", "StaleEnvPw123")
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)

    assert main(["NewPassword1", "--yes"]) == 0

    err = capsys.readouterr().err
    assert "ADMIN_PASSWORD" in err
    assert "StaleEnvPw123" not in err


def test_cli_warns_loudly_when_force_is_still_set(monkeypatch, capsys):
    """Worst footgun: a CLI reset while ADMIN_PASSWORD_FORCE is set gets reverted on restart."""
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setenv("ADMIN_PASSWORD", "StaleEnvPw123")
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")

    assert main(["NewPassword1", "--yes"]) == 0

    err = capsys.readouterr().err
    assert "ADMIN_PASSWORD_FORCE" in err
    assert "restart" in err.lower()
    assert "StaleEnvPw123" not in err


def test_cli_non_tty_without_yes_exits_2(monkeypatch):
    """docker compose exec -T / CI: input() would block forever — exit(2) instead.

    Explicitly monkeypatches a non-TTY stdin rather than relying on pytest's own capture
    behaviour, so this test still exercises (and pins) the guard under `pytest -s`.
    """
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setattr(sys, "stdin", _FakeNonTtyStdin())

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1"])  # no --yes

    assert exc.value.code == 2
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_non_tty_without_password_exits_2(monkeypatch):
    """Explicit non-TTY stdin — see test_cli_non_tty_without_yes_exits_2 for why."""
    from another_s3_manager.reset_admin_password import main

    monkeypatch.setattr(sys, "stdin", _FakeNonTtyStdin())

    with pytest.raises(SystemExit) as exc:
        main(["--yes"])  # no positional password

    assert exc.value.code == 2


def test_cli_tty_confirmation_no_aborts(monkeypatch):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1"])

    assert exc.value.code == 1
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_tty_confirmation_yes_proceeds(monkeypatch):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")

    assert main(["NewPassword1"]) == 0
    assert verify_password("NewPassword1", _admin()["password_hash"])


def test_cli_prompts_for_password_when_omitted(monkeypatch):
    """Interactive form: hidden getpass prompt — keeps the password out of shell history."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": "NewPassword1")

    assert main(["--yes"]) == 0
    assert verify_password("NewPassword1", _admin()["password_hash"])


def test_cli_password_prompt_mismatch_exits_1(monkeypatch):
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")
    monkeypatch.setattr(sys, "stdin", _FakeTtyStdin())
    prompts = iter(["FirstTry1", "SecondTry2"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": next(prompts))

    with pytest.raises(SystemExit) as exc:
        main(["--yes"])

    assert exc.value.code == 1


def test_cli_enforces_password_policy(capsys):
    """Same policy as the UI (plan D8). Default: min 8 chars, 1 upper, 1 lower, 1 digit."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    with pytest.raises(SystemExit) as exc:
        main(["abc", "--yes"])

    assert exc.value.code == 1
    assert "password_min_length" in capsys.readouterr().err
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_rejects_whitespace_only_password(capsys):
    """Pins the dedicated empty/whitespace guard itself — the default policy (min length 8 +
    upper/lower/digit) also rejects "   ", so an exit-code-only assertion would still pass
    with the guard deleted. Assert the guard's own message to pin the right code path."""
    from another_s3_manager.reset_admin_password import main

    with pytest.raises(SystemExit) as exc:
        main(["   ", "--yes"])

    assert exc.value.code == 1
    assert "empty or whitespace-only" in capsys.readouterr().err


def test_cli_creates_missing_admin(capsys):
    from another_s3_manager.reset_admin_password import main

    assert main(["NewPassword1", "--yes"]) == 0

    assert "created" in capsys.readouterr().out
    assert _admin()["is_admin"] is True


# --- OperationalError handling ------------------------------------------------
# reset_admin_password() is imported inside main() via `from another_s3_manager.users import
# reset_admin_password`, re-reading the current module attribute on every call — so patching
# `another_s3_manager.users.reset_admin_password` here is picked up.


def test_cli_no_such_table_gets_friendly_message(monkeypatch, capsys):
    """Schema genuinely missing (fresh DB, migrations never ran) — the one case that gets the
    "start the app once" advice, because it is actually the right advice here."""
    from sqlalchemy.exc import OperationalError

    from another_s3_manager import users as users_module
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    def _raise(*_args, **_kwargs):
        raise OperationalError("statement", {}, Exception("no such table: users"))

    monkeypatch.setattr(users_module, "reset_admin_password", _raise)

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1", "--yes"])

    assert exc.value.code == 1
    assert "not initialized" in capsys.readouterr().err
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_other_operational_errors_pass_through(monkeypatch, capsys):
    """A locked DB (app container running — WAL contention), a bad DATA_DIR, or a disk I/O error
    must NOT be reported as "schema missing" — that sends a locked-out operator chasing the wrong
    problem. Every OperationalError other than "no such table" must surface its real message."""
    from sqlalchemy.exc import OperationalError

    from another_s3_manager import users as users_module
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    def _raise(*_args, **_kwargs):
        raise OperationalError("statement", {}, Exception("database is locked"))

    monkeypatch.setattr(users_module, "reset_admin_password", _raise)

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1", "--yes"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "database is locked" in err
    assert "not initialized" not in err
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_database_error_gets_clean_message_not_traceback(monkeypatch, capsys):
    """DatabaseError (e.g. a corrupt database file: "database disk image is malformed") is NOT an
    OperationalError. Before the outer SQLAlchemyError net, this escaped main() entirely and dumped
    a raw Python traceback at the operator instead of a clean "database error: ..." line."""
    from sqlalchemy.exc import DatabaseError

    from another_s3_manager import users as users_module
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    def _raise(*_args, **_kwargs):
        raise DatabaseError("statement", {}, Exception("database disk image is malformed"))

    monkeypatch.setattr(users_module, "reset_admin_password", _raise)

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1", "--yes"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "database disk image is malformed" in err
    assert "not initialized" not in err
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_integrity_error_gets_clean_message_not_traceback(monkeypatch, capsys):
    """IntegrityError is also not an OperationalError and used to escape as a raw traceback too."""
    from sqlalchemy.exc import IntegrityError

    from another_s3_manager import users as users_module
    from another_s3_manager.auth import verify_password
    from another_s3_manager.reset_admin_password import main

    _seed_admin("change_me_pls")

    def _raise(*_args, **_kwargs):
        raise IntegrityError("statement", {}, Exception("UNIQUE constraint failed: users.username"))

    monkeypatch.setattr(users_module, "reset_admin_password", _raise)

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1", "--yes"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "UNIQUE constraint failed" in err
    assert verify_password("change_me_pls", _admin()["password_hash"])  # untouched


def test_cli_database_error_message_omits_sql_and_bound_parameters(monkeypatch, capsys):
    """By the time reset_admin_password() runs, the password has been hashed — so the bound
    parameters SQLAlchemy would append via str(exc) (the "[SQL: ...] [parameters: ...]" suffix)
    contain the new password's bcrypt HASH. _fail() must print only exc.orig (the DBAPI message),
    never the full exception string, so that hash never reaches a tee'd/CI log."""
    from sqlalchemy.exc import OperationalError

    from another_s3_manager import users as users_module
    from another_s3_manager.reset_admin_password import main

    def _raise(*_args, **_kwargs):
        raise OperationalError(
            "UPDATE users SET password_hash=:password_hash",
            {"password_hash": "$2b$12$notarealhashvalueusedonlyintests"},
            Exception("database is locked"),
        )

    monkeypatch.setattr(users_module, "reset_admin_password", _raise)

    with pytest.raises(SystemExit) as exc:
        main(["NewPassword1", "--yes"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "database is locked" in err
    assert "notarealhashvalueusedonlyintests" not in err
    assert "[SQL:" not in err
