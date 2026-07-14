"""Break-glass CLI: reset the password of the built-in ``admin`` user.

Usage:
    python -m another_s3_manager.reset_admin_password [NEW_PASSWORD] [--yes]

Docker (interactive — hidden password prompt + confirmation; preferred, because it keeps
the password out of your shell history):
    docker compose exec app python -m another_s3_manager.reset_admin_password

Docker (non-interactive — scripts/CI; -T disables the TTY, so both --yes and the password
argument are required):
    docker compose exec -T app python -m another_s3_manager.reset_admin_password 'NewPassword1' --yes

The reset stamps the password's provenance as "cli", so the ordinary startup ADMIN_PASSWORD
sync will never overwrite it — including on the very next restart. The one exception is an
explicit ADMIN_PASSWORD_FORCE in the environment, which overrides every provenance; if that
variable is set, this command warns that the reset will be reverted on the next restart.

Exit codes: 0 success; 1 error (policy violation, prompt mismatch, operator abort, empty
password, database not initialized); 2 usage (non-interactive session without --yes or
without a password argument).

If your password starts with "-", argparse will treat it as an option and reject it —
pass it after a literal "--" (e.g. `... -- '-Weird1Pass'`), or just use the interactive
prompt, which never parses the password as an argument at all.

This module talks to the operator via print()/getpass on stdout/stderr — a deliberate,
documented exception to the project's "no print(), use logging" backend rule: this is an
interactive terminal tool whose output IS its interface, not server code. It never prints
the password itself.
"""

import argparse
import getpass
import os
import sys
from typing import NoReturn

from sqlalchemy.exc import OperationalError, SQLAlchemyError

from another_s3_manager.constants import DEFAULT_ADMIN_PASSWORD

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _resolve_password(arg_password: str | None) -> str:
    """The positional argument wins; otherwise prompt (TTY only; hidden input, asked twice)."""
    if arg_password is not None:
        return arg_password
    if not sys.stdin.isatty():
        _fail(
            "no password argument and stdin is not a TTY — pass the new password as an argument, e.g. "
            "docker compose exec -T app python -m another_s3_manager.reset_admin_password 'NewPassword1' --yes",
            EXIT_USAGE,
        )
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Repeat new admin password: ")
    if first != second:
        _fail("passwords do not match")
    return first


def _check_policy(password: str) -> None:
    """Enforce the same password policy the UI enforces (main._enforce_password_policy)."""
    from another_s3_manager.config import load_config
    from another_s3_manager.utils import validate_password

    try:
        config = load_config(force_reload=True)
    except Exception as exc:
        # Break-glass tool: an unreadable/corrupt config.json must not block recovery.
        # Only the config load is guarded — validate_password() itself runs unguarded below,
        # so a real bug there still surfaces instead of being downgraded to this warning.
        print(f"warning: could not load the password policy ({exc}); skipping the policy check", file=sys.stderr)
        return
    failures = validate_password(password, config)
    if failures:
        for failure in failures:
            print(f"policy: {failure}", file=sys.stderr)
        _fail("password does not meet the configured policy (see the failures above)")


def _confirm_or_abort(assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        # Never call input() without a TTY — it would block forever under
        # `docker compose exec -T` or in a CI pipeline.
        _fail("refusing to run without confirmation in a non-interactive session — pass --yes", EXIT_USAGE)
    answer = input("Reset the password for user 'admin'? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        _fail("aborted by operator")


def _warn_about_environment() -> None:
    """Tell the operator how the environment will interact with the reset they just made.

    Two cases, both worth saying out loud:
      - ADMIN_PASSWORD_FORCE set: the next restart WILL revert this reset. Loudest warning.
      - ADMIN_PASSWORD set (no FORCE): it is now inert for this user; leaving it in the compose
        file is just confusing.
    The truthiness rule is imported, never re-implemented — one definition of "force is on".
    """
    from another_s3_manager.users import _admin_password_force_enabled

    env_password = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    if env_password == DEFAULT_ADMIN_PASSWORD:
        return
    if _admin_password_force_enabled():
        print(
            "WARNING: ADMIN_PASSWORD_FORCE is set in this environment. On the next restart it will "
            "OVERWRITE the password you just set with ADMIN_PASSWORD. Remove ADMIN_PASSWORD_FORCE from "
            "your compose file before restarting.",
            file=sys.stderr,
        )
        return
    print(
        "note: ADMIN_PASSWORD is set in this environment, but after this reset it will NO LONGER be "
        "applied to user 'admin' (the password is now CLI-managed). Remove it from your compose file "
        "to avoid confusion.",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m another_s3_manager.reset_admin_password",
        description="Reset the password of the built-in 'admin' user (recreates the user if it was deleted).",
        # RawDescriptionHelpFormatter + the module docstring as epilog: --help is the operator's
        # only reference right now (docs land in a later task), so it must be self-sufficient —
        # the Docker invocations, why the interactive form is preferred, and the exit codes all
        # need to show up here, not just in a docstring argparse would otherwise never print.
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("password", nargs="?", default=None, help="new password (omit to be prompted securely)")
    parser.add_argument(
        "-y", "--yes", action="store_true", help="skip the confirmation prompt (required in non-TTY sessions)"
    )
    args = parser.parse_args(argv)

    password = _resolve_password(args.password)
    if not password.strip():
        _fail("password must not be empty or whitespace-only")
    _check_policy(password)
    _confirm_or_abort(args.yes)

    # App imports are deferred so `--help` and usage errors stay instant and DB-free.
    from another_s3_manager.auth import hash_password
    from another_s3_manager.users import reset_admin_password

    try:
        outcome = reset_admin_password(hash_password(password))
    except SQLAlchemyError as exc:
        # SQLAlchemyError is the outer net: a corrupt database file raises DatabaseError (e.g.
        # "database disk image is malformed"), a constraint violation raises IntegrityError — neither
        # is an OperationalError, so both used to escape as a raw traceback. OperationalError with
        # "no such table" is the one case that gets the friendly "not initialized" fix, because the
        # schema genuinely hasn't been migrated yet. Every other error (database is locked because the
        # app container is running, unable to open database file — wrong DATA_DIR or bind-mount
        # permissions, disk I/O error, a corrupt file, ...) must NOT be told "schema is missing" —
        # that sends a locked-out operator chasing the wrong problem. Pass the real error through.
        if isinstance(exc, OperationalError) and "no such table" in str(exc):
            _fail(
                "the database is not initialized (no users table). Start the app once so migrations create "
                "the schema, then re-run this command."
            )
        # exc.orig is the underlying DBAPI exception's message — the part that actually helps
        # diagnose. str(exc) on its own appends "[SQL: ...] [parameters: ...]", and by this point the
        # bound parameters contain the new password's bcrypt HASH (never the plaintext, but still not
        # something that belongs in a tee'd/CI log for no benefit).
        _fail(f"database error: {getattr(exc, 'orig', None) or exc}")

    if outcome == "created":
        print(
            "user 'admin' did not exist — created it with the new password. No restart needed — "
            "log in as 'admin' with it now."
        )
    else:
        print("the password for user 'admin' has been reset. No restart needed — log in as 'admin' with it now.")
    _warn_about_environment()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
