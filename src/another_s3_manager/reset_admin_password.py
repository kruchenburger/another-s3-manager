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

from sqlalchemy.exc import OperationalError

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
    try:
        from another_s3_manager.config import load_config
        from another_s3_manager.utils import validate_password

        failures = validate_password(password, load_config(force_reload=True))
    except Exception as exc:
        # Break-glass tool: an unreadable/corrupt config.json must not block recovery.
        print(f"warning: could not load the password policy ({exc}); skipping the policy check", file=sys.stderr)
        return
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
    except OperationalError:
        _fail(
            "the database is not initialized (no users table). Start the app once so migrations create "
            "the schema, then re-run this command."
        )

    if outcome == "created":
        print("user 'admin' did not exist — created it with the new password.")
    else:
        print("the password for user 'admin' has been reset.")
    _warn_about_environment()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
