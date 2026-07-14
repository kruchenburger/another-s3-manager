"""ADMIN_PASSWORD startup sync: env governs 'env' rows, never touches 'ui'/'cli' rows,
legacy 'unknown' rows are classified exactly once, and ADMIN_PASSWORD_FORCE overrides
everything (loudly)."""

import logging

import pytest

ENV_PASSWORD = "EnvSecret123"
ROTATED_PASSWORD = "RotatedSecret456"


def _seed_admin(password: str, provenance: str, must_change_password: bool = False) -> None:
    """Insert the 'admin' row directly with an explicit provenance."""
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


def _seed_bystander(username: str, password: str, provenance: str) -> None:
    """Insert a non-admin user row -- used to pin that the sync's WHERE username == 'admin'
    filter really does leave every other row alone."""
    from another_s3_manager.auth import hash_password
    from another_s3_manager.database import session_scope
    from another_s3_manager.models import User

    with session_scope() as session:
        session.add(
            User(
                username=username,
                password_hash=hash_password(password),
                is_admin=False,
                theme="auto",
                must_change_password=False,
                password_set_via=provenance,
            )
        )


def _admin() -> dict:
    from another_s3_manager.users import get_user_by_username

    user = get_user_by_username("admin")
    assert user is not None
    return user


def _user(username: str) -> dict:
    from another_s3_manager.users import get_user_by_username

    user = get_user_by_username(username)
    assert user is not None
    return user


# --- provenance "env": env governs -----------------------------------------


def test_env_rotation_applies(monkeypatch, caplog):
    """THE case the provenance model exists for: ADMIN_PASSWORD foo -> bar rotates the password."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin(ENV_PASSWORD, PASSWORD_SET_VIA_ENV)  # previously applied from env
    _seed_bystander("alice", "AliceSecret1", PASSWORD_SET_VIA_UI)
    alice_hash_before = _user("alice")["password_hash"]
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)

    with caplog.at_level(logging.WARNING):
        applied = sync_admin_password_from_env()

    assert applied is True
    assert verify_password(ROTATED_PASSWORD, _admin()["password_hash"])
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_ENV  # still env-governed
    assert any("ADMIN_PASSWORD" in r.message for r in caplog.records)
    assert ROTATED_PASSWORD not in caplog.text  # never log the password
    # The destructive write must be scoped to 'admin' -- the bystander is untouched.
    alice = _user("alice")
    assert alice["password_hash"] == alice_hash_before
    assert alice["password_set_via"] == PASSWORD_SET_VIA_UI


def test_env_unchanged_is_a_noop(monkeypatch):
    """The stored hash already verifies against the env value -> no write, no churn.

    Asserts byte-for-byte hash equality, not just the return value -- an implementation that
    pointlessly re-hashed the password (new salt) and returned False would still pass a
    return-value-only assertion.
    """
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin(ENV_PASSWORD, PASSWORD_SET_VIA_ENV)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    hash_before = _admin()["password_hash"]

    assert sync_admin_password_from_env() is False
    assert _admin()["password_hash"] == hash_before


def test_default_password_row_gets_env_applied(monkeypatch):
    """Fresh deploy: seeded with the default, operator then sets ADMIN_PASSWORD and restarts."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("change_me_pls", PASSWORD_SET_VIA_ENV)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is True
    assert verify_password(ENV_PASSWORD, _admin()["password_hash"])


def test_env_unset_never_downgrades_to_default(monkeypatch):
    """Removing ADMIN_PASSWORD from the environment must NOT reset the password to change_me_pls."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin(ENV_PASSWORD, PASSWORD_SET_VIA_ENV)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)  # conftest sets it; remove it

    assert sync_admin_password_from_env() is False
    assert verify_password(ENV_PASSWORD, _admin()["password_hash"])


def test_env_set_to_the_literal_default_is_a_noop(monkeypatch):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin(ENV_PASSWORD, PASSWORD_SET_VIA_ENV)
    monkeypatch.setenv("ADMIN_PASSWORD", "change_me_pls")

    assert sync_admin_password_from_env() is False
    assert verify_password(ENV_PASSWORD, _admin()["password_hash"])


def test_apply_clears_must_change_password(monkeypatch):
    """The operator chose this password — don't force a change on first login (plan D7)."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("change_me_pls", PASSWORD_SET_VIA_ENV, must_change_password=True)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is True
    assert _admin()["must_change_password"] is False


# --- provenance "ui" / "cli": terminal for the ORDINARY sync -----------------


def test_ui_password_is_never_overwritten(monkeypatch):
    """THE operator-protecting branch: a UI-set password survives any env value."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI, must_change_password=True)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is False
    admin = _admin()
    assert verify_password("OperatorChose1", admin["password_hash"])
    assert not verify_password(ENV_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_UI
    assert admin["must_change_password"] is True  # nothing on the row was touched


def test_cli_password_is_never_overwritten(monkeypatch):
    """A restart right after a break-glass reset must not clobber the reset (plan D4)."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("RecoveredPw1", PASSWORD_SET_VIA_CLI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is False
    assert verify_password("RecoveredPw1", _admin()["password_hash"])


# --- diagnosability: INFO log when ADMIN_PASSWORD is set but doesn't govern -


def test_ui_password_with_real_env_password_logs_info(monkeypatch, caplog):
    """The undiagnosable case a JSON-origin admin (migration.py stamps every imported row 'ui')
    used to hit silently: ADMIN_PASSWORD is set to something real, but this admin's password is
    'ui'-governed, so nothing ever happens and nothing was ever said. Must now log at INFO."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    with caplog.at_level(logging.INFO):
        assert sync_admin_password_from_env() is False

    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    assert any("does not govern" in r.message for r in info_records)
    assert ENV_PASSWORD not in caplog.text  # never the password


def test_cli_password_with_real_env_password_logs_info(monkeypatch, caplog):
    """Same diagnosability for 'cli' provenance -- a break-glass reset is just as silent today."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("RecoveredPw1", PASSWORD_SET_VIA_CLI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    with caplog.at_level(logging.INFO):
        assert sync_admin_password_from_env() is False

    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    assert any("does not govern" in r.message for r in info_records)


def test_ui_password_with_default_env_stays_silent(monkeypatch, caplog):
    """The common, unremarkable case (no ADMIN_PASSWORD in the compose file, admin password
    changed through the UI) must NOT log at INFO on every boot -- narrowing to
    ADMIN_PASSWORD != default is what keeps this from being noisy for the majority of 'ui'
    deployments."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)  # conftest sets it; remove it

    with caplog.at_level(logging.INFO):
        assert sync_admin_password_from_env() is False

    assert not any("does not govern" in r.message for r in caplog.records)


# --- provenance "unknown": one-time legacy classification --------------------


def test_unknown_still_on_default_becomes_env_and_gets_env_applied(monkeypatch):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UNKNOWN
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("change_me_pls", PASSWORD_SET_VIA_UNKNOWN)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV
    assert verify_password(ENV_PASSWORD, admin["password_hash"])


def test_unknown_matching_current_env_becomes_env_without_a_write(monkeypatch):
    """Legacy deploy seeded from ADMIN_PASSWORD: stored == env -> it was env-driven."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UNKNOWN
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin(ENV_PASSWORD, PASSWORD_SET_VIA_UNKNOWN)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    hash_before = _admin()["password_hash"]

    assert sync_admin_password_from_env() is False  # nothing to apply
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_ENV  # but now env-governed
    # "without a write" is in the name, so pin it: bcrypt is salted, so a pointless re-hash
    # would produce a different string while still returning False and still reading 'env'.
    assert _admin()["password_hash"] == hash_before, "the sync must not re-hash an already-synced password"


def test_unknown_with_a_human_password_becomes_ui_and_is_untouched(monkeypatch, caplog):
    """THE upgrade-safety case: a live operator's password must survive the upgrade boot."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI, PASSWORD_SET_VIA_UNKNOWN
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("HumanChose99", PASSWORD_SET_VIA_UNKNOWN)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    with caplog.at_level(logging.WARNING):
        assert sync_admin_password_from_env() is False

    admin = _admin()
    assert admin["password_set_via"] == PASSWORD_SET_VIA_UI
    assert verify_password("HumanChose99", admin["password_hash"])
    assert not verify_password(ENV_PASSWORD, admin["password_hash"])
    # The operator must be able to see in the logs that env no longer governs this user.
    assert any("ignored" in r.message.lower() for r in caplog.records)


def test_classification_is_persisted_and_not_repeated(monkeypatch):
    """The second boot must not re-classify (and must not re-run bcrypt against the default)."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI, PASSWORD_SET_VIA_UNKNOWN
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("HumanChose99", PASSWORD_SET_VIA_UNKNOWN)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    sync_admin_password_from_env()
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_UI

    assert sync_admin_password_from_env() is False
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_UI


def test_uninformative_boot_does_not_burn_the_classification(monkeypatch):
    """An upgrade boot with NO ADMIN_PASSWORD must not permanently stamp 'ui' on a legacy admin
    whose password happens not to be the default -- the environment said nothing, so there is
    nothing to classify WITH. A later, informed boot must still be able to prove 'env' and, from
    there, rotate. This is the likely upgrade order: ADMIN_PASSWORD dropped from compose long ago
    (docs describe it as first-boot-only), then re-added later expecting rotation to work."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UNKNOWN
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("SeededLongAgo1", PASSWORD_SET_VIA_UNKNOWN)

    # Boot 1: ADMIN_PASSWORD is absent. Nothing in the environment can prove or disprove "env"
    # against this non-default hash -- the row must stay "unknown", not be locked to "ui".
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    assert sync_admin_password_from_env() is False
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_UNKNOWN

    # Boot 2: operator adds ADMIN_PASSWORD matching the stored password. Now the environment can
    # prove "env" (a direct bcrypt match) -- classify, no write needed yet (already matches).
    monkeypatch.setenv("ADMIN_PASSWORD", "SeededLongAgo1")
    assert sync_admin_password_from_env() is False
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_ENV

    # Boot 3: operator rotates ADMIN_PASSWORD. Because the row is now genuinely "env"-governed,
    # rotation fires -- the whole point of not having burned the classification in boot 1.
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)
    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert verify_password(ROTATED_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


# --- missing admin ----------------------------------------------------------


def test_noop_when_admin_user_missing(monkeypatch):
    """Startup never creates or resurrects users — the CLI is the escape hatch."""
    from another_s3_manager.users import get_user_by_username, sync_admin_password_from_env

    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    assert sync_admin_password_from_env() is False
    assert get_user_by_username("admin") is None


# ---------------------------------------------------------------------------
# ADMIN_PASSWORD_FORCE — the explicit escape hatch (plan D10).
# Overrides EVERY provenance, including "cli". Must be impossible to trigger by
# accident, and must be loud when it fires.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "Yes", " yes "])
def test_force_truthy_values_overwrite_a_ui_password(monkeypatch, truthy):
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", truthy)

    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert verify_password(ENV_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV  # provenance handed back to env
    assert admin["must_change_password"] is False


def test_force_overwrites_a_cli_password(monkeypatch):
    """FORCE beats 'cli' too (plan D10): an escape hatch with a carve-out is not an escape hatch."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI, PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("RecoveredPw1", PASSWORD_SET_VIA_CLI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")

    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert verify_password(ENV_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "", "  ", "yep"])
def test_force_falsy_values_do_not_overwrite(monkeypatch, falsy):
    """ADMIN_PASSWORD_FORCE=0 must NOT force anything. Anything outside {1,true,yes} is false."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", falsy)

    assert sync_admin_password_from_env() is False
    admin = _admin()
    assert verify_password("OperatorChose1", admin["password_hash"])
    assert not verify_password(ENV_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_UI


def test_force_without_admin_password_is_a_noop(monkeypatch, caplog):
    """FORCE can never install the built-in default password (plan D3) — and says why."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")

    with caplog.at_level(logging.WARNING):
        assert sync_admin_password_from_env() is False

    admin = _admin()
    assert verify_password("OperatorChose1", admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_UI
    assert any("ADMIN_PASSWORD_FORCE" in r.message and "ignored" in r.message.lower() for r in caplog.records)


def test_force_recovers_the_rotated_before_upgrade_deadend(monkeypatch):
    """R1: a legacy deploy that rotated ADMIN_PASSWORD before upgrading classifies as 'ui'
    and loses env management. FORCE is the documented way back."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("SeededLongAgo1", "unknown")
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)

    # Upgrade boot: classified 'ui' (the stored password is neither the default nor the env value).
    assert sync_admin_password_from_env() is False
    assert _admin()["password_set_via"] == PASSWORD_SET_VIA_UI

    # Operator adds ADMIN_PASSWORD_FORCE=1 and restarts.
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")
    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert verify_password(ROTATED_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


def test_force_is_not_sticky_and_nags_while_it_stays_set(monkeypatch, caplog):
    """Once applied, a still-set FORCE changes nothing on later boots (env == stored), but it
    keeps warning that it should be removed — and removing it leaves the row env-managed."""
    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("OperatorChose1", PASSWORD_SET_VIA_UI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")
    assert sync_admin_password_from_env() is True

    # Boot 2 — FORCE still set, env unchanged: no write, but a nag.
    with caplog.at_level(logging.WARNING):
        assert sync_admin_password_from_env() is False
    assert any("ADMIN_PASSWORD_FORCE" in r.message and "remove" in r.message.lower() for r in caplog.records)

    # Boot 3 — FORCE removed: the row is plain env-managed, so rotation still works.
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)
    assert sync_admin_password_from_env() is True
    admin = _admin()
    assert verify_password(ROTATED_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


def test_force_logs_loudly_and_never_logs_the_password(monkeypatch, caplog):
    """The most destructive thing this feature can do must be reconstructable from the logs."""
    from another_s3_manager.constants import PASSWORD_SET_VIA_CLI
    from another_s3_manager.users import sync_admin_password_from_env

    _seed_admin("RecoveredPw1", PASSWORD_SET_VIA_CLI)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "true")

    with caplog.at_level(logging.WARNING):
        assert sync_admin_password_from_env() is True

    forced = [r for r in caplog.records if "ADMIN_PASSWORD_FORCE" in r.message]
    assert forced, "the forced overwrite must be logged"
    record = forced[0]
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert "admin" in message  # names the user
    assert "cli" in message  # names the provenance it overrode
    assert "env" in message  # says provenance is reset to env
    assert ENV_PASSWORD not in caplog.text  # never the password


# ---------------------------------------------------------------------------
# Startup integration. The sync must run inside the real startup sequence, after
# alembic + the legacy JSON migration -- so these drive main.run_startup_tasks(),
# the actual startup routine, not sync_admin_password_from_env() in isolation.
#
# Why not through the real FastAPI lifespan / TestClient: `lifespan` also enters
# FastMCP's session manager, whose .run() is a hard once-per-INSTANCE guard in the
# mcp SDK (not once-at-a-time -- once, ever), and the FastMCP instance is a
# module-level singleton in mcp_server.py that the suite deliberately never reloads
# (see the comment in tests/test_mcp_protocol.py). So exactly ONE test in the whole
# process may boot the real lifespan; it already exists
# (test_main.py::test_startup_runs_migrations_and_json_import), and
# test_main.py::test_lifespan_runs_startup_tasks_then_enters_mcp pins that `lifespan`
# really does call run_startup_tasks(). Multi-boot scenarios live here.
#
# Reload pattern mirrors test_main.py::test_startup_runs_migrations_and_json_import:
# point DATA_DIR at a FRESH empty dir (so `alembic upgrade head` builds the schema
# itself rather than colliding with conftest's create_all), then reload
# constants -> database -> users -> main so every module binds the new engine.
# ---------------------------------------------------------------------------


def _fresh_main(monkeypatch, tmp_path):
    import importlib

    import another_s3_manager.constants as constants
    import another_s3_manager.database as database
    import another_s3_manager.main as main
    import another_s3_manager.users as users

    data_dir = tmp_path / "startup-data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")

    importlib.reload(constants)
    importlib.reload(database)
    importlib.reload(users)
    database.reset_engine_for_tests()
    return importlib.reload(main)


def test_startup_seed_then_rotate_then_ui_wins(monkeypatch, tmp_path):
    """Three boots end-to-end:
    1. fresh DB, ADMIN_PASSWORD=foo  -> seeded from env
    2. ADMIN_PASSWORD=bar, restart   -> ROTATED (the fix this feature exists for)
    3. admin changes the password in the UI, restart with a stale env -> UI password survives
    """
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
    main = _fresh_main(monkeypatch, tmp_path)

    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    main.run_startup_tasks()

    from another_s3_manager.auth import verify_password
    from another_s3_manager.users import get_user_by_username, load_users

    load_users()  # trigger the lazy seed, as the first real request would

    assert verify_password(ENV_PASSWORD, get_user_by_username("admin")["password_hash"])

    # Boot 2 — rotation.
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)
    main.run_startup_tasks()
    assert verify_password(ROTATED_PASSWORD, get_user_by_username("admin")["password_hash"])

    # Admin changes the password through the UI (same call path as PUT /api/me/password).
    from another_s3_manager.auth import hash_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI
    from another_s3_manager.users import update_user

    update_user("admin", password_hash=hash_password("UiChosen456"), password_set_via=PASSWORD_SET_VIA_UI)

    # Boot 3 — the stale env var must not win.
    monkeypatch.setenv("ADMIN_PASSWORD", "YetAnother789")
    main.run_startup_tasks()
    admin = get_user_by_username("admin")
    assert verify_password("UiChosen456", admin["password_hash"])
    assert not verify_password("YetAnother789", admin["password_hash"])


def test_startup_force_overrides_a_ui_password(monkeypatch, tmp_path):
    """The FORCE escape hatch, driven through the real startup sequence."""
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
    main = _fresh_main(monkeypatch, tmp_path)

    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    main.run_startup_tasks()

    from another_s3_manager.auth import hash_password, verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV, PASSWORD_SET_VIA_UI
    from another_s3_manager.users import get_user_by_username, load_users, update_user

    load_users()

    update_user("admin", password_hash=hash_password("UiChosen456"), password_set_via=PASSWORD_SET_VIA_UI)

    # Operator adds ADMIN_PASSWORD_FORCE=1 and restarts.
    monkeypatch.setenv("ADMIN_PASSWORD", ROTATED_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD_FORCE", "1")
    main.run_startup_tasks()

    admin = get_user_by_username("admin")
    assert verify_password(ROTATED_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


def test_startup_on_a_fresh_db_is_a_clean_noop(monkeypatch, tmp_path, caplog):
    """The admin seed is LAZY (it fires from load_users(), not at startup). So on a genuinely
    fresh DB the sync runs against a users table with no admin row and must no-op quietly --
    and must NOT create the user itself. The seed then stamps 'env' on first use.

    Also pins step ORDERING: the sync must run after the alembic migration that adds the
    `password_set_via` column. Because a failing sync is swallowed (warn-and-continue), a
    misordering wouldn't raise here -- it would just make the sync blow up with
    OperationalError (no `users` table yet) and log the failure warning. Asserting that
    warning is absent is what turns "ran after alembic" from a comment into a real check:
    hoist `sync_admin_password_from_env()` above the alembic step and this assertion fails.
    """
    monkeypatch.delenv("ADMIN_PASSWORD_FORCE", raising=False)
    main = _fresh_main(monkeypatch, tmp_path)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)

    with caplog.at_level(logging.WARNING):
        main.run_startup_tasks()  # no admin row exists yet

    assert not any("ADMIN_PASSWORD startup sync failed" in r.message for r in caplog.records), (
        "sync must run AFTER the alembic migration; a failure here means it ran too early"
    )

    from another_s3_manager.auth import verify_password
    from another_s3_manager.constants import PASSWORD_SET_VIA_ENV
    from another_s3_manager.users import get_user_by_username, load_users

    assert get_user_by_username("admin") is None, "startup must not create the admin user"

    load_users()  # the lazy seed fires here, as it would on the first request
    admin = get_user_by_username("admin")
    assert verify_password(ENV_PASSWORD, admin["password_hash"])
    assert admin["password_set_via"] == PASSWORD_SET_VIA_ENV


def test_startup_default_env_still_warns(monkeypatch, tmp_path, caplog):
    """Regression guard: the pre-existing default-password warning keeps firing (plan D3)."""
    main = _fresh_main(monkeypatch, tmp_path)
    monkeypatch.setenv("ADMIN_PASSWORD", "change_me_pls")

    with caplog.at_level(logging.WARNING):
        main.run_startup_tasks()

    assert any("ADMIN_PASSWORD is the default" in r.message for r in caplog.records)


def test_startup_survives_sync_failure(monkeypatch, tmp_path, caplog, mocker):
    """A broken sync must not brick startup — warn and continue (retried next boot)."""
    main = _fresh_main(monkeypatch, tmp_path)
    monkeypatch.setenv("ADMIN_PASSWORD", ENV_PASSWORD)
    mocker.patch.object(main, "sync_admin_password_from_env", side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.WARNING):
        main.run_startup_tasks()  # returning normally means startup completed

    assert any("sync failed" in r.message for r in caplog.records)
