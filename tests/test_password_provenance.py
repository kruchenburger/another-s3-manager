"""Schema, migration backfill, and write-site stamping for User.password_set_via."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

# Pinned revision IDs for migrations/versions/35173f08b83b_add_password_set_via_to_users.py.
# Deliberately NOT "head" / "-1": once another migration lands on top, "head" stops
# meaning "this migration" and "-1" starts stepping back the wrong revision, silently
# defeating the one test that guards the fail-safe backfill. Pinning keeps this test
# tied to exactly the migration it documents, no matter how many migrations follow it.
_THIS_REVISION = "35173f08b83b"
_PARENT_REVISION = "63c8a9adb455"


def _alembic_cfg(db_url: str) -> Config:
    """Same helper shape as tests/test_migrations.py."""
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "migrations"))
    return cfg


def test_orm_model_declares_password_set_via_column():
    """Schema-level check on the ORM model -- NOT the Alembic migration.

    This reads the engine built by conftest.py's `isolated_environment` fixture via
    `Base.metadata.create_all()`, so it only proves `User.password_set_via` exists and
    is NOT NULL on the declarative model in models.py. It says nothing about the
    migration's backfill behavior for pre-existing rows -- that coverage lives in
    `test_migration_backfills_admin_unknown_and_others_ui` below, which actually runs
    the Alembic migration against rows inserted before the column existed.
    """
    from another_s3_manager.database import get_engine

    columns = {c["name"]: c for c in inspect(get_engine()).get_columns("users")}
    assert "password_set_via" in columns, "password_set_via column missing from the ORM model"
    assert columns["password_set_via"]["nullable"] is False, "password_set_via must be NOT NULL"


def test_migration_backfills_admin_unknown_and_others_ui(tmp_path, monkeypatch):
    """THE dangerous case. On upgrade of an existing deployment:
    - the literal 'admin' row must become 'unknown' (classified later, in app code,
      with bcrypt proof)
    - NO row may become 'env' (that would let a stale env var overwrite a live password)
    - every other row becomes 'ui' (env never governs them) -- including the exact
      fail-safe branches a future "improvement" to the backfill (e.g. swapping
      `username <> 'admin'` for `is_admin = 0`) would silently break:
        * a renamed admin (is_admin=1, username no longer literally "admin")
        * a second admin account (another is_admin=1 row alongside "admin")
        * a case variant of the literal username ("Admin")
    - password_hash must survive the migration byte-for-byte -- a backfill that
      mangles it would lock every operator out.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD", "EnvSecret123")  # must NOT influence the migration

    db_path = tmp_path / "another_s3_manager.db"
    if db_path.exists():
        db_path.unlink()
    db_url = f"sqlite:///{db_path}"
    cfg = _alembic_cfg(db_url)

    # Bring the DB to exactly this migration (pinned revision, not "head"), then
    # downgrade to its pinned parent so the users table looks exactly like an
    # existing deployment's (no password_set_via column yet).
    command.upgrade(cfg, _THIS_REVISION)
    engine = create_engine(db_url)
    command.downgrade(cfg, _PARENT_REVISION)

    # username -> (is_admin, password_hash)
    seed_rows = {
        "admin": (1, "legacy-hash-admin"),
        "alice": (0, "legacy-hash-alice"),
        "renamed_admin": (1, "legacy-hash-renamed"),  # is_admin=1, not literally "admin"
        "second_admin": (1, "legacy-hash-second"),  # a second is_admin=1 row alongside "admin"
        "Admin": (1, "legacy-hash-casevariant"),  # case variant -- SQL <> is case-sensitive, no NOCASE collation
    }

    with engine.begin() as conn:
        assert "password_set_via" not in {c["name"] for c in inspect(conn).get_columns("users")}
        for username, (is_admin, password_hash) in seed_rows.items():
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash, is_admin, theme, must_change_password, "
                    "created_at, updated_at) VALUES (:u, :h, :a, 'auto', 0, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"u": username, "h": password_hash, "a": is_admin},
            )

    command.upgrade(cfg, _THIS_REVISION)

    with engine.begin() as conn:
        result = {
            username: (password_set_via, password_hash)
            for username, password_set_via, password_hash in conn.execute(
                text("SELECT username, password_set_via, password_hash FROM users")
            ).all()
        }

    assert result["admin"][0] == "unknown", "admin provenance must be deferred to app-side classification"
    assert result["alice"][0] == "ui", "non-admin rows must be marked do-not-touch"
    assert result["renamed_admin"][0] == "ui", (
        "a renamed admin (is_admin=1, username != 'admin') must fall through to 'ui' -- "
        "env must stop governing it the moment it stops being the literal 'admin' row"
    )
    assert result["second_admin"][0] == "ui", "a second is_admin=1 row must never be classified 'unknown'/'env'"
    assert result["Admin"][0] == "ui", "the backfill's username match is case-sensitive by design ('Admin' != 'admin')"

    provenances = {row[0] for row in result.values()}
    assert "env" not in provenances, "the migration must NEVER backfill 'env' -- it would arm an overwrite"

    for username, (_is_admin, expected_hash) in seed_rows.items():
        assert result[username][1] == expected_hash, f"migration must not mangle password_hash for {username!r}"


def test_user_dict_exposes_password_set_via():
    from another_s3_manager import users
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI

    users.create_user(username="dictguy", password_hash="h", is_admin=False)
    user = users.get_user_by_username("dictguy")
    assert user["password_set_via"] == PASSWORD_SET_VIA_UI
