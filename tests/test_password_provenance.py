"""Schema, migration backfill, and write-site stamping for User.password_set_via."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def _alembic_cfg(db_url: str) -> Config:
    """Same helper shape as tests/test_migrations.py."""
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "migrations"))
    return cfg


def test_users_table_has_password_set_via_column():
    from another_s3_manager.database import get_engine

    columns = {c["name"]: c for c in inspect(get_engine()).get_columns("users")}
    assert "password_set_via" in columns, "password_set_via column missing"
    assert columns["password_set_via"]["nullable"] is False, "password_set_via must be NOT NULL"


def test_migration_backfills_admin_unknown_and_others_ui(tmp_path, monkeypatch):
    """THE dangerous case. On upgrade of an existing deployment:
    - the admin row must become 'unknown' (classified later, in app code, with bcrypt proof)
    - NO row may become 'env' (that would let a stale env var overwrite a live password)
    - every non-admin row becomes 'ui' (env never governs them)
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD", "EnvSecret123")  # must NOT influence the migration

    db_path = tmp_path / "another_s3_manager.db"
    if db_path.exists():
        db_path.unlink()
    db_url = f"sqlite:///{db_path}"
    cfg = _alembic_cfg(db_url)

    # Bring the DB to head, then step back one revision so the users table looks
    # exactly like an existing deployment's (no password_set_via column yet).
    command.upgrade(cfg, "head")
    engine = create_engine(db_url)
    command.downgrade(cfg, "-1")

    with engine.begin() as conn:
        assert "password_set_via" not in {c["name"] for c in inspect(conn).get_columns("users")}
        for username, is_admin in (("admin", 1), ("alice", 0)):
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash, is_admin, theme, must_change_password, "
                    "created_at, updated_at) VALUES (:u, 'legacy-hash', :a, 'auto', 0, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"u": username, "a": is_admin},
            )

    command.upgrade(cfg, "head")

    with engine.begin() as conn:
        rows = dict(conn.execute(text("SELECT username, password_set_via FROM users")).all())

    assert rows["admin"] == "unknown", "admin provenance must be deferred to app-side classification"
    assert rows["alice"] == "ui", "non-admin rows must be marked do-not-touch"
    assert "env" not in rows.values(), "the migration must NEVER backfill 'env' — it would arm an overwrite"


def test_user_dict_exposes_password_set_via():
    from another_s3_manager import users
    from another_s3_manager.constants import PASSWORD_SET_VIA_UI

    users.create_user(username="dictguy", password_hash="h", is_admin=False)
    user = users.get_user_by_username("dictguy")
    assert user["password_set_via"] == PASSWORD_SET_VIA_UI
