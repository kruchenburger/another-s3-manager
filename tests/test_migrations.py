from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def _alembic_cfg(db_url: str) -> Config:
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parent.parent / "migrations"),
    )
    return cfg


def test_tour_seen_columns_dropped(tmp_path, monkeypatch):
    """No tour_seen* columns remain on users after migrations run.

    The legacy tour_seen_v1 column was added in 7d34318962ca and dropped
    in 6e601cabdb60 when the onboarding tour feature was removed.
    """
    # env.py overrides sqlalchemy.url with get_db_path() -> DATA_DIR/another_s3_manager.db.
    # Point DATA_DIR at tmp_path; get_db_path() reads DATA_DIR at call time.
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    db_path = tmp_path / "another_s3_manager.db"
    if db_path.exists():
        db_path.unlink()
    db_url = f"sqlite:///{db_path}"

    command.upgrade(_alembic_cfg(db_url), "head")

    engine = create_engine(db_url)
    col_names = {c["name"] for c in inspect(engine).get_columns("users")}
    assert "tour_seen" not in col_names
    assert "tour_seen_v1" not in col_names
    assert "tour_seen_v2" not in col_names


def test_downgrade_recreating_users_preserves_child_rows(tmp_path, monkeypatch):
    """A batch table-recreate on `users` must not cascade-delete its children.

    `35173f08b83b`'s downgrade() drops the `password_set_via` column via
    `batch_alter_table`, which on SQLite has no native ALTER for drop_column and
    is implemented by recreating the whole table: create new `users` -> copy
    rows -> DROP TABLE users -> rename. If FK enforcement were ON during that
    DROP TABLE, every ON DELETE CASCADE pointing at `users` (user_roles, bans,
    api_tokens) would fire and silently wipe those rows, even though the
    migration never touched them. This seeds one row in each child table on a
    populated DB, downgrades one step (triggering that exact recreate), and
    asserts the children survive.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    db_path = tmp_path / "another_s3_manager.db"
    if db_path.exists():
        db_path.unlink()
    db_url = f"sqlite:///{db_path}"
    cfg = _alembic_cfg(db_url)

    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash, is_admin, theme, "
                "must_change_password, password_set_via, created_at, updated_at) "
                "VALUES (1, 'alice', 'hash', 0, 'auto', 0, 'ui', "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP), "
                "(2, 'bob', 'hash', 0, 'auto', 0, 'ui', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        conn.execute(text("INSERT INTO user_roles (user_id, role_name) VALUES (1, 'reader'), (2, 'writer')"))
        conn.execute(
            text(
                "INSERT INTO bans (user_id, banned_until, banned_at, reason, created_at) "
                "VALUES (1, 999999999, 1, 'test ban', CURRENT_TIMESTAMP)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO api_tokens (user_id, token_hash, name, created_at, is_read_only, max_read_bytes) "
                "VALUES (1, 'deadbeef', 'tok', CURRENT_TIMESTAMP, 1, 1024)"
            )
        )
        before_users = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
        before_roles = conn.execute(text("SELECT COUNT(*) FROM user_roles")).scalar_one()
        before_bans = conn.execute(text("SELECT COUNT(*) FROM bans")).scalar_one()
        before_tokens = conn.execute(text("SELECT COUNT(*) FROM api_tokens")).scalar_one()

    assert (before_users, before_roles, before_bans, before_tokens) == (2, 2, 1, 1)

    # Downgrade one step: 35173f08b83b's downgrade() drops password_set_via,
    # forcing SQLite's batch-recreate path on the `users` table.
    command.downgrade(cfg, "-1")

    with engine.connect() as conn:
        after_users = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
        after_roles = conn.execute(text("SELECT COUNT(*) FROM user_roles")).scalar_one()
        after_bans = conn.execute(text("SELECT COUNT(*) FROM bans")).scalar_one()
        after_tokens = conn.execute(text("SELECT COUNT(*) FROM api_tokens")).scalar_one()

    assert after_users == 2, "users should survive the recreate (they're copied)"
    assert after_roles == 2, "user_roles must not be cascade-wiped by the users table recreate"
    assert after_bans == 1, "bans must not be cascade-wiped by the users table recreate"
    assert after_tokens == 1, "api_tokens must not be cascade-wiped by the users table recreate"
