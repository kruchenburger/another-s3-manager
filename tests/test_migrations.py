from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


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
