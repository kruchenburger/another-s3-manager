"""Alembic environment — uses our app's engine + models."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from another_s3_manager.constants import get_db_path
from another_s3_manager.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Override the URL from alembic.ini with the live app DB path.
config.set_main_option("sqlalchemy.url", f"sqlite:///{get_db_path()}")


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # Explicitly force FK enforcement OFF for the migration connection.
        #
        # render_as_batch=True makes Alembic implement drop_column/alter_column on
        # SQLite by recreating the whole table (create new -> copy rows -> DROP TABLE
        # users -> rename). With FK enforcement ON, that DROP TABLE fires every
        # ON DELETE CASCADE pointing at the recreated table, silently wiping child
        # rows (user_roles/bans/api_tokens on a `users` recreate) even though the
        # migration never intended to touch them.
        #
        # Merely NOT setting "PRAGMA foreign_keys = ON" here is not enough: SQLAlchemy's
        # Engine "connect" event is process-global (another_s3_manager.database registers
        # its pragma listener on the Engine *class*, not one instance), and in production
        # `main.py` imports `users.py` -> `database.py` before running this migration at
        # startup — so by the time this connection is opened, that listener has ALREADY
        # turned FK enforcement ON for it. We must explicitly override it back OFF here,
        # before context.begin_transaction() — PRAGMA foreign_keys is a no-op once a
        # transaction is open and cannot be changed mid-transaction.
        #
        # No migration in versions/ relies on FK enforcement during the run (checked:
        # no ORM cascade, no raw DELETE that depends on a DB-level cascade — the app's
        # own cascades happen at runtime via database.py, not here). Runtime FK
        # enforcement is unaffected by this: it's set independently by the connect-listener
        # in database.py, which every real request/session still goes through.
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        # Safety net: FK enforcement was off for the whole run, so verify no migration
        # introduced a real dangling reference (e.g. a bad manual op.execute).
        # NOTE: this DETECTS, it does not prevent — SQLite here is in
        # non-transactional DDL mode (see the explicit commit below), so a
        # migration's schema changes have already auto-committed by the time this
        # runs. Raising turns silent corruption into a loud deploy-time failure
        # (and withholds the alembic_version stamp, so the run isn't marked done),
        # but it does not roll the damage back. Returns one row per violation.
        violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"Migration left dangling foreign key references: {violations}")
        # SQLAlchemy 2.0 + SQLite (non-transactional DDL): commit explicitly so the
        # alembic_version row written by run_migrations() is persisted to disk.
        # Without this, the schema is created (DDL auto-commits) but the version
        # stamp is lost on connection close, causing subsequent runs to re-apply
        # the same migration and fail with "table already exists".
        connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
