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
        url=url, target_metadata=target_metadata, literal_binds=True,
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
        # Enable FKs for SQLite
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
