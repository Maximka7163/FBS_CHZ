from __future__ import annotations

from logging.config import fileConfig
import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import make_url

from wbcz_web.models import Base


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _migration_database_url() -> str:
    raw = (
        os.getenv("WBCZ_MIGRATION_DATABASE_URL", "").strip()
        or os.getenv("WBCZ_DATABASE_URL", "").strip()
    )
    if not raw:
        raise RuntimeError("WBCZ_MIGRATION_DATABASE_URL or WBCZ_DATABASE_URL is required for Alembic")
    url = make_url(raw)
    if url.get_backend_name() != "postgresql":
        raise ValueError("Alembic migrations require PostgreSQL")
    return raw


config.set_main_option("sqlalchemy.url", _migration_database_url().replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
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
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
