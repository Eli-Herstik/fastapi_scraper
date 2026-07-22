import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Alembic runs this file directly, so the repo root isn't on sys.path yet.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.db import Base, _database_url  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# The URL lives in the environment, not alembic.ini, so migrations and the app share
# one source of truth (api.db._database_url). escape % so ConfigParser doesn't try to
# interpolate it out of a password.
config.set_main_option("sqlalchemy.url", _database_url().replace("%", "%%"))


def _configure_kwargs(**extra) -> dict:
    return dict(
        target_metadata=target_metadata,
        # Without this, autogenerate silently ignores column type changes — which is
        # exactly the drift the inventory service would trip over.
        compare_type=True,
        compare_server_default=True,
        **extra,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **_configure_kwargs(),
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, **_configure_kwargs())
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
