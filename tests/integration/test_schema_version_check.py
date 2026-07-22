"""init_db() must refuse to start the app against a schema it doesn't expect.

The app no longer calls create_all() — migrations own the schema, because a second
service (the inventory API) reads these tables from its own repo. That makes "did anyone
actually run the migration?" a question worth answering loudly at boot rather than
discovering through a confusing runtime error later.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from api.db import init_db


@pytest.mark.asyncio
async def test_init_db_accepts_a_migrated_database(migrated_database_url):
    engine = create_async_engine(migrated_database_url, future=True)
    try:
        await init_db(engine)  # must not raise
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_init_db_rejects_an_unmigrated_database(migrated_database_url):
    """A database with no schema at all — the "forgot to migrate" case."""
    url = make_url(migrated_database_url)
    scratch = f"gk_empty_{uuid.uuid4().hex[:8]}"

    admin = create_async_engine(migrated_database_url, future=True, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{scratch}"'))

    engine = create_async_engine(url.set(database=scratch).render_as_string(hide_password=False))
    try:
        with pytest.raises(RuntimeError, match="no alembic_version table"):
            await init_db(engine)
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE "{scratch}"'))
        await admin.dispose()


@pytest.mark.asyncio
async def test_init_db_rejects_a_stale_revision(migrated_database_url):
    """Schema present but behind (or ahead of) the code."""
    engine = create_async_engine(migrated_database_url, future=True, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        real = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        await conn.execute(text("UPDATE alembic_version SET version_num = 'stale0000000'"))
    try:
        with pytest.raises(RuntimeError, match="Database is at migration stale0000000"):
            await init_db(engine)
    finally:
        async with engine.connect() as conn:
            await conn.execute(
                text("UPDATE alembic_version SET version_num = :v"), {"v": real}
            )
        await engine.dispose()
