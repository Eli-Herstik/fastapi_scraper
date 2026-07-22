"""The inventory service's database role must be able to read, and nothing else.

The inventory service vendors a copy of the ORM (contrib/inventory_schema.py), so a
second codebase holds SQLAlchemy models of these tables and could in principle write to
them or call create_all(). scripts/inventory_reader_role.sql is what makes that
impossible; this test asserts the grants in that file actually produce the intended
boundary, rather than trusting that they do.

Mirrors scripts/inventory_reader_role.sql — if you change the grants there, change them
here.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine

# Distinct from the production role name so a real inventory_reader is never touched.
ROLE = "inventory_reader_test"
PASSWORD = "test-only-password"

READABLE = ["apps", "submissions", "findings"]
FORBIDDEN = ["scans", "scan_events"]


@pytest_asyncio.fixture
async def reader_url(migrated_database_url):
    """Create the role with the documented grants; yield a URL that logs in as it."""
    url = make_url(migrated_database_url)
    admin = create_async_engine(migrated_database_url, future=True, isolation_level="AUTOCOMMIT")

    async def _drop_role(conn):
        """DROP OWNED must precede DROP ROLE, but errors if the role doesn't exist."""
        exists = (
            await conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": ROLE})
        ).scalar()
        if exists:
            await conn.execute(text(f"DROP OWNED BY {ROLE} CASCADE"))
            await conn.execute(text(f"DROP ROLE {ROLE}"))

    # Roles are cluster-wide, so a previous crashed run may have left one behind.
    async with admin.connect() as conn:
        await _drop_role(conn)
        await conn.execute(text(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PASSWORD}'"))
        await conn.execute(text(f'GRANT CONNECT ON DATABASE "{url.database}" TO {ROLE}'))
        await conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {ROLE}"))
        await conn.execute(text(f"GRANT SELECT ON {', '.join(READABLE)} TO {ROLE}"))
        await conn.execute(text(f"REVOKE CREATE ON SCHEMA public FROM {ROLE}"))

    yield url.set(username=ROLE, password=PASSWORD).render_as_string(hide_password=False)

    async with admin.connect() as conn:
        await _drop_role(conn)
    await admin.dispose()


@pytest_asyncio.fixture
async def reader_engine(reader_url):
    engine = create_async_engine(reader_url, future=True)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", READABLE)
async def test_reader_can_select_the_tables_it_needs(reader_engine, table):
    async with reader_engine.connect() as conn:
        await conn.execute(text(f"SELECT * FROM {table} LIMIT 1"))


@pytest.mark.asyncio
@pytest.mark.parametrize("table", FORBIDDEN)
async def test_reader_cannot_read_tables_outside_its_contract(reader_engine, table):
    async with reader_engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await conn.execute(text(f"SELECT * FROM {table} LIMIT 1"))


@pytest.mark.asyncio
@pytest.mark.parametrize("statement", [
    "INSERT INTO apps (id, name, owner_ad_group, created_at) "
    "VALUES ('x', 'x', 'x', now())",
    "UPDATE findings SET excluded = true",
    "DELETE FROM submissions",
])
async def test_reader_cannot_write(reader_engine, statement):
    async with reader_engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await conn.execute(text(statement))


@pytest.mark.asyncio
async def test_reader_cannot_create_schema(reader_engine):
    """The failure mode this role exists to prevent: a stray create_all() downstream."""
    async with reader_engine.connect() as conn:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await conn.execute(text("CREATE TABLE should_not_exist (id text primary key)"))
