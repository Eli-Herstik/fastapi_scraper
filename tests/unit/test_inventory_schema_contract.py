"""Drift guard between api/db.py and the vendored contrib/inventory_schema.py.

An identical copy of contrib/inventory_schema.py lives in the gatekeeper-inventory
repo, which reads this database directly. Nothing enforces that copy at runtime, so
this test is the tripwire: it fails here, in the commit that changes the schema,
rather than in production on another machine.

Deliberately in tests/unit and not tests/integration — .gitignore excludes
tests/integration, so a guard placed there would never run in CI. It needs no
database; it compares SQLAlchemy metadata.
"""
from __future__ import annotations

import pytest

from api.db import Base
from contrib.inventory_schema import InventoryBase

FIX_HINT = (
    "If this change is intentional, update contrib/inventory_schema.py AND copy it to "
    "the gatekeeper-inventory repo before deploying that service."
)

VENDORED = InventoryBase.metadata.tables
UPSTREAM = Base.metadata.tables

# (table, column) pairs, so a failure names exactly one column.
VENDORED_COLUMNS = [
    (table_name, column.name)
    for table_name, table in VENDORED.items()
    for column in table.columns
]


def test_vendored_schema_covers_only_the_expected_tables():
    """Guards the narrowness of the contract, not just its correctness.

    If someone widens the vendored copy to include scans or scan_events, the drift
    surface grows silently. Growing it should be a deliberate edit to this list.
    """
    assert set(VENDORED) == {"apps", "submissions", "findings"}, (
        f"contrib/inventory_schema.py should vendor exactly 3 tables; got {sorted(VENDORED)}. "
        "The inventory service reads apps, submissions and findings only."
    )


@pytest.mark.parametrize("table_name", sorted(VENDORED))
def test_vendored_table_exists_upstream(table_name):
    assert table_name in UPSTREAM, (
        f"table {table_name!r} is vendored in contrib/inventory_schema.py but no longer "
        f"exists in api/db.py. {FIX_HINT}"
    )


@pytest.mark.parametrize("table_name,column_name", VENDORED_COLUMNS)
def test_vendored_column_exists_upstream_with_a_compatible_type(table_name, column_name):
    upstream_table = UPSTREAM[table_name]
    assert column_name in upstream_table.columns, (
        f"{table_name}.{column_name} is required by contrib/inventory_schema.py but is "
        f"missing from api/db.py. {FIX_HINT}"
    )

    vendored_col = VENDORED[table_name].columns[column_name]
    upstream_col = upstream_table.columns[column_name]

    # Compare python_type rather than the SQL type class: String -> Text is harmless
    # for a reader, but Boolean -> String or String -> Integer is not.
    assert vendored_col.type.python_type is upstream_col.type.python_type, (
        f"{table_name}.{column_name} changed type: contrib/inventory_schema.py expects "
        f"{vendored_col.type.python_type.__name__}, api/db.py now has "
        f"{upstream_col.type.python_type.__name__}. {FIX_HINT}"
    )


@pytest.mark.parametrize("table_name,column_name", VENDORED_COLUMNS)
def test_upstream_does_not_loosen_nullability(table_name, column_name):
    """A column becoming nullable upstream hands the reader unexpected Nones."""
    upstream_table = UPSTREAM[table_name]
    if column_name not in upstream_table.columns:
        pytest.skip("covered by the column-existence test")

    vendored_col = VENDORED[table_name].columns[column_name]
    upstream_col = upstream_table.columns[column_name]

    if not vendored_col.nullable:
        assert not upstream_col.nullable, (
            f"{table_name}.{column_name} is NOT NULL in contrib/inventory_schema.py but "
            f"is now nullable in api/db.py, so the inventory service would receive "
            f"unexpected NULLs. {FIX_HINT}"
        )


def test_vendored_schema_stays_read_only():
    """The vendored copy must not be able to describe a schema worth creating."""
    for table_name, table in VENDORED.items():
        assert not table.foreign_keys, (
            f"{table_name} declares foreign keys. The vendored schema is read-only and "
            "must not carry FKs, relationships or cascade rules — they only widen the "
            "drift surface and imply DDL the consumer must never perform."
        )


def test_vendored_metadata_is_isolated_from_the_app():
    """InventoryBase must not share MetaData with the app, or alembic would see it."""
    assert InventoryBase.metadata is not Base.metadata, (
        "contrib/inventory_schema.py must declare its own DeclarativeBase. Sharing "
        "api.db.Base would pull these duplicate table definitions into alembic "
        "autogenerate runs."
    )
