"""Read-only schema for the inventory service. VENDORED — keep the copies in sync.

An identical copy of this file lives in the gatekeeper-inventory repo. This is the
canonical version: edit it here, then copy it there. Nothing in this app imports it at
runtime; it exists so that drift is caught in the repo where schema changes actually
happen, by tests/integration/test_inventory_schema_contract.py.

Deliberately narrow. The inventory service reads 3 tables and 12 columns, and never
touches `scans` or `scan_events` at all. Everything not needed for those reads is
omitted, which is what keeps the drift surface small.

Read-only by construction:
  - No ForeignKeys. They exist for DDL and integrity enforcement, neither of which a
    read-only consumer performs, and omitting them means this module cannot describe a
    schema worth creating.
  - No relationships, no cascade rules, no defaults.
  - Its own DeclarativeBase, NOT api.db.Base, so these tables can never be swept into
    this app's metadata or into an alembic autogenerate run.
  - The consuming service must never call create_all() or run migrations. It connects
    as the `inventory_reader` role, which has SELECT and nothing else.

Column names and types are the entire contract.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class InventoryBase(DeclarativeBase):
    pass


class App(InventoryBase):
    __tablename__ = "apps"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    owner_ad_group: Mapped[str] = mapped_column(String, nullable=False)
    # The app's approved scan. Set only on a successful submit, and sticky — it stays
    # put across later unsubmitted scans. NULL means the app has never been submitted,
    # which is how the inventory service decides what to list.
    current_scan_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Submission(InventoryBase):
    __tablename__ = "submissions"

    # Not read by the inventory service, but SQLAlchemy requires a mapped primary key.
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    submitted_by: Mapped[str] = mapped_column(String, nullable=False)


class Finding(InventoryBase):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    # Findings dismissed during review. Excluded rows are not part of the approved
    # service inventory and must be filtered out of both endpoints.
    excluded: Mapped[bool] = mapped_column(Boolean, nullable=False)
