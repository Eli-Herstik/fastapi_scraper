import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, Optional

if TYPE_CHECKING:
    from alembic.config import Config

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AppRow(Base):
    __tablename__ = "apps"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    owner_ad_group: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Canonical "current version" — the scan that was most recently submitted for
    # this app. Sticky: stays set across subsequent unsubmitted scans, only moves
    # when another scan is submitted. Nullable for apps that have never had a
    # submission. use_alter avoids the apps<->scans circular FK on create_all.
    current_scan_id: Mapped[Optional[str]] = mapped_column(
        String,
        ForeignKey(
            "scans.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_apps_current_scan_id",
        ),
        nullable=True,
    )


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    app_id: Mapped[str] = mapped_column(
        String, ForeignKey("apps.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_by: Mapped[str] = mapped_column(String, nullable=False)
    max_depth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    findings: Mapped[list["FindingRow"]] = relationship(
        "FindingRow", back_populates="scan", cascade="all, delete-orphan"
    )
    submissions: Mapped[list["SubmissionRow"]] = relationship(
        "SubmissionRow", back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEventRow"]] = relationship(
        "ScanEventRow", back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host: Mapped[str] = mapped_column(String, nullable=False)
    auth_method: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen_on_page: Mapped[str] = mapped_column(String, default="", nullable=False)
    headers_snippet: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="findings")


class SubmissionRow(Base):
    __tablename__ = "submissions"
    __table_args__ = (
        # A scan can be submitted at most once. The `already_submitted` check in
        # routes_scans.submit_scan is single-transaction; the unique constraint
        # is what actually wins under concurrent submits — the loser hits an
        # IntegrityError and we translate it to a 409.
        UniqueConstraint("scan_id", name="uq_submissions_scan_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    submitted_by: Mapped[str] = mapped_column(String, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="submissions")


class ScanEventRow(Base):
    __tablename__ = "scan_events"
    # (scan_id, seq) is the composite primary key below, which already enforces
    # uniqueness — a separate UniqueConstraint over the same columns used to be
    # declared here and was pure redundancy. On Postgres it also made autogenerate
    # report a permanent phantom diff, which would have silently defeated the
    # "autogenerate must be empty" drift check.
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Epoch MILLISECONDS (int(time.time() * 1000) in EventBus.emit) — ~1.8e12, which
    # overflows a 32-bit INTEGER. Must stay BigInteger.
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="events")


def _database_url() -> str:
    """The Postgres URL, from DATABASE_URL.

    No default. The inventory service reads this same database from a separate host,
    which is only possible on Postgres — and a silent fallback to a local file would
    let the server come up healthy against the wrong (empty) database.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Example: "
            "postgresql+asyncpg://postgres:postgres@localhost:5432/gatekeeper"
        )
    return url


def make_engine() -> AsyncEngine:
    return create_async_engine(_database_url(), future=True)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _alembic_config() -> "Config":
    from alembic.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    return cfg


async def init_db(engine: AsyncEngine) -> None:
    """Assert the database is migrated to head. Never creates or alters schema.

    Migrations own the schema now, because a second service (the inventory API) reads
    these tables from its own repo. If the app were still calling create_all() it could
    silently materialize a schema that disagrees with the migration history, and the
    two codebases would drift apart with nothing to catch it.
    """
    from alembic.migration import MigrationContext
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()

    def _current_revision(sync_conn) -> Optional[str]:
        return MigrationContext.configure(sync_conn).get_current_revision()

    async with engine.connect() as conn:
        current = await conn.run_sync(_current_revision)

    if current == head:
        return
    if current is None:
        raise RuntimeError(
            "Database has no schema (no alembic_version table). "
            "Run 'alembic upgrade head' before starting the server."
        )
    raise RuntimeError(
        f"Database is at migration {current}, but the code expects {head}. "
        "Run 'alembic upgrade head' before starting the server."
    )


async def sweep_stale_scans(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """Mark any scans left in queued/running by a previous process as failed."""
    async with session_factory() as session:
        stmt = (
            update(ScanRow)
            .where(ScanRow.status.in_(["queued", "running"]))
            .values(status="failed", completed_at=_utcnow(), error="server restarted")
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount or 0


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session
