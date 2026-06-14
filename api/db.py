import os
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from sqlalchemy import (
    JSON,
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


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
    approvals: Mapped[list["ApprovalRow"]] = relationship(
        "ApprovalRow", back_populates="scan", cascade="all, delete-orphan"
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
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="findings")


class ApprovalRow(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    submitted_by: Mapped[str] = mapped_column(String, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="approvals")


class ScanEventRow(Base):
    __tablename__ = "scan_events"
    __table_args__ = (
        UniqueConstraint("scan_id", "seq", name="uq_scan_events_scan_seq"),
    )

    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    scan: Mapped[ScanRow] = relationship("ScanRow", back_populates="events")


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is required "
            "(example: postgresql+asyncpg://user:pass@host:5432/scraper)"
        )
    return url


def make_engine() -> AsyncEngine:
    return create_async_engine(
        _database_url(),
        future=True,
        # Validate each pooled connection before use. Idle connections get
        # silently dropped in OpenShift (Postgres idle timeout, SDN/router, or
        # an intervening proxy), which otherwise surfaces as asyncpg
        # "connection is closed" on the next request.
        pool_pre_ping=True,
        # Proactively retire connections before they hit the server/proxy idle
        # cutoff. 300s is comfortably below typical timeouts.
        pool_recycle=300,
    )


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


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
