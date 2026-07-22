"""Sequence allocation must stay correct under concurrent emits.

EventBus used to read MAX(seq)+1 in one session and INSERT in another. SQLite's global
write lock serialized that by accident; Postgres does not, so two concurrent emits for
one scan could claim the same seq and collide on the (scan_id, seq) primary key. The
resulting IntegrityError was uncaught and propagated through the scrape job's on_event
callback, failing the whole scan.

There is a live window for this in production: create_scan emits the seed scan_started
event while the background scrape task it just spawned begins emitting its own.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from api.db import AppRow, ScanEventRow, ScanRow
from api.sse import EventBus

# High enough to defeat a retry-only implementation: with N concurrent allocators each
# retry round yields exactly one winner, so pure retry needs ~N rounds. A bounded retry
# fails here; the advisory lock in EventBus._lock_scan is what makes it pass.
CONCURRENCY = 50


async def _seed_scan(session_factory) -> str:
    app_id = "app_" + uuid.uuid4().hex[:8]
    scan_id = uuid.uuid4().hex
    async with session_factory() as session:
        session.add(
            AppRow(id=app_id, name="Seq Test", url="https://t.invalid", owner_ad_group="g")
        )
        session.add(
            ScanRow(
                id=scan_id,
                app_id=app_id,
                name="Seq Test",
                url="https://t.invalid",
                status="running",
                started_at=datetime.now(timezone.utc),
                started_by="tester",
                pages_crawled=0,
            )
        )
        await session.commit()
    return scan_id


@pytest.mark.asyncio
async def test_concurrent_emits_get_unique_contiguous_seqs(session_factory):
    scan_id = await _seed_scan(session_factory)
    bus = EventBus(session_factory)

    await asyncio.gather(
        *(bus.emit(scan_id, "tick", {"i": i}) for i in range(CONCURRENCY))
    )

    async with session_factory() as session:
        seqs = (
            await session.execute(
                select(ScanEventRow.seq)
                .where(ScanEventRow.scan_id == scan_id)
                .order_by(ScanEventRow.seq)
            )
        ).scalars().all()

    # Every emit persisted exactly once, and the SSE replay ordering stays a dense
    # 0..N-1 range — Last-Event-ID resume depends on there being no gaps.
    assert seqs == list(range(CONCURRENCY)), (
        f"expected contiguous seqs 0..{CONCURRENCY - 1}, got {seqs}"
    )


@pytest.mark.asyncio
async def test_concurrent_emits_across_scans_do_not_interfere(session_factory):
    """seq is per-scan, so two scans emitting at once must each start from 0."""
    scan_a = await _seed_scan(session_factory)
    scan_b = await _seed_scan(session_factory)
    bus = EventBus(session_factory)

    await asyncio.gather(
        *(bus.emit(scan_a, "tick", {"i": i}) for i in range(10)),
        *(bus.emit(scan_b, "tick", {"i": i}) for i in range(10)),
    )

    async with session_factory() as session:
        for scan_id in (scan_a, scan_b):
            seqs = (
                await session.execute(
                    select(ScanEventRow.seq)
                    .where(ScanEventRow.scan_id == scan_id)
                    .order_by(ScanEventRow.seq)
                )
            ).scalars().all()
            assert seqs == list(range(10)), f"scan {scan_id} got {seqs}"


@pytest.mark.asyncio
async def test_explicit_seq_collision_is_not_silently_renumbered(session_factory):
    """A caller-supplied seq that collides is a caller bug — surface it, don't hide it."""
    from sqlalchemy.exc import IntegrityError

    scan_id = await _seed_scan(session_factory)
    bus = EventBus(session_factory)

    await bus.emit(scan_id, "first", {}, seq=7)
    with pytest.raises(IntegrityError):
        await bus.emit(scan_id, "second", {}, seq=7)
