"""SSE event bus: per-subscriber queues, durable replay via scan_events."""
import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import ScanEventRow

logger = logging.getLogger(__name__)

# Backstop only. Allocation is serialized by an advisory lock (see _lock_scan), so a
# collision should be unreachable; this bounds the damage if one happens anyway rather
# than spinning forever. Note retry alone is NOT sufficient at scale: with N concurrent
# emits each round produces exactly one winner, so pure retry needs up to N rounds.
_MAX_SEQ_ATTEMPTS = 5


class EventBus:
    """A registry of per-scan subscribers. Producers fan out to live queues
    while persisting every event for durable resume."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._notification_subscribers: Set[asyncio.Queue] = set()
        self._session_factory = session_factory
        self._lock = asyncio.Lock()

    def subscribers_for(self, scan_id: str) -> Set[asyncio.Queue]:
        return self._subscribers.setdefault(scan_id, set())

    async def subscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            self.subscribers_for(scan_id).add(queue)

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subscribers.get(scan_id)
            if subs and queue in subs:
                subs.discard(queue)
                if not subs:
                    self._subscribers.pop(scan_id, None)

    async def subscribe_notifications(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._notification_subscribers.add(queue)

    async def unsubscribe_notifications(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._notification_subscribers.discard(queue)

    async def next_seq(self, scan_id: str) -> int:
        """The seq an event for this scan would get right now.

        Advisory only — the value can be stale the moment it's returned. Real
        allocation happens inside _persist's transaction, which is what makes it safe.
        """
        async with self._session_factory() as session:
            return await self._peek_seq(session, scan_id)

    @staticmethod
    async def _lock_scan(session: AsyncSession, scan_id: str) -> None:
        """Serialize seq allocation for a single scan, for the life of the transaction.

        A transaction-scoped advisory lock, released automatically on commit or
        rollback. Two emits for the same scan queue instead of colliding, which makes
        the read-then-insert below effectively atomic.

        Different scan_ids may occasionally share a hashtext() value and serialize
        against each other — harmless, since emits are cheap and per-scan traffic is low.
        """
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:scan_id))"),
            {"scan_id": scan_id},
        )

    @staticmethod
    async def _peek_seq(session: AsyncSession, scan_id: str) -> int:
        result = await session.execute(
            select(func.coalesce(func.max(ScanEventRow.seq), -1)).where(
                ScanEventRow.scan_id == scan_id
            )
        )
        return int(result.scalar_one()) + 1

    async def _persist(
        self,
        scan_id: str,
        event_type: str,
        payload: Dict[str, Any],
        ts: int,
        seq: Optional[int],
    ) -> int:
        """Allocate a seq and insert the event in one transaction. Returns the seq used.

        Allocating in a separate transaction from the insert (as this used to) races:
        two concurrent emits for one scan read the same MAX(seq) and both try to claim
        it. SQLite's global write lock used to hide this; Postgres does not, and a
        25-way concurrent emit lost 19 of 25 events to IntegrityErrors that propagated
        out of the scrape job's on_event callback and failed the scan.

        _lock_scan serializes allocation so collisions don't occur; the (scan_id, seq)
        primary key plus the retry below is a backstop, not the mechanism.
        """
        explicit = seq is not None
        last_error: IntegrityError | None = None

        for _ in range(_MAX_SEQ_ATTEMPTS):
            async with self._session_factory() as session:
                try:
                    if not explicit:
                        await self._lock_scan(session, scan_id)
                    resolved = seq if explicit else await self._peek_seq(session, scan_id)
                    session.add(
                        ScanEventRow(
                            scan_id=scan_id,
                            seq=resolved,
                            ts=ts,
                            type=event_type,
                            payload=payload,
                        )
                    )
                    await session.commit()
                    return resolved
                except IntegrityError as e:
                    await session.rollback()
                    # A caller-supplied seq that collides is a bug in the caller —
                    # silently renumbering it would hide the problem.
                    if explicit:
                        raise
                    last_error = e

        raise RuntimeError(
            f"could not allocate a seq for scan {scan_id} after {_MAX_SEQ_ATTEMPTS} attempts"
        ) from last_error

    async def emit(
        self,
        scan_id: str,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        seq: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Persist + fan out an event. Returns the event dict.

        Fan-out is best-effort: full subscriber queues drop and log."""
        ts = int(time.time() * 1000)
        payload = payload or {}
        seq = await self._persist(scan_id, event_type, payload, ts, seq)

        event = {
            "scan_id": scan_id,
            "seq": str(seq),
            "ts": ts,
            "type": event_type,
            "payload": payload,
        }

        for queue in list(self._subscribers.get(scan_id, set())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("SSE subscriber queue full for scan %s; dropping event", scan_id)

        if event_type in ("scan_completed", "scan_failed"):
            for queue in list(self._notification_subscribers):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Notification queue full; dropping event for scan %s", scan_id)
        return event


async def replay_events(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    start_seq: int,
):
    async with session_factory() as session:
        stmt = (
            select(ScanEventRow)
            .where(ScanEventRow.scan_id == scan_id, ScanEventRow.seq >= start_seq)
            .order_by(ScanEventRow.seq.asc())
        )
        result = await session.execute(stmt)
        return [row for row in result.scalars()]
