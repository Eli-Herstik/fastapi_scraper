import asyncio
import copy
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_loader import Config
from scraper import Mapper

from .config_hunter_runner import run_config_hunter
from .db import FindingRow, ScanRow
from .models import Severity
from .sse import EventBus
from .translate import hosts_to_findings

logger = logging.getLogger(__name__)


def build_request_config(base: Config, *, start_url: str, max_depth: int | None) -> Config:
    cfg = copy.deepcopy(base)
    cfg.start_url = start_url
    if max_depth is not None:
        cfg.max_depth = max_depth
    return cfg


async def _set_status(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    **values: Any,
) -> None:
    async with session_factory() as session:
        await session.execute(update(ScanRow).where(ScanRow.id == scan_id).values(**values))
        await session.commit()


async def _persist_findings(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    rows: list[Dict[str, Any]],
) -> None:
    if not rows:
        return
    async with session_factory() as session:
        for r in rows:
            session.add(FindingRow(**r))
        await session.commit()


async def _run_mapper(mapper: Mapper) -> Dict[str, Any]:
    await mapper.initialize()
    try:
        return await mapper.map_website()
    finally:
        await mapper.cleanup()


def _merge_host_entries(
    scraper_hosts: list[Dict[str, Any]],
    ch_hosts: list[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    """Union by host. Scraper wins on auth fields (live request evidence);
    request_counts sum; first_seen_on_page keeps scraper's value if present,
    else falls back to config_hunter's `config:<origin>` marker."""
    merged: dict[str, Dict[str, Any]] = {}
    for h in scraper_hosts:
        host = h.get("host") or ""
        if not host:
            continue
        merged[host] = dict(h)
    for h in ch_hosts:
        host = h.get("host") or ""
        if not host:
            continue
        existing = merged.get(host)
        if existing is None:
            merged[host] = dict(h)
            continue
        existing["request_count"] = (
            int(existing.get("request_count", 0) or 0)
            + int(h.get("request_count", 0) or 0)
        )
        if not existing.get("first_seen_on_page"):
            existing["first_seen_on_page"] = h.get("first_seen_on_page", "") or ""
    return list(merged.values())


async def run_scrape_job(
    *,
    scan_id: str,
    base_config: Config,
    start_url: str,
    max_depth: int | None,
    semaphore: asyncio.Semaphore,
    session_factory: async_sessionmaker[AsyncSession],
    event_bus: EventBus,
) -> None:
    """Background task: acquire semaphore, run scrape, persist outcome.

    Must not raise — all exceptions are recorded as failed.
    """
    async with semaphore:
        started_at = datetime.now(timezone.utc)
        started_ms = int(time.time() * 1000)
        await _set_status(session_factory, scan_id, status="running", started_at=started_at)

        config = build_request_config(base_config, start_url=start_url, max_depth=max_depth)

        async def on_event(event_type: str, payload: Dict[str, Any]) -> None:
            await event_bus.emit(scan_id, event_type, payload)

        mapper = Mapper(config, on_event=on_event)
        try:
            scraper_result, ch_result = await asyncio.gather(
                _run_mapper(mapper),
                run_config_hunter(start_url, on_event=on_event),
                return_exceptions=True,
            )

            scraper_hosts: list[Dict[str, Any]] = []
            pages_crawled = 0
            if isinstance(scraper_result, asyncio.CancelledError):
                raise scraper_result
            if isinstance(scraper_result, BaseException):
                logger.exception(
                    "Scraper failed for scan %s", scan_id, exc_info=scraper_result
                )
                await event_bus.emit(scan_id, "scraper_failed", {
                    "error": f"{scraper_result.__class__.__name__}: {scraper_result}",
                })
            else:
                scraper_hosts = scraper_result.get("external_hosts", []) or []
                pages_crawled = int(scraper_result.get("pages_crawled", 0) or 0)

            ch_hosts: list[Dict[str, Any]] = []
            if isinstance(ch_result, asyncio.CancelledError):
                raise ch_result
            if isinstance(ch_result, BaseException):
                logger.exception(
                    "config_hunter failed for scan %s", scan_id, exc_info=ch_result
                )
                await event_bus.emit(scan_id, "config_hunter_failed", {
                    "error": f"{ch_result.__class__.__name__}: {ch_result}",
                })
            else:
                ch_hosts = ch_result or []

            if isinstance(scraper_result, BaseException) and isinstance(ch_result, BaseException):
                raise scraper_result

            merged_hosts = _merge_host_entries(scraper_hosts, ch_hosts)
            finding_rows = hosts_to_findings(scan_id, merged_hosts)
            await _persist_findings(session_factory, scan_id, finding_rows)

            blockers = sum(1 for r in finding_rows if r["severity"] == Severity.blocker.value)
            for r in finding_rows:
                if r["severity"] == Severity.blocker.value:
                    await event_bus.emit(scan_id, "blocker_found", {
                        "host": r["host"],
                        "auth_method": r["auth_method"],
                    })

            completed_at = datetime.now(timezone.utc)
            duration_ms = int(time.time() * 1000) - started_ms
            await _set_status(
                session_factory,
                scan_id,
                status="completed",
                completed_at=completed_at,
                pages_crawled=pages_crawled,
            )
            await event_bus.emit(scan_id, "scan_completed", {
                "duration_ms": duration_ms,
                "findings": len(finding_rows),
                "blockers": blockers,
            })

        except asyncio.CancelledError:
            cancel_at = datetime.now(timezone.utc)
            await _set_status(
                session_factory,
                scan_id,
                status="cancelled",
                completed_at=cancel_at,
                error="cancelled",
            )
            await event_bus.emit(scan_id, "scan_failed", {"reason": "cancelled"})
            raise

        except Exception as e:
            logger.exception("Scrape failed for scan %s (%s)", scan_id, start_url)
            failed_at = datetime.now(timezone.utc)
            err_msg = f"{e.__class__.__name__}: {e}"
            await _set_status(
                session_factory,
                scan_id,
                status="failed",
                completed_at=failed_at,
                error=err_msg,
            )
            await event_bus.emit(scan_id, "scan_failed", {"error": err_msg})
