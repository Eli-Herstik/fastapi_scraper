import asyncio
import copy
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from motor.motor_asyncio import AsyncIOMotorCollection

from config_loader import Config
from scraper import Mapper

from .db import mark_done, mark_failed, mark_running
from .models import ScrapeRequest

logger = logging.getLogger(__name__)


def build_request_config(base: Config, request: ScrapeRequest) -> Config:
    cfg = copy.deepcopy(base)
    cfg.start_url = str(request.start_url)
    if request.max_depth is not None:
        cfg.max_depth = request.max_depth
    return cfg


async def run_scrape(base_config: Config, request: ScrapeRequest) -> Dict[str, Any]:
    config = build_request_config(base_config, request)
    mapper = Mapper(config)
    try:
        await mapper.initialize()
        result = await mapper.map_website()
    finally:
        await mapper.cleanup()

    return {
        "start_url": config.start_url,
        "external_hosts": result.get("external_hosts", []),
    }


async def run_scrape_job(
    *,
    job_id: str,
    base_config: Config,
    request: ScrapeRequest,
    semaphore: asyncio.Semaphore,
    collection: AsyncIOMotorCollection,
) -> None:
    """Background task: acquire semaphore, run scrape, persist outcome.

    Must not raise — all exceptions are recorded as failed.
    """
    async with semaphore:
        await mark_running(collection, job_id, datetime.now(timezone.utc))
        try:
            result = await run_scrape(base_config, request)
            await mark_done(collection, job_id, datetime.now(timezone.utc), result)
        except asyncio.CancelledError:
            await mark_failed(
                collection, job_id, datetime.now(timezone.utc), "task cancelled"
            )
            raise
        except Exception as e:
            logger.exception("Scrape failed for job %s (%s)", job_id, request.start_url)
            await mark_failed(
                collection,
                job_id,
                datetime.now(timezone.utc),
                f"{e.__class__.__name__}: {e}",
            )
