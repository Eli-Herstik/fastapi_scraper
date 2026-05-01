import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status

from config_loader import load_config

from .db import (
    connect_mongo,
    ensure_indexes,
    get_job,
    insert_pending_job,
    mark_stale_jobs_failed,
)
from .models import (
    JobStatus,
    JobStatusResponse,
    JobSubmissionResponse,
    ScrapeRequest,
)
from .service import run_scrape_job

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Single-worker deployment assumed: background scrape tasks run in-process,
    # and orphaned pending/running rows are swept to "failed" at startup.
    config_path = os.environ.get("SCRAPER_CONFIG_PATH", "./config.json")
    app.state.base_config = load_config(config_path)
    max_parallel = int(os.environ.get("SCRAPER_MAX_PARALLEL", "2"))
    app.state.semaphore = asyncio.Semaphore(max_parallel)

    client, collection = await connect_mongo()
    app.state.mongo_client = client
    app.state.jobs_collection = collection
    await ensure_indexes(collection)

    stale = await mark_stale_jobs_failed(collection, reason="server restarted")
    if stale:
        logger.warning("Marked %d stale jobs as failed (server restarted)", stale)

    app.state.background_tasks: set[asyncio.Task] = set()

    logger.info(
        "Loaded base config from %s (max_parallel=%d)", config_path, max_parallel
    )
    try:
        yield
    finally:
        tasks = list(app.state.background_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        client.close()


app = FastAPI(
    title="Hosts Scraper API",
    description="Submit a start_url to crawl a site and collect external hosts.",
    version="1.0.0",
    lifespan=lifespan,
)


def _doc_to_status(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "job_id": doc["job_id"],
        "status": doc["status"],
        "submitted_at": doc["submitted_at"],
        "started_at": doc.get("started_at"),
        "finished_at": doc.get("finished_at"),
        "start_url": doc["start_url"],
        "result": doc.get("result"),
        "error": doc.get("error"),
    }


@app.post(
    "/scrape",
    response_model=JobSubmissionResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def scrape(
    request: ScrapeRequest, http_request: Request
) -> JobSubmissionResponse:
    app_state = http_request.app.state
    job_id = uuid.uuid4().hex
    submitted_at = datetime.now(timezone.utc)

    await insert_pending_job(
        app_state.jobs_collection,
        job_id=job_id,
        start_url=str(request.start_url),
        max_depth=request.max_depth,
        submitted_at=submitted_at,
    )

    task = asyncio.create_task(
        run_scrape_job(
            job_id=job_id,
            base_config=app_state.base_config,
            request=request,
            semaphore=app_state.semaphore,
            collection=app_state.jobs_collection,
        ),
        name=f"scrape-{job_id}",
    )
    app_state.background_tasks.add(task)
    task.add_done_callback(app_state.background_tasks.discard)

    return JobSubmissionResponse(job_id=job_id, status=JobStatus.pending)


@app.get("/scrape/{job_id}", response_model=JobStatusResponse)
async def get_scrape(job_id: str, http_request: Request) -> JobStatusResponse:
    doc = await get_job(http_request.app.state.jobs_collection, job_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="job not found")
    return JobStatusResponse(**_doc_to_status(doc))


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
