import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from pymongo import ASCENDING, DESCENDING


async def connect_mongo() -> Tuple[AsyncIOMotorClient, AsyncIOMotorCollection]:
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.environ.get("MONGO_DB", "scraper")
    coll_name = os.environ.get("MONGO_JOBS_COLLECTION", "scrape_jobs")
    client = AsyncIOMotorClient(uri)
    collection = client[db_name][coll_name]
    return client, collection


async def ensure_indexes(collection: AsyncIOMotorCollection) -> None:
    await collection.create_index([("status", ASCENDING)])
    await collection.create_index([("submitted_at", DESCENDING)])


async def insert_pending_job(
    collection: AsyncIOMotorCollection,
    *,
    job_id: str,
    start_url: str,
    max_depth: Optional[int],
    submitted_at: datetime,
) -> None:
    await collection.insert_one(
        {
            "_id": job_id,
            "job_id": job_id,
            "status": "pending",
            "start_url": start_url,
            "max_depth": max_depth,
            "submitted_at": submitted_at,
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
        }
    )


async def mark_running(
    collection: AsyncIOMotorCollection, job_id: str, started_at: datetime
) -> None:
    await collection.update_one(
        {"_id": job_id},
        {"$set": {"status": "running", "started_at": started_at}},
    )


async def mark_done(
    collection: AsyncIOMotorCollection,
    job_id: str,
    finished_at: datetime,
    result_dict: Dict[str, Any],
) -> None:
    await collection.update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": "done",
                "finished_at": finished_at,
                "result": result_dict,
            }
        },
    )


async def mark_failed(
    collection: AsyncIOMotorCollection,
    job_id: str,
    finished_at: datetime,
    error_msg: str,
) -> None:
    await collection.update_one(
        {"_id": job_id},
        {
            "$set": {
                "status": "failed",
                "finished_at": finished_at,
                "error": error_msg,
            }
        },
    )


async def get_job(
    collection: AsyncIOMotorCollection, job_id: str
) -> Optional[Dict[str, Any]]:
    return await collection.find_one({"_id": job_id})


async def mark_stale_jobs_failed(
    collection: AsyncIOMotorCollection, reason: str
) -> int:
    result = await collection.update_many(
        {"status": {"$in": ["pending", "running"]}},
        {
            "$set": {
                "status": "failed",
                "error": reason,
                "finished_at": datetime.now(timezone.utc),
            }
        },
    )
    return result.modified_count
