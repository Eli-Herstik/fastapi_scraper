from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScrapeRequest(BaseModel):
    start_url: HttpUrl = Field(..., description="URL to begin the crawl from")
    max_depth: Optional[int] = Field(None, ge=0, description="Override max crawl depth")


class ScrapeResponse(BaseModel):
    start_url: str
    external_hosts: List[dict]


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"


class JobSubmissionResponse(BaseModel):
    job_id: str
    status: JobStatus


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    submitted_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    start_url: str
    result: Optional[ScrapeResponse] = None
    error: Optional[str] = None
