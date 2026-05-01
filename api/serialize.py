"""Helpers that turn ORM rows into the shapes the frontend expects."""
from datetime import datetime, timezone
from typing import Iterable

from .db import FindingRow, ScanRow
from .models import (
    AuthMethod,
    Finding,
    FindingEvidence,
    ScanDetail,
    ScanSummary,
    Severity,
)


def _isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def finding_to_schema(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        host=row.host,
        auth_method=AuthMethod(row.auth_method),
        severity=Severity(row.severity),
        request_count=row.request_count,
        first_seen_on_page=row.first_seen_on_page,
        evidence=FindingEvidence(
            headers_snippet=row.headers_snippet,
            status_code=row.status_code,
        ),
        excluded=row.excluded,
    )


def findings_to_schemas(rows: Iterable[FindingRow]) -> list[Finding]:
    return [finding_to_schema(r) for r in rows]


def scan_to_summary(
    scan: ScanRow,
    *,
    blocker_count: int,
    finding_count: int,
) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        app_id=scan.app_id,
        name=scan.name,
        url=scan.url,
        status=scan.status,
        started_at=_isoformat(scan.started_at) or "",
        completed_at=_isoformat(scan.completed_at),
        started_by=scan.started_by,
        blocker_count=blocker_count,
        finding_count=finding_count,
    )


def scan_to_detail(
    scan: ScanRow,
    *,
    blocker_count: int,
    finding_count: int,
    external_hosts: int,
    auth_methods: int,
) -> ScanDetail:
    duration_ms: int | None = None
    if scan.completed_at and scan.started_at:
        duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)
    return ScanDetail(
        id=scan.id,
        app_id=scan.app_id,
        name=scan.name,
        url=scan.url,
        status=scan.status,
        started_at=_isoformat(scan.started_at) or "",
        completed_at=_isoformat(scan.completed_at),
        started_by=scan.started_by,
        blocker_count=blocker_count,
        finding_count=finding_count,
        duration_ms=duration_ms,
        pages_crawled=scan.pages_crawled,
        external_hosts=external_hosts,
        auth_methods_identified=auth_methods,
    )
