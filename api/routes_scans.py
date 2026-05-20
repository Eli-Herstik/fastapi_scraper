import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import AppRow, FindingRow, ApprovalRow, ScanRow
from .models import (
    CreateScanRequest,
    CreateScanResponse,
    CurrentUser,
    Finding,
    PatchFindingRequest,
    ScanDetail,
    ScanSummary,
    Severity,
    SubmitScanResponse,
)
from .security import get_current_user
from .serialize import finding_to_schema, scan_to_detail, scan_to_summary
from .service import run_scrape_job

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(get_current_user)])


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


def _summary_aggregates_subq():
    return (
        select(
            FindingRow.scan_id.label("scan_id"),
            func.count(FindingRow.id).label("finding_count"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (FindingRow.severity == Severity.blocker.value)
                            & (FindingRow.excluded.is_(False)),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("blocker_count"),
            func.count(func.distinct(FindingRow.host)).label("host_count"),
            func.count(func.distinct(FindingRow.auth_method)).label("auth_count"),
        )
        .group_by(FindingRow.scan_id)
        .subquery()
    )


@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(request: Request) -> List[ScanSummary]:
    factory = _session_factory(request)
    async with factory() as session:
        agg = _summary_aggregates_subq()
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0).label("blocker_count"),
                func.coalesce(agg.c.finding_count, 0).label("finding_count"),
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .order_by(ScanRow.started_at.desc())
        )
        result = await session.execute(stmt)
        out: list[ScanSummary] = []
        for scan, blocker_count, finding_count in result.all():
            out.append(
                scan_to_summary(
                    scan,
                    blocker_count=int(blocker_count or 0),
                    finding_count=int(finding_count or 0),
                )
            )
        return out


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, request: Request) -> ScanDetail:
    factory = _session_factory(request)
    async with factory() as session:
        agg = _summary_aggregates_subq()
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.finding_count, 0),
                func.coalesce(agg.c.host_count, 0),
                func.coalesce(agg.c.auth_count, 0),
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .where(ScanRow.id == scan_id)
        )
        row = (await session.execute(stmt)).first()
        if not row:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})
        scan, blocker_count, finding_count, host_count, auth_count = row
        return scan_to_detail(
            scan,
            blocker_count=int(blocker_count or 0),
            finding_count=int(finding_count or 0),
            external_hosts=int(host_count or 0),
            auth_methods=int(auth_count or 0),
        )


@router.get("/scans/{scan_id}/findings", response_model=List[Finding])
async def list_findings(scan_id: str, request: Request) -> List[Finding]:
    factory = _session_factory(request)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})
        rows = (
            await session.execute(
                select(FindingRow).where(FindingRow.scan_id == scan_id).order_by(FindingRow.host)
            )
        ).scalars().all()
        return [finding_to_schema(r) for r in rows]


@router.post("/scans", response_model=CreateScanResponse)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> CreateScanResponse:
    app_state = request.app.state
    factory = _session_factory(request)
    event_bus = app_state.event_bus

    scan_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc)
    name = body.name or body.url
    started_by = current_user.username

    async with factory() as session:
        existing_app = await session.get(AppRow, body.app_id)
        if not existing_app:
            raise HTTPException(status_code=404, detail={"message": "app not found"})
        name = existing_app.name
        session.add(
            ScanRow(
                id=scan_id,
                app_id=body.app_id,
                name=name,
                url=body.url,
                status="queued",
                started_at=started_at,
                started_by=started_by,
                max_depth=body.max_depth,
                pages_crawled=0,
            )
        )
        await session.commit()

    # Persist the seed scan_started event before responding so an immediate SSE
    # GET sees at least one event.
    await event_bus.emit(scan_id, "scan_started", {"url": body.url, "name": name})

    task = asyncio.create_task(
        run_scrape_job(
            scan_id=scan_id,
            base_config=app_state.base_config,
            start_url=body.url,
            max_depth=body.max_depth,
            semaphore=app_state.semaphore,
            session_factory=factory,
            event_bus=event_bus,
        ),
        name=f"scan-{scan_id}",
    )
    app_state.scan_tasks[scan_id] = task
    app_state.background_tasks.add(task)

    def _cleanup(_t: asyncio.Task) -> None:
        app_state.background_tasks.discard(_t)
        app_state.scan_tasks.pop(scan_id, None)

    task.add_done_callback(_cleanup)

    return CreateScanResponse(scan_id=scan_id)


@router.patch("/scans/{scan_id}/findings/{finding_id}", response_model=Finding)
async def patch_finding(
    scan_id: str,
    finding_id: str,
    body: PatchFindingRequest,
    request: Request,
) -> Finding:
    factory = _session_factory(request)
    async with factory() as session:
        finding = await session.get(FindingRow, finding_id)
        if not finding or finding.scan_id != scan_id:
            raise HTTPException(status_code=404, detail={"message": "finding not found"})
        finding.excluded = body.excluded
        if body.justification is not None:
            finding.justification = body.justification
        await session.commit()
        await session.refresh(finding)
        return finding_to_schema(finding)


@router.post("/scans/{scan_id}/submit", response_model=SubmitScanResponse)
async def submit_scan(
    scan_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> SubmitScanResponse:
    factory = _session_factory(request)
    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})

        unresolved_blockers = (
            await session.execute(
                select(func.count())
                .select_from(FindingRow)
                .where(
                    FindingRow.scan_id == scan_id,
                    FindingRow.severity == Severity.blocker.value,
                    FindingRow.excluded.is_(False),
                )
            )
        ).scalar_one()
        if unresolved_blockers:
            raise HTTPException(
                status_code=409,
                detail={"message": f"{unresolved_blockers} unresolved blocker(s) remain"},
            )

        approval_id = "apv_" + uuid.uuid4().hex[:10]
        session.add(
            ApprovalRow(
                id=approval_id,
                scan_id=scan_id,
                submitted_by=current_user.username,
            )
        )
        await session.commit()
        return SubmitScanResponse(approval_id=approval_id)


@router.post("/scans/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(scan_id: str, request: Request) -> Response:
    app_state = request.app.state
    factory = _session_factory(request)

    async with factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"message": "scan not found"})

    task = app_state.scan_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
    else:
        # Task already gone — record a cancellation manually.
        async with factory() as session:
            scan = await session.get(ScanRow, scan_id)
            if scan and scan.status in ("queued", "running"):
                scan.status = "cancelled"
                scan.completed_at = datetime.now(timezone.utc)
                scan.error = "cancelled"
                await session.commit()
        await app_state.event_bus.emit(scan_id, "scan_failed", {"reason": "cancelled"})

    return Response(status_code=status.HTTP_204_NO_CONTENT)
