from typing import Dict, List

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .db import FindingRow, ScanRow
from .models import (
    AuthMethod,
    AuthMethodChange,
    ExclusionChange,
    Finding,
    ScanDiff,
    ScanSummary,
    Severity,
)
from .serialize import finding_to_schema, scan_to_summary

router = APIRouter()


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


@router.get("/apps/{app_id}/scans", response_model=List[ScanSummary])
async def list_app_scans(app_id: str, request: Request) -> List[ScanSummary]:
    factory = _session_factory(request)
    async with factory() as session:
        agg = (
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
            )
            .group_by(FindingRow.scan_id)
            .subquery()
        )
        stmt = (
            select(
                ScanRow,
                func.coalesce(agg.c.blocker_count, 0),
                func.coalesce(agg.c.finding_count, 0),
            )
            .outerjoin(agg, agg.c.scan_id == ScanRow.id)
            .where(ScanRow.app_id == app_id)
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


async def _findings_by_host(session, scan_id: str) -> Dict[str, Finding]:
    rows = (
        await session.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
    ).scalars().all()
    return {r.host: finding_to_schema(r) for r in rows}


@router.get("/apps/{app_id}/diff", response_model=ScanDiff)
async def app_diff(
    app_id: str,
    request: Request,
    from_: str | None = None,
    to: str | None = None,
) -> ScanDiff:
    # `from` is reserved in Python, so accept it under an alias.
    qp = request.query_params
    from_id = from_ or qp.get("from") or ""
    to_id = to or qp.get("to") or ""
    if not from_id or not to_id:
        raise HTTPException(status_code=400, detail={"message": "from and to are required"})

    factory = _session_factory(request)
    async with factory() as session:
        for scan_id in (from_id, to_id):
            scan = await session.get(ScanRow, scan_id)
            if not scan or scan.app_id != app_id:
                raise HTTPException(
                    status_code=404,
                    detail={"message": f"scan {scan_id} not found for app {app_id}"},
                )
        a = await _findings_by_host(session, from_id)
        b = await _findings_by_host(session, to_id)

    added: list[Finding] = [f for host, f in b.items() if host not in a]
    removed: list[Finding] = [f for host, f in a.items() if host not in b]
    exclusion_changes: list[ExclusionChange] = []
    auth_method_changes: list[AuthMethodChange] = []
    for host, b_finding in b.items():
        a_finding = a.get(host)
        if not a_finding:
            continue
        if a_finding.excluded != b_finding.excluded:
            exclusion_changes.append(
                ExclusionChange(
                    id=b_finding.id,
                    host=host,
                    before=a_finding.excluded,
                    after=b_finding.excluded,
                )
            )
        if a_finding.auth_method != b_finding.auth_method:
            auth_method_changes.append(
                AuthMethodChange(
                    id=b_finding.id,
                    host=host,
                    before=AuthMethod(a_finding.auth_method),
                    after=AuthMethod(b_finding.auth_method),
                )
            )

    return ScanDiff(
        from_scan_id=from_id,
        to_scan_id=to_id,
        added=added,
        removed=removed,
        exclusion_changes=exclusion_changes,
        auth_method_changes=auth_method_changes,
    )
