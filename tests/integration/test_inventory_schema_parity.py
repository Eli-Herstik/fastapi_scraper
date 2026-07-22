"""The vendored schema must produce the same answers as the live endpoints.

tests/unit/test_inventory_schema_contract.py checks that the columns still exist and
still have compatible types. That is necessary but not sufficient: a column can survive
a refactor while its *meaning* shifts. This test pins the semantics instead — it writes
through the app's own ORM (api.db) and reads back through the vendored models
(contrib.inventory_schema), then asserts the results match the endpoints that the
inventory service is replacing.

Those endpoints stay in this repo until the inventory service is live, which is what
makes them usable here as the reference implementation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from api.db import AppRow, FindingRow, ScanRow, SubmissionRow
from contrib.inventory_schema import App, Finding, Submission


async def _seed(session_factory, *, app_id, findings, submitted=True, offset=0):
    """Write a submitted app + scan + findings using the app's real ORM."""
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc) - timedelta(seconds=offset)
    async with session_factory() as session:
        session.add(AppRow(id=app_id, name=f"App {app_id}", url="https://t.invalid",
                           owner_ad_group="grp"))
        session.add(ScanRow(id=scan_id, app_id=app_id, name=f"App {app_id}",
                            url="https://t.invalid", status="completed", started_at=started,
                            completed_at=started, started_by="tester", pages_crawled=1))
        for host, auth, excluded in findings:
            session.add(FindingRow(id="f_" + uuid.uuid4().hex[:8], scan_id=scan_id, host=host,
                                   auth_method=auth, severity="cleared", excluded=excluded))
        if submitted:
            session.add(SubmissionRow(id="sub_" + uuid.uuid4().hex[:8], scan_id=scan_id,
                                      submitted_by="submitter"))
        await session.commit()

    if submitted:
        async with session_factory() as session:
            app = await session.get(AppRow, app_id)
            app.current_scan_id = scan_id
            await session.commit()
    return scan_id


# --- the two queries the inventory service will run, over the VENDORED models ---


async def _vendored_inventory(session_factory):
    svc = (
        select(
            Finding.scan_id.label("scan_id"),
            func.count(Finding.id).label("service_count"),
        )
        .where(Finding.excluded.is_(False))
        .group_by(Finding.scan_id)
        .subquery()
    )
    stmt = (
        select(App, Submission.submitted_at, Submission.submitted_by,
               func.coalesce(svc.c.service_count, 0))
        .outerjoin(Submission, Submission.scan_id == App.current_scan_id)
        .outerjoin(svc, svc.c.scan_id == App.current_scan_id)
        .where(App.current_scan_id.is_not(None))
        .order_by(Submission.submitted_at.desc())
    )
    async with session_factory() as session:
        return [
            {"id": a.id, "service_count": int(count or 0), "submitted_by": by}
            for a, _at, by, count in (await session.execute(stmt)).all()
        ]


async def _vendored_services(session_factory, app_id):
    async with session_factory() as session:
        app = await session.get(App, app_id)
        if app is None or app.current_scan_id is None:
            return None
        rows = (
            await session.execute(
                select(Finding)
                .where(Finding.scan_id == app.current_scan_id, Finding.excluded.is_(False))
                .order_by(Finding.host)
            )
        ).scalars().all()
        return [{"host": r.host, "auth_method": r.auth_method} for r in rows]


@pytest.mark.asyncio
async def test_inventory_list_matches_the_endpoint(client):
    ac, sf = client
    await _seed(sf, app_id="app_one", offset=60, findings=[
        ("sso.contoso.com", "kerberos", False),
        ("api.partner.io", "oauth", False),
        ("dismissed.contoso.com", "basic", True),
    ])
    await _seed(sf, app_id="app_two", offset=0, findings=[("only.contoso.com", "ntlm", False)])
    # Never submitted — must appear in neither.
    await _seed(sf, app_id="app_none", submitted=False, findings=[("x.contoso.com", "oauth", False)])

    endpoint = [
        {"id": a["id"], "service_count": a["service_count"], "submitted_by": a["submitted_by"]}
        for a in (await ac.get("/api/apps/submitted")).json()
    ]
    vendored = await _vendored_inventory(sf)

    assert vendored == endpoint
    assert {a["id"] for a in vendored} == {"app_one", "app_two"}
    assert next(a for a in vendored if a["id"] == "app_one")["service_count"] == 2


@pytest.mark.asyncio
async def test_services_match_the_endpoint(client):
    ac, sf = client
    await _seed(sf, app_id="app_svc", findings=[
        ("zeta.contoso.com", "ntlm", False),
        ("alpha.contoso.com", "oauth", False),
        ("hidden.contoso.com", "basic", True),
    ])

    endpoint = (await ac.get("/api/apps/app_svc/services")).json()
    vendored = await _vendored_services(sf, "app_svc")

    assert vendored == endpoint
    assert vendored == [
        {"host": "alpha.contoso.com", "auth_method": "oauth"},
        {"host": "zeta.contoso.com", "auth_method": "ntlm"},
    ]


@pytest.mark.asyncio
async def test_sticky_submission_is_preserved_through_vendored_models(client):
    """A newer completed-but-unsubmitted scan must not shift the inventory."""
    ac, sf = client
    await _seed(sf, app_id="app_sticky", offset=3600,
                findings=[("approved.contoso.com", "kerberos", False)])
    # A newer scan for the same app, never submitted.
    async with sf() as session:
        newer = uuid.uuid4().hex
        session.add(ScanRow(id=newer, app_id="app_sticky", name="App app_sticky",
                            url="https://t.invalid", status="completed",
                            started_at=datetime.now(timezone.utc),
                            completed_at=datetime.now(timezone.utc),
                            started_by="tester", pages_crawled=1))
        session.add(FindingRow(id="f_new", scan_id=newer, host="new.contoso.com",
                               auth_method="oauth", severity="cleared", excluded=False))
        await session.commit()

    assert await _vendored_services(sf, "app_sticky") == (
        await ac.get("/api/apps/app_sticky/services")
    ).json() == [{"host": "approved.contoso.com", "auth_method": "kerberos"}]


@pytest.mark.asyncio
async def test_unsubmitted_and_unknown_apps_are_indistinguishable(client):
    """Documents the one intentional behaviour change for the new service.

    The endpoints return two different 404s ("app not found" vs "app has no submitted
    scan"). A consumer reading only these tables cannot tell those apart — both yield
    no rows. Collapsing them is deliberate: it also stops the inventory service from
    enumerating which app IDs exist but aren't submitted.
    """
    ac, sf = client
    await _seed(sf, app_id="app_unsubmitted", submitted=False,
                findings=[("x.contoso.com", "oauth", False)])

    assert await _vendored_services(sf, "app_unsubmitted") is None
    assert await _vendored_services(sf, "app_does_not_exist") is None

    # ...whereas the endpoints being replaced distinguish them.
    assert (await ac.get("/api/apps/app_unsubmitted/services")).json()["detail"]["message"] == (
        "app has no submitted scan"
    )
    assert (await ac.get("/api/apps/app_does_not_exist/services")).json()["detail"]["message"] == (
        "app not found"
    )
