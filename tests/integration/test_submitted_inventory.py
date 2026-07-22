"""Integration tests for the submitted-app service inventory endpoints.

Covers:
  - GET /api/apps/submitted lists only apps with a submitted scan.
  - service_count counts non-excluded findings of the *submitted* scan.
  - GET /api/apps/{app_id}/services returns host + auth_method for those findings.
  - Stickiness: a newer unsubmitted scan does not shift either endpoint.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.db import AppRow, FindingRow, ScanRow, SubmissionRow

# The `client` fixture (Postgres-backed, migrated, truncated per test) comes from
# tests/integration/conftest.py.


async def _seed_app(session_factory, app_id: str, name: str = "Test App") -> str:
    async with session_factory() as session:
        session.add(
            AppRow(
                id=app_id,
                name=name,
                url="https://test.invalid",
                owner_ad_group="test-group",
            )
        )
        await session.commit()
    return app_id


async def _seed_scan(
    session_factory,
    app_id: str,
    *,
    started_offset_seconds: int = 0,
    findings: list[tuple[str, str, bool]] | None = None,
) -> str:
    """Insert a completed scan plus its findings as (host, auth_method, excluded)."""
    scan_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc) - timedelta(seconds=started_offset_seconds)
    async with session_factory() as session:
        session.add(
            ScanRow(
                id=scan_id,
                app_id=app_id,
                name="Test App",
                url="https://test.invalid",
                status="completed",
                started_at=started_at,
                completed_at=started_at,
                started_by="tester",
                pages_crawled=1,
            )
        )
        for host, auth_method, excluded in findings or []:
            session.add(
                FindingRow(
                    id="f_" + uuid.uuid4().hex[:8],
                    scan_id=scan_id,
                    host=host,
                    auth_method=auth_method,
                    severity="cleared",
                    excluded=excluded,
                )
            )
        await session.commit()
    return scan_id


async def _mark_submitted(session_factory, app_id: str, scan_id: str) -> None:
    """Replicate what POST /scans/{id}/submit commits, without the eligibility rules."""
    async with session_factory() as session:
        session.add(
            SubmissionRow(
                id="sub_" + uuid.uuid4().hex[:8],
                scan_id=scan_id,
                submitted_by="submitter",
            )
        )
        app = await session.get(AppRow, app_id)
        app.current_scan_id = scan_id
        await session.commit()


@pytest.mark.asyncio
async def test_submitted_list_omits_never_submitted_apps(client):
    ac, sf = client
    await _seed_app(sf, "app_unsubmitted")
    await _seed_scan(sf, "app_unsubmitted", findings=[("a.contoso.com", "oauth", False)])

    resp = await ac.get("/api/apps/submitted")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_submitted_list_reports_non_excluded_service_count(client):
    ac, sf = client
    await _seed_app(sf, "app_sub", name="Payments Portal")
    scan_id = await _seed_scan(
        sf,
        "app_sub",
        findings=[
            ("sso.contoso.com", "kerberos", False),
            ("api.partner.io", "oauth", False),
            ("dismissed.contoso.com", "basic", True),
        ],
    )
    await _mark_submitted(sf, "app_sub", scan_id)

    resp = await ac.get("/api/apps/submitted")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    entry = body[0]
    assert entry["id"] == "app_sub"
    assert entry["name"] == "Payments Portal"
    assert entry["owner_ad_group"] == "test-group"
    assert entry["submitted_scan_id"] == scan_id
    assert entry["submitted_by"] == "submitter"
    assert entry["submitted_at"] is not None
    # The excluded finding is not part of the approved inventory.
    assert entry["service_count"] == 2


@pytest.mark.asyncio
async def test_submitted_list_counts_zero_when_all_findings_excluded(client):
    ac, sf = client
    await _seed_app(sf, "app_all_excluded")
    scan_id = await _seed_scan(
        sf,
        "app_all_excluded",
        findings=[("x.contoso.com", "ntlm", True), ("y.contoso.com", "basic", True)],
    )
    await _mark_submitted(sf, "app_all_excluded", scan_id)

    resp = await ac.get("/api/apps/submitted")
    assert resp.status_code == 200
    assert resp.json()[0]["service_count"] == 0


@pytest.mark.asyncio
async def test_newer_unsubmitted_scan_does_not_shift_inventory(client):
    ac, sf = client
    await _seed_app(sf, "app_sticky")
    submitted_scan = await _seed_scan(
        sf,
        "app_sticky",
        started_offset_seconds=3600,
        findings=[("approved.contoso.com", "kerberos", False)],
    )
    await _mark_submitted(sf, "app_sticky", submitted_scan)
    # A newer scan completes with different findings but is never submitted.
    await _seed_scan(
        sf,
        "app_sticky",
        started_offset_seconds=0,
        findings=[
            ("new-a.contoso.com", "oauth", False),
            ("new-b.contoso.com", "basic", False),
        ],
    )

    listed = (await ac.get("/api/apps/submitted")).json()
    assert listed[0]["submitted_scan_id"] == submitted_scan
    assert listed[0]["service_count"] == 1

    services = (await ac.get("/api/apps/app_sticky/services")).json()
    assert [s["host"] for s in services] == ["approved.contoso.com"]


@pytest.mark.asyncio
async def test_services_returns_hosts_and_auth_methods_sorted(client):
    ac, sf = client
    await _seed_app(sf, "app_services")
    scan_id = await _seed_scan(
        sf,
        "app_services",
        findings=[
            ("zeta.contoso.com", "ntlm", False),
            ("alpha.contoso.com", "oauth", False),
            ("hidden.contoso.com", "basic", True),
        ],
    )
    await _mark_submitted(sf, "app_services", scan_id)

    resp = await ac.get("/api/apps/app_services/services")
    assert resp.status_code == 200
    assert resp.json() == [
        {"host": "alpha.contoso.com", "auth_method": "oauth"},
        {"host": "zeta.contoso.com", "auth_method": "ntlm"},
    ]


@pytest.mark.asyncio
async def test_services_404s_distinguish_unknown_app_from_unsubmitted(client):
    ac, sf = client
    await _seed_app(sf, "app_no_submission")

    missing = await ac.get("/api/apps/app_does_not_exist/services")
    assert missing.status_code == 404
    assert missing.json()["detail"]["message"] == "app not found"

    unsubmitted = await ac.get("/api/apps/app_no_submission/services")
    assert unsubmitted.status_code == 404
    assert unsubmitted.json()["detail"]["message"] == "app has no submitted scan"
