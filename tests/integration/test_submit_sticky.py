"""Integration tests for the sticky-submission flow.

Covers:
  - Only the latest scan can be submitted (older scans → 409).
  - PATCHing a finding on a submitted scan → 409 (freeze rule).
  - After one scan is submitted, the app's exposure_state stays "submitted"
    even when a newer, non-submitted scan completes (pure sticky).
  - The promoted scan_id is reflected as `current_scan_id` on AppSummary.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.db import AppRow, FindingRow, ScanRow

# The `client` fixture (Postgres-backed, migrated, truncated per test) comes from
# tests/integration/conftest.py.


async def _seed_app(session_factory, app_id: str = "app_test") -> str:
    async with session_factory() as session:
        session.add(
            AppRow(
                id=app_id,
                name="Test App",
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
    status: str = "completed",
    with_blocker: bool = False,
) -> str:
    """Insert a scan row directly; bypasses the async scrape job."""
    scan_id = uuid.uuid4().hex
    started_at = datetime.now(timezone.utc) - timedelta(seconds=started_offset_seconds)
    async with session_factory() as session:
        session.add(
            ScanRow(
                id=scan_id,
                app_id=app_id,
                name="Test App",
                url="https://test.invalid",
                status=status,
                started_at=started_at,
                completed_at=started_at if status == "completed" else None,
                started_by="tester",
                pages_crawled=1,
            )
        )
        if with_blocker:
            session.add(
                FindingRow(
                    id="f_" + uuid.uuid4().hex[:8],
                    scan_id=scan_id,
                    host="bad.contoso.com",
                    auth_method="ntlm",
                    severity="blocker",
                    excluded=False,
                )
            )
        await session.commit()
    return scan_id


@pytest.mark.asyncio
async def test_submit_rejects_older_completed_scan_when_newer_completed_exists(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    older_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0)  # newer, also completed

    resp = await ac.post(f"/api/scans/{older_scan}/submit")
    assert resp.status_code == 409
    assert "latest" in resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_submit_allowed_when_later_scan_failed(client):
    """A failed scan is noise — it shouldn't lock out an earlier completed scan."""
    ac, sf = client
    app_id = await _seed_app(sf)
    completed_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0, status="failed")

    resp = await ac.post(f"/api/scans/{completed_scan}/submit")
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_submit_allowed_when_later_scan_cancelled(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    completed_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0, status="cancelled")

    resp = await ac.post(f"/api/scans/{completed_scan}/submit")
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_submit_allowed_when_later_scan_running(client):
    """Running/queued scans don't block submission of the latest completed scan."""
    ac, sf = client
    app_id = await _seed_app(sf)
    completed_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0, status="running")

    resp = await ac.post(f"/api/scans/{completed_scan}/submit")
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_submit_latest_succeeds_and_sets_current_scan_id(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)

    resp = await ac.post(f"/api/scans/{scan_id}/submit")
    assert resp.status_code == 200, resp.text
    assert resp.json()["submission_id"].startswith("sub_")

    apps_resp = await ac.get("/api/apps")
    assert apps_resp.status_code == 200
    apps = apps_resp.json()
    [app] = [a for a in apps if a["id"] == app_id]
    assert app["current_scan_id"] == scan_id
    assert app["exposure_state"] == "submitted"


async def _seed_finding(session_factory, scan_id: str) -> str:
    finding_id = "f_" + uuid.uuid4().hex[:8]
    async with session_factory() as session:
        session.add(
            FindingRow(
                id=finding_id,
                scan_id=scan_id,
                host="ok.contoso.com",
                auth_method="oauth",
                severity="cleared",
                excluded=False,
            )
        )
        await session.commit()
    return finding_id


@pytest.mark.asyncio
async def test_patch_finding_on_submitted_scan_is_frozen(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_finding(sf, scan_id)

    submit_resp = await ac.post(f"/api/scans/{scan_id}/submit")
    assert submit_resp.status_code == 200

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"excluded": True},
    )
    assert patch_resp.status_code == 409
    assert "submitted" in patch_resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_patch_finding_on_older_completed_scan_is_frozen(client):
    """A completed scan that's no longer the latest is also locked."""
    ac, sf = client
    app_id = await _seed_app(sf)
    older_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    finding_id = await _seed_finding(sf, older_scan)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0)  # newer completed

    patch_resp = await ac.patch(
        f"/api/scans/{older_scan}/findings/{finding_id}",
        json={"excluded": True},
    )
    assert patch_resp.status_code == 409
    assert "latest" in patch_resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_patch_finding_on_latest_completed_scan_succeeds(client):
    """The latest completed scan is the only editable one."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_finding(sf, scan_id)

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"excluded": True},
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["excluded"] is True


@pytest.mark.asyncio
async def test_patch_finding_on_latest_with_later_failed_scan_succeeds(client):
    """A later failed scan doesn't lock the latest completed scan."""
    ac, sf = client
    app_id = await _seed_app(sf)
    completed_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)
    finding_id = await _seed_finding(sf, completed_scan)
    _ = await _seed_scan(sf, app_id, started_offset_seconds=0, status="failed")

    patch_resp = await ac.patch(
        f"/api/scans/{completed_scan}/findings/{finding_id}",
        json={"excluded": True},
    )
    assert patch_resp.status_code == 200, patch_resp.text


async def _seed_unknown_finding(session_factory, scan_id: str) -> str:
    """An unclassified finding: auth_method 'unknown' → severity 'review'."""
    finding_id = "f_" + uuid.uuid4().hex[:8]
    async with session_factory() as session:
        session.add(
            FindingRow(
                id=finding_id,
                scan_id=scan_id,
                host="mystery.contoso.com",
                auth_method="unknown",
                severity="review",
                excluded=False,
            )
        )
        await session.commit()
    return finding_id


@pytest.mark.asyncio
async def test_patch_auth_method_on_unknown_finding_recomputes_severity(client):
    """Manually setting an unknown finding to ntlm re-derives severity → blocker."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_unknown_finding(sf, scan_id)

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"auth_method": "ntlm"},
    )
    assert patch_resp.status_code == 200, patch_resp.text
    body = patch_resp.json()
    assert body["auth_method"] == "ntlm"
    assert body["severity"] == "blocker"


@pytest.mark.asyncio
async def test_patch_auth_method_to_cleared_method_recomputes_severity(client):
    """bearer → severity 'cleared' (mirrors translate.severity_for)."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_unknown_finding(sf, scan_id)

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"auth_method": "bearer"},
    )
    assert patch_resp.status_code == 200, patch_resp.text
    body = patch_resp.json()
    assert body["auth_method"] == "bearer"
    assert body["severity"] == "cleared"


@pytest.mark.asyncio
async def test_patch_auth_method_rejected_when_already_classified(client):
    """Only 'unknown' findings can be set manually — overriding is blocked."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_finding(sf, scan_id)  # auth_method 'oauth2'

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"auth_method": "basic"},
    )
    assert patch_resp.status_code == 409
    assert "unknown" in patch_resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_patch_auth_method_to_unknown_rejected(client):
    """You can't manually set a finding back to 'unknown'."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_unknown_finding(sf, scan_id)

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"auth_method": "unknown"},
    )
    assert patch_resp.status_code == 422


@pytest.mark.asyncio
async def test_patch_auth_method_on_submitted_scan_is_frozen(client):
    """The submit freeze applies to auth-method edits too, not just exclusion."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    finding_id = await _seed_unknown_finding(sf, scan_id)

    submit_resp = await ac.post(f"/api/scans/{scan_id}/submit")
    assert submit_resp.status_code == 200

    patch_resp = await ac.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"auth_method": "ntlm"},
    )
    assert patch_resp.status_code == 409
    assert "submitted" in patch_resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_sticky_state_persists_after_new_scan_completes(client):
    """Pure sticky: a newer non-submitted scan does not revert exposure_state."""
    ac, sf = client
    app_id = await _seed_app(sf)
    first_scan = await _seed_scan(sf, app_id, started_offset_seconds=3600)

    submit_resp = await ac.post(f"/api/scans/{first_scan}/submit")
    assert submit_resp.status_code == 200

    # New scan runs and completes WITHOUT being submitted.
    new_scan = await _seed_scan(sf, app_id, started_offset_seconds=0)

    apps_resp = await ac.get("/api/apps")
    [app] = [a for a in apps_resp.json() if a["id"] == app_id]
    # Sticky semantics: exposure_state stays "submitted", current_scan_id still
    # points at the first scan even though `new_scan` is now the latest.
    assert app["exposure_state"] == "submitted"
    assert app["current_scan_id"] == first_scan
    # The new scan can be submitted — it's the latest.
    resubmit_resp = await ac.post(f"/api/scans/{new_scan}/submit")
    assert resubmit_resp.status_code == 200
    # current_scan_id now advances to the new scan.
    apps_resp2 = await ac.get("/api/apps")
    [app2] = [a for a in apps_resp2.json() if a["id"] == app_id]
    assert app2["current_scan_id"] == new_scan


@pytest.mark.asyncio
async def test_submit_rejects_non_completed_scan(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id, status="running")

    resp = await ac.post(f"/api/scans/{scan_id}/submit")
    assert resp.status_code == 409
    assert "completed" in resp.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_submit_rejects_resubmit_of_same_scan(client):
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)

    first = await ac.post(f"/api/scans/{scan_id}/submit")
    assert first.status_code == 200
    second = await ac.post(f"/api/scans/{scan_id}/submit")
    assert second.status_code == 409
    assert "already" in second.json()["detail"]["message"].lower()


@pytest.mark.asyncio
async def test_submissions_scan_id_is_unique_at_db_level(client):
    """The race-safety guard: the DB enforces one submission per scan_id even
    if two requests pass the in-transaction `already_submitted` check.
    """
    from sqlalchemy.exc import IntegrityError

    from api.db import SubmissionRow

    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)
    await ac.post(f"/api/scans/{scan_id}/submit")

    async with sf() as session:
        session.add(
            SubmissionRow(id="sub_dup", scan_id=scan_id, submitted_by="x")
        )
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_concurrent_submits_only_one_succeeds(client):
    """Fire two submits in parallel against the same scan. Exactly one wins."""
    ac, sf = client
    app_id = await _seed_app(sf)
    scan_id = await _seed_scan(sf, app_id)

    r1, r2 = await asyncio.gather(
        ac.post(f"/api/scans/{scan_id}/submit"),
        ac.post(f"/api/scans/{scan_id}/submit"),
    )
    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [200, 409], (r1.text, r2.text)
