import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.core.config import settings
from app.database.session import AsyncSessionLocal
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.models.user import User


async def create_authenticated_user(async_client: AsyncClient, email_prefix: str = "analyst"):
    """Helper to register and log in a user, returning email and password."""
    email = f"{email_prefix}_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "StrongPassword123!"

    # Register
    reg_resp = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_resp.status_code == 201

    # Login
    login_resp = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    return email, password


@pytest.mark.asyncio
async def test_unauthenticated_guest_url_analysis_succeeds_without_persistence(async_client: AsyncClient):
    """Guest can analyze URLs without authentication; scan is not saved to DB; private history remains 401."""
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://paypal-security-update.serveo.net/login"},
    )
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["target_type"] == "URL"
    assert report["risk_score"] > 0
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL", "SUSPICIOUS")
    assert len(report["evidence_items"]) > 0

    # Verify scan is NOT persisted in DB for unauthenticated guests
    scan_uuid = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_uuid)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        assert scan is None, "Guest scans must not be written to the database"

    # Verify private history and stats endpoints strictly require authentication (401)
    history_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert history_resp.status_code == 401

    stats_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/stats/summary")
    assert stats_resp.status_code == 401

    # Verify invalid or expired authorization header does not prevent guest analysis
    invalid_auth_resp = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        headers={"Authorization": "Bearer invalid.expired.token"},
        json={"url": "https://example.com"},
    )
    assert invalid_auth_resp.status_code == 200


@pytest.mark.asyncio
async def test_authenticated_url_analysis_flow(async_client: AsyncClient):
    """Authenticated user performs URL security analysis; verifies report and database persistence."""
    email, _ = await create_authenticated_user(async_client, "scanner")

    target_url = "https://paypal-security-update.serveo.net/login"
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": target_url, "deep_scan": True},
    )
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["target_type"] == "URL"
    assert report["risk_score"] > 0
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL", "SUSPICIOUS")
    assert len(report["evidence_items"]) > 0
    assert len(report["recommended_actions"]) > 0
    assert "paypal" in report["technical_metadata"]["detected_brands"]

    # Verify Database Persistence
    scan_uuid = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_uuid)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        assert scan is not None
        assert scan.input_type == "URL"
        assert scan.risk_score == report["risk_score"]

        # Verify findings persisted
        stmt_f = select(Finding).where(Finding.scan_id == scan_uuid)
        findings = (await db.execute(stmt_f)).scalars().all()
        assert len(findings) == len(report["evidence_items"])

        # Verify audit log recorded
        stmt_a = select(AuditLog).where(AuditLog.scan_id == scan_uuid)
        audit_logs = (await db.execute(stmt_a)).scalars().all()
        assert len(audit_logs) >= 1
        assert audit_logs[0].event_type == "URL_SCAN_COMPLETED"


@pytest.mark.asyncio
async def test_ssrf_prevention_on_private_ip(async_client: AsyncClient):
    """Submitting private loopback IP triggers critical finding without socket connection."""
    await create_authenticated_user(async_client, "ssrf_tester")

    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "http://127.0.0.1:8080/internal/admin"},
    )
    assert response.status_code == 200
    report = response.json()

    assert report["risk_score"] >= 70
    titles = [item["title"] for item in report["evidence_items"]]
    assert any("Internal Network" in t or "Localhost" in t or "Private" in t for t in titles)


@pytest.mark.asyncio
async def test_scan_history_and_report_by_id(async_client: AsyncClient):
    """Tests retrieving scan history and loading specific report by ID."""
    await create_authenticated_user(async_client, "history_tester")

    # Scan two URLs
    await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://first-test-example.com"},
    )
    res2 = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://second-test-example.com"},
    )
    scan_id2 = res2.json()["scan_id"]

    # Check history
    hist_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/history?limit=10")
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    assert len(history) >= 2
    assert history[0]["scan_id"] == scan_id2

    # Check report by ID
    rep_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id2}")
    assert rep_resp.status_code == 200
    assert rep_resp.json()["scan_id"] == scan_id2


@pytest.mark.asyncio
async def test_tenant_isolation(async_client: AsyncClient):
    """User B cannot access User A's scans; returns 404."""
    # User A creates a scan
    await create_authenticated_user(async_client, "user_a")
    res_a = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://user-a-secret-domain.org"},
    )
    scan_id_a = res_a.json()["scan_id"]

    # User B logs in (overwriting session cookie)
    await create_authenticated_user(async_client, "user_b")

    # User B attempts to access User A's scan
    res_b_view = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id_a}")
    assert res_b_view.status_code == 404

    # User B's history should not contain User A's scan
    hist_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert hist_resp.status_code == 200
    scan_ids = [item["scan_id"] for item in hist_resp.json()]
    assert scan_id_a not in scan_ids
