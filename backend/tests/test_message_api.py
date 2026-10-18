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


async def create_authenticated_user(async_client: AsyncClient, email_prefix: str = "msg_analyst"):
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
async def test_unauthenticated_guest_message_analysis_succeeds_without_persistence(async_client: AsyncClient):
    """Guest can submit messages for phishing analysis without authentication; scan is not saved to DB."""
    message_text = (
        "USPS Alert: Your package delivery has an unpaid customs fee of $2.49. "
        "Visit https://usps-redelivery-support.xyz/track immediately or your parcel will be returned."
    )
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        json={"content": message_text, "sender": "alerts@usps-post-service.xyz"},
    )
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["target_type"] == "MESSAGE"
    assert report["risk_score"] > 0
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL", "SUSPICIOUS")
    assert len(report["evidence_items"]) > 0

    # Verify scan is NOT written to database for guests
    scan_uuid = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_uuid)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        assert scan is None, "Guest scans must not be written to the database"

    # Verify invalid session still allows guest scan
    invalid_auth_resp = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        headers={"Authorization": "Bearer expired_session_token"},
        json={"content": "Hello team, please find the meeting agenda attached."},
    )
    assert invalid_auth_resp.status_code == 200


@pytest.mark.asyncio
async def test_authenticated_message_analysis_flow(async_client: AsyncClient):
    """Authenticated user performs message phishing analysis; verifies report and database persistence."""
    await create_authenticated_user(async_client, "phish_tester")

    message_text = (
        "USPS Alert: Your package delivery has an unpaid customs fee of $2.49. "
        "Delivery will be canceled within 12 hours unless verified at: https://usps-redelivery-support.xyz/auth"
    )
    sender_meta = "+1 (800) 555-0199"

    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        json={
            "content": message_text,
            "sender_metadata": sender_meta,
            "subject": "Urgent Delivery Notice",
        },
    )
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["target_type"] == "MESSAGE"
    assert report["risk_score"] >= 70
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL")
    assert len(report["evidence_items"]) > 0
    assert len(report["recommended_actions"]) > 0
    assert "usps" in report["technical_metadata"]["detected_brands"]
    assert len(report["technical_metadata"]["extracted_urls"]) >= 1

    # Verify Database Persistence
    scan_uuid = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_uuid)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        assert scan is not None
        assert scan.input_type == "MESSAGE"
        assert scan.risk_score == report["risk_score"]

        # Verify findings persisted
        stmt_f = select(Finding).where(Finding.scan_id == scan_uuid)
        findings = (await db.execute(stmt_f)).scalars().all()
        assert len(findings) == len(report["evidence_items"])

        # Verify audit log recorded
        stmt_a = select(AuditLog).where(AuditLog.scan_id == scan_uuid)
        audit_logs = (await db.execute(stmt_a)).scalars().all()
        assert len(audit_logs) >= 1
        assert audit_logs[0].event_type == "MESSAGE_SCAN_COMPLETED"
        assert audit_logs[0].details["target_type"] == "MESSAGE"


@pytest.mark.asyncio
async def test_message_with_loopback_url_ssrf_safety(async_client: AsyncClient):
    """Message embedding private IP or loopback address is evaluated safely without socket connections."""
    await create_authenticated_user(async_client, "msg_ssrf")

    message_text = "Internal management portal relocated: http://127.0.0.1:8080/admin/login"
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        json={"content": message_text},
    )
    assert response.status_code == 200
    report = response.json()

    assert report["risk_score"] >= 70
    titles = [item["title"] for item in report["evidence_items"]]
    assert any("Internal Network" in t or "Localhost" in t or "Loopback" in t or "Embedded Link Risk" in t for t in titles)


@pytest.mark.asyncio
async def test_tenant_isolation_on_message_scans(async_client: AsyncClient):
    """User B cannot access User A's message scan report; returns 404."""
    # User A creates a message scan
    await create_authenticated_user(async_client, "msg_user_a")
    res_a = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        json={"content": "Confidential internal merger memo: details at https://secure-corp.org"},
    )
    scan_id_a = res_a.json()["scan_id"]

    # User B logs in
    await create_authenticated_user(async_client, "msg_user_b")

    # User B attempts to access User A's scan
    res_b_view = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id_a}")
    assert res_b_view.status_code == 404

    # User B's history should not contain User A's scan
    hist_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert hist_resp.status_code == 200
    scan_ids = [item["scan_id"] for item in hist_resp.json()]
    assert scan_id_a not in scan_ids
