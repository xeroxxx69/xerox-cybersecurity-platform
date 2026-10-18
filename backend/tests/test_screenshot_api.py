import uuid
import pytest
from unittest.mock import patch
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.database.session import AsyncSessionLocal
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.models.user import User
from app.analyzers.screenshot.vision.base import VisionExtractionResult


SAMPLE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


async def create_authenticated_user(async_client: AsyncClient, email_prefix: str = "screen_analyst"):
    """Helper to register and log in a user."""
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
async def test_unauthenticated_guest_screenshot_analysis_succeeds_without_persistence(async_client: AsyncClient):
    """Guest can submit screenshot for analysis without authentication; scan is not saved to DB."""
    mock_vision_result = VisionExtractionResult(
        raw_text="Apple ID Sign in: Enter your Apple ID and password to unlock iCloud. https://apple-verify.support-secure.live",
        detected_brands=["Apple"],
        visual_elements=["Login Form", "Password Input", "Brand Logo"],
        visible_urls=["https://apple-verify.support-secure.live"],
        provider_name="TesseractOCR+Vision",
        is_available=True,
    )

    with patch(
        "app.analyzers.screenshot.vision.gemini.GeminiVisionProvider.extract",
        return_value=mock_vision_result,
    ):

        files = {"file": ("guest_capture.png", SAMPLE_PNG, "image/png")}
        response = await async_client.post(
            f"{settings.API_V1_STR}/analyze/screenshot",
            files=files,
        )
        assert response.status_code == 200
        report = response.json()

        assert "scan_id" in report
        assert report["target_type"] == "SCREENSHOT"
        assert report["risk_score"] > 0
        assert len(report["evidence_items"]) > 0

        # Verify scan is NOT written to database for guests
        scan_uuid = uuid.UUID(report["scan_id"])
        async with AsyncSessionLocal() as db:
            stmt = select(Scan).where(Scan.id == scan_uuid)
            scan = (await db.execute(stmt)).scalar_one_or_none()
            assert scan is None, "Guest scans must not be written to the database"


@pytest.mark.asyncio
async def test_authenticated_screenshot_analysis_flow(async_client: AsyncClient):
    """Authenticated user submits screenshot; verifies findings, DB persistence, and ThreatReport."""
    await create_authenticated_user(async_client, "screen_tester")

    mock_vision_result = VisionExtractionResult(
        raw_text="Apple ID Sign in: Enter your Apple ID and password to unlock iCloud. https://apple-verify.support-secure.live",
        visible_urls=["https://apple-verify.support-secure.live"],
        visible_domains=["apple-verify.support-secure.live"],
        detected_brands=["Apple"],
        visual_elements=["login_form", "password_field"],
        confidence_score=95.0,
        is_available=True,
    )

    with patch(
        "app.analyzers.screenshot.vision.gemini.GeminiVisionProvider.extract",
        return_value=mock_vision_result,
    ):
        files = {"file": ("suspect_portal.png", SAMPLE_PNG, "image/png")}
        response = await async_client.post(
            f"{settings.API_V1_STR}/analyze/screenshot",
            files=files,
        )

    assert response.status_code == 200
    data = response.json()

    assert data["target_type"] == "SCREENSHOT"
    assert data["risk_level"] in ("HIGH RISK", "CRITICAL")
    assert data["risk_score"] >= 70
    assert len(data["evidence_items"]) > 0
    assert len(data["recommended_actions"]) > 0
    assert "apple-verify.support-secure.live" in data["technical_metadata"]["extracted_urls"][0]

    # Verify Database Persistence
    scan_id = uuid.UUID(data["scan_id"])
    async with AsyncSessionLocal() as session:
        # Check Scan record
        scan_result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        assert scan is not None
        assert scan.input_type == "SCREENSHOT"
        assert scan.risk_score == data["risk_score"]

        # Check Finding records
        finding_result = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
        findings = finding_result.scalars().all()
        assert len(findings) > 0

        # Check AuditLog record
        audit_result = await session.execute(select(AuditLog).where(AuditLog.scan_id == scan_id))
        audit = audit_result.scalar_one_or_none()
        assert audit is not None
        assert audit.event_type == "SCREENSHOT_ANALYZED"
        assert audit.details["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_invalid_screenshot_format_returns_400(async_client: AsyncClient):
    """Submitting non-image or invalid magic bytes returns 400 Bad Request."""
    await create_authenticated_user(async_client, "invalid_uploader")

    # Upload HTML disguised as PNG
    files = {"file": ("malicious.png", b"<html><body>Not an image</body></html>", "image/png")}
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/screenshot",
        files=files,
    )
    assert response.status_code == 400
    assert "Unsupported or invalid image file signature" in response.json()["detail"]


@pytest.mark.asyncio
async def test_tenant_isolation_on_screenshot_scans(async_client: AsyncClient):
    """User B cannot retrieve User A's screenshot scan report."""
    # User A creates a scan
    await create_authenticated_user(async_client, "user_a_screen")
    mock_vision = VisionExtractionResult(raw_text="Team slide", is_available=True)

    with patch("app.analyzers.screenshot.vision.gemini.GeminiVisionProvider.extract", return_value=mock_vision):
        files = {"file": ("user_a_capture.png", SAMPLE_PNG, "image/png")}
        scan_resp = await async_client.post(
            f"{settings.API_V1_STR}/analyze/screenshot",
            files=files,
        )
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # User B logs in
    await create_authenticated_user(async_client, "user_b_screen")

    # User B attempts to access User A's scan
    get_resp = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id}")
    assert get_resp.status_code == 404
