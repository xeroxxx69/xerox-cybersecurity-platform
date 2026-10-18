import io
import uuid
import pytest
from httpx import AsyncClient
from unittest.mock import patch
from sqlalchemy import select

from app.core.config import settings
from app.database.session import AsyncSessionLocal
from app.models.scan import Scan
from app.models.user import User
from app.analyzers.screenshot.vision.base import VisionExtractionResult

SAMPLE_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

SAMPLE_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj << /JavaScript (app.alert('pwned')) >> endobj\n"
    b"2 0 obj << /Launch << /F (cmd.exe) >> >> endobj\n"
    b"3 0 obj << /URI (https://evil-phish-portal.live/login) >> endobj\n"
    b"trailer << /Root 1 0 R >> %%EOF\n"
)


async def register_and_login(client: AsyncClient, prefix: str):
    email = f"{prefix}_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "StrongPassword123!"
    reg_resp = await client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_resp.status_code == 201
    login_resp = await client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    return email


@pytest.mark.asyncio
async def test_guest_can_submit_url_analysis(async_client: AsyncClient):
    """Proves guests can submit URL analyses without registration/login, returning full report without DB persistence."""
    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://paypal-security-update.serveo.net/login"},
    )
    assert res.status_code == 200
    report = res.json()
    assert "scan_id" in report
    assert report["target_type"] == "URL"
    assert report["risk_score"] > 0
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL", "SUSPICIOUS")
    assert len(report["evidence_items"]) > 0

    # Ensure zero database persistence for guest scan
    scan_id = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        assert scan is None, "Guest scans must NEVER be persisted to the database"


@pytest.mark.asyncio
async def test_guest_can_submit_message_analysis(async_client: AsyncClient):
    """Proves guests can submit message phishing analyses without authentication."""
    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/message",
        json={"content": "Urgent: Your account is suspended. Verify at https://secure-bank-login.xyz immediately."},
    )
    assert res.status_code == 200
    report = res.json()
    assert report["target_type"] == "MESSAGE"
    assert report["risk_score"] > 0

    scan_id = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        assert scan is None


@pytest.mark.asyncio
async def test_guest_can_submit_screenshot_analysis(async_client: AsyncClient):
    """Proves guests can submit screenshot analyses safely without persistent storage."""
    mock_vision = VisionExtractionResult(
        raw_text="Microsoft Account: Enter password. https://login-microsoft.attacker.org",
        detected_brands=["Microsoft"],
        visual_elements=["Login Form"],
        visible_urls=["https://login-microsoft.attacker.org"],
        is_available=True,
    )

    with patch(
        "app.analyzers.screenshot.vision.gemini.GeminiVisionProvider.extract",
        return_value=mock_vision,
    ):
        files = {"file": ("guest_screenshot.png", SAMPLE_PNG, "image/png")}
        res = await async_client.post(
            f"{settings.API_V1_STR}/analyze/screenshot",
            files=files,
        )
        assert res.status_code == 200
        report = res.json()
        assert report["target_type"] == "SCREENSHOT"
        assert report["risk_score"] > 0

        scan_id = uuid.UUID(report["scan_id"])
        async with AsyncSessionLocal() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
            assert scan is None


@pytest.mark.asyncio
async def test_guest_can_submit_file_analysis(async_client: AsyncClient):
    """Proves guests can submit suspicious files safely without permanent storage or DB writes."""
    files = {"file": ("malicious_doc.pdf", SAMPLE_PDF, "application/pdf")}
    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/file",
        files=files,
    )
    assert res.status_code == 200
    report = res.json()
    assert report["target_type"] == "FILE"
    assert report["risk_score"] >= 70

    scan_id = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        assert scan is None


@pytest.mark.asyncio
async def test_guest_receives_no_access_to_private_account_history(async_client: AsyncClient):
    """Proves unauthenticated visitors receive 401 on private history, stats, and saved reports."""
    # History endpoint
    hist_res = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert hist_res.status_code == 401

    # Stats endpoint
    stats_res = await async_client.get(f"{settings.API_V1_STR}/analyze/stats/summary")
    assert stats_res.status_code == 401

    # Arbitrary scan report endpoint
    scan_res = await async_client.get(f"{settings.API_V1_STR}/analyze/{uuid.uuid4()}")
    assert scan_res.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_users_retain_personal_scan_history(async_client: AsyncClient):
    """Proves authenticated users have their scans saved to their account and accessible in history."""
    await register_and_login(async_client, "auth_user_history")

    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://auth-user-scan-domain.net"},
    )
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]

    # History contains this scan
    hist_res = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert any(item["scan_id"] == scan_id for item in history)

    # Report by ID is retrievable
    rep_res = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id}")
    assert rep_res.status_code == 200
    assert rep_res.json()["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_one_user_cannot_access_another_users_records(async_client: AsyncClient):
    """Proves strict tenant isolation: User B cannot retrieve User A's scans."""
    # User A creates a scan
    await register_and_login(async_client, "user_alpha")
    res_a = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "https://confidential-user-alpha.org"},
    )
    scan_id_a = res_a.json()["scan_id"]

    # User B logs in
    await register_and_login(async_client, "user_bravo")

    # User B attempts to access User A's scan
    res_b = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id_a}")
    assert res_b.status_code == 404

    # User B's history does not contain User A's scan
    hist_b = await async_client.get(f"{settings.API_V1_STR}/analyze/history")
    assert hist_b.status_code == 200
    assert not any(item["scan_id"] == scan_id_a for item in hist_b.json())


@pytest.mark.asyncio
async def test_invalid_or_expired_sessions_do_not_prevent_guest_access(async_client: AsyncClient):
    """Proves expired tokens, invalid cookies, or corrupted auth headers still allow public guest analysis."""
    bad_headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.corrupted.token"}
    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        headers=bad_headers,
        json={"url": "https://example-guest-test.com"},
    )
    assert res.status_code == 200
    assert res.json()["target_type"] == "URL"


@pytest.mark.asyncio
async def test_empty_target_produces_accurate_error_message(async_client: AsyncClient):
    """Proves input validation produces informative error messages without claiming operational status."""
    res = await async_client.post(
        f"{settings.API_V1_STR}/analyze/url",
        json={"url": "   "},
    )
    assert res.status_code == 400
    assert "URL target cannot be empty." in res.json()["detail"]
