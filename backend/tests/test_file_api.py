import io
import uuid
import zipfile
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.database.session import AsyncSessionLocal
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from tests.test_screenshot_api import create_authenticated_user


SAMPLE_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj << /JavaScript (app.alert('pwned')) >> endobj\n"
    b"2 0 obj << /Launch << /F (cmd.exe) >> >> endobj\n"
    b"3 0 obj << /URI (https://evil-phish-portal.live/login) >> endobj\n"
    b"trailer << /Root 1 0 R >> %%EOF\n"
)


@pytest.mark.asyncio
async def test_unauthenticated_guest_file_analysis_succeeds_without_persistence(async_client: AsyncClient):
    """Guest can submit files for security inspection without authentication; scan is not saved to DB."""
    files = {"file": ("guest_sample.pdf", SAMPLE_PDF, "application/pdf")}
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/file",
        files=files,
    )
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["target_type"] == "FILE"
    assert report["risk_score"] >= 70
    assert report["risk_level"] in ("HIGH RISK", "CRITICAL")
    assert len(report["evidence_items"]) > 0

    # Verify scan is NOT written to database for guests
    scan_uuid = uuid.UUID(report["scan_id"])
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_uuid)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        assert scan is None, "Guest scans must not be written to the database"


@pytest.mark.asyncio
async def test_authenticated_pdf_file_analysis_flow(async_client: AsyncClient):
    """Authenticated user submits malicious PDF; verifies findings, DB persistence, and ThreatReport."""
    await create_authenticated_user(async_client, "file_tester")

    files = {"file": ("invoice_trojan.pdf", SAMPLE_PDF, "application/pdf")}
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/file",
        files=files,
    )

    assert response.status_code == 200
    data = response.json()

    assert data["target_type"] == "FILE"
    assert data["risk_level"] in ("HIGH RISK", "CRITICAL")
    assert data["risk_score"] >= 70
    assert len(data["evidence_items"]) > 0
    assert len(data["recommended_actions"]) > 0
    assert data["technical_metadata"]["file_name"] == "invoice_trojan.pdf"
    assert data["technical_metadata"]["is_executable"] is False
    assert len(data["technical_metadata"]["file_hash_sha256"]) == 64

    # Verify DB persistence
    scan_id = uuid.UUID(data["scan_id"])
    async with AsyncSessionLocal() as session:
        scan_result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        assert scan is not None
        assert scan.input_type == "FILE"
        assert scan.risk_score == data["risk_score"]

        # Check Finding records
        finding_result = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
        findings = finding_result.scalars().all()
        assert len(findings) > 0

        # Check Audit Log
        audit_result = await session.execute(select(AuditLog).where(AuditLog.scan_id == scan_id))
        audit = audit_result.scalar_one_or_none()
        assert audit is not None
        assert audit.event_type == "FILE_SCAN_COMPLETED"
        assert audit.details["target_type"] == "FILE"


@pytest.mark.asyncio
async def test_authenticated_docm_file_analysis_flow(async_client: AsyncClient):
    """Authenticated user submits DOCM with VBA; verifies macro extraction and high risk score."""
    await create_authenticated_user(async_client, "docm_tester")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/vbaProject.bin", b"sub AutoOpen()\n Shell('powershell -enc ...')\n End Sub")
    docm_bytes = buf.getvalue()

    files = {"file": ("Resume_Candidate.docm", docm_bytes, "application/vnd.ms-word.document.macroEnabled.12")}
    response = await async_client.post(
        f"{settings.API_V1_STR}/analyze/file",
        files=files,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "FILE"
    assert data["risk_score"] >= 50
    evidence_titles = [e["title"] for e in data["evidence_items"]]
    assert any("OFFICE_VBA_MACRO_PRESENT" in t or "OFFICE_VBA_AUTO_EXEC" in t for t in evidence_titles)


@pytest.mark.asyncio
async def test_tenant_isolation_on_file_scans(async_client: AsyncClient):
    """User B cannot view or retrieve User A's file scan report (404/denied)."""
    # 1. User A scans a file
    await create_authenticated_user(async_client, "user_a")
    files = {"file": ("secret_user_a.pdf", SAMPLE_PDF, "application/pdf")}
    resp_a = await async_client.post(f"{settings.API_V1_STR}/analyze/file", files=files)
    assert resp_a.status_code == 200
    scan_id_a = resp_a.json()["scan_id"]

    # 2. User B logs in
    await create_authenticated_user(async_client, "user_b")

    # 3. User B attempts to access User A's scan report
    resp_b = await async_client.get(f"{settings.API_V1_STR}/analyze/{scan_id_a}")
    assert resp_b.status_code == 404
