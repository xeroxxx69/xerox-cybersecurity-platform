import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, File, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db, get_optional_db
from app.models.user import User
from app.security.dependencies import get_current_user, get_optional_current_user
from app.schemas.threat import (
    ThreatReport,
    URLScanRequest,
    MessageScanRequest,
    ScanHistoryItem,
    StatsSummary,
)
from app.services.url_analysis_service import URLAnalysisService
from app.services.message_analysis_service import MessageAnalysisService
from app.services.screenshot_analysis_service import ScreenshotAnalysisService
from app.services.file_analysis_service import FileAnalysisService
from app.analyzers.screenshot.validator import ImageValidationError
from app.analyzers.file.validator import FileValidationError

router = APIRouter()


@router.post(
    "/url",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious URL for security threats",
)
async def analyze_url_endpoint(
    request_data: URLScanRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Optional[AsyncSession] = Depends(get_optional_db),
) -> ThreatReport:
    """Performs deterministic static heuristic analysis and threat intelligence checks
    on a target URL. NEVER opens socket connections to the target (strict SSRF prevention).
    Persists scan and forensic findings scoped to the authenticated user if logged in;
    returns complete ThreatReport directly for guests.
    """
    cleaned_url = request_data.url.strip()
    if not cleaned_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL target cannot be empty.",
        )

    service = URLAnalysisService()
    try:
        report = await service.analyze_url(
            raw_url=cleaned_url,
            user_id=current_user.id if current_user else None,
            db=db,
        )
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"URL security analysis failed: {str(exc)}",
        )


@router.post(
    "/message",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious message or email lure for phishing threats",
)
async def analyze_message_endpoint(
    request_data: MessageScanRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Optional[AsyncSession] = Depends(get_optional_db),
) -> ThreatReport:
    """Performs deterministic phishing, social engineering, and embedded URL security analysis
    on message/email content. Evaluates urgency, coercion, credential solicitation, and embedded links.
    NEVER connects to target URLs or executes message code. Persists scan scoped to authenticated user;
    returns complete ThreatReport directly for guests.
    """
    cleaned_content = request_data.content.strip()
    if not cleaned_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty.",
        )

    service = MessageAnalysisService()
    try:
        report = await service.analyze_message(
            content=cleaned_content,
            user_id=current_user.id if current_user else None,
            db=db,
            subject=request_data.subject,
            sender=request_data.sender,
            sender_metadata=request_data.sender_metadata,
        )
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Message security analysis failed: {str(exc)}",
        )


@router.post(
    "/screenshot",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious screenshot for phishing, credential theft, and visual lures",
)
async def analyze_screenshot_endpoint(
    file: UploadFile = File(..., description="Screenshot image file (PNG, JPEG, WEBP, max 10MB)"),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Optional[AsyncSession] = Depends(get_optional_db),
) -> ThreatReport:
    """Performs isolated, secure visual and OCR heuristic analysis on untrusted screenshot uploads.
    Extracts text, visual elements, and embedded links; reuses M5 URL and M6 phishing engines.
    Persists scan strictly scoped to authenticated user; handles guest uploads transiently in-memory.
    """
    try:
        file_bytes = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    service = ScreenshotAnalysisService()
    try:
        report = await service.analyze_screenshot(
            file_bytes=file_bytes,
            declared_mime=file.content_type,
            client_filename=file.filename,
            user_id=current_user.id if current_user else None,
            db=db,
        )
        return report
    except ImageValidationError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Screenshot security analysis failed: {str(exc)}",
        )


@router.post(
    "/file",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious file for security threats (PDF, Office, EML, ZIP, Text)",
)
async def analyze_file_endpoint(
    file: UploadFile = File(..., description="Suspicious file upload (PDF, DOCX, DOCM, EML, ZIP, TXT, max 15MB)"),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Optional[AsyncSession] = Depends(get_optional_db),
) -> ThreatReport:
    """Performs isolated, safe static structural inspection and threat intelligence lookup
    on untrusted file uploads. Non-executable storage, zero code execution, and strict tenant isolation.
    Handles guest uploads transiently in-memory and skips DB persistence.
    """
    try:
        file_bytes = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    service = FileAnalysisService()
    try:
        report = await service.analyze_file(
            file_bytes=file_bytes,
            declared_mime=file.content_type,
            client_filename=file.filename,
            user_id=current_user.id if current_user else None,
            db=db,
        )
        return report
    except FileValidationError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File security analysis failed: {str(exc)}",
        )


@router.get(
    "/history",
    response_model=List[ScanHistoryItem],
    status_code=status.HTTP_200_OK,
    summary="Retrieve user's historical security scans",
)
async def get_history_endpoint(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[ScanHistoryItem]:
    """Retrieves paginated scan history strictly scoped to the authenticated user."""
    service = URLAnalysisService()
    return await service.get_user_history(
        user_id=current_user.id,
        db=db,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/stats/summary",
    response_model=StatsSummary,
    status_code=status.HTTP_200_OK,
    summary="Get user security telemetry statistics",
)
@router.get(
    "/summary/stats",
    response_model=StatsSummary,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def get_stats_endpoint(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StatsSummary:
    """Returns aggregated threat telemetry statistics for the authenticated user."""
    service = URLAnalysisService()
    return await service.get_stats_summary(user_id=current_user.id, db=db)


@router.get(
    "/{scan_id}",
    response_model=ThreatReport,
    status_code=status.HTTP_200_OK,
    summary="Retrieve full threat report by scan ID",
)
async def get_scan_report_endpoint(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ThreatReport:
    """Loads a full ThreatReport by scan ID, enforcing strict tenant isolation."""
    service = URLAnalysisService()
    report = await service.get_scan_report(
        scan_id=scan_id,
        user_id=current_user.id,
        db=db,
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan report not found or access denied.",
        )
    return report
