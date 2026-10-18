import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.feedback import Feedback
from app.schemas.feedback import FeedbackCreateRequest, FeedbackResponse
from app.security.dependencies import get_current_user

router = APIRouter(prefix="/feedback", tags=["Feedback"])


@router.post(
    "",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit analyst tuning feedback on a specific scan result",
)
async def submit_feedback(
    req: FeedbackCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FeedbackResponse:
    """Submits feedback for an investigation report, verifying scan existence and strict tenant ownership."""
    stmt = select(Scan).where(Scan.id == req.scan_id)
    scan = (await db.execute(stmt)).scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan report not found.",
        )

    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to submit feedback for another user's scan report.",
        )

    feedback_text = req.get_effective_feedback()
    feedback_entry = Feedback(
        user_id=current_user.id,
        scan_id=req.scan_id,
        feedback=feedback_text,
    )
    db.add(feedback_entry)
    await db.commit()
    await db.refresh(feedback_entry)

    return feedback_entry


@router.get(
    "",
    response_model=List[FeedbackResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve user submitted feedback history",
)
async def get_user_feedback(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[FeedbackResponse]:
    """Retrieves paginated feedback entries strictly scoped to the authenticated user."""
    stmt = (
        select(Feedback)
        .where(Feedback.user_id == current_user.id)
        .order_by(Feedback.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    entries = result.scalars().all()
    return list(entries)
