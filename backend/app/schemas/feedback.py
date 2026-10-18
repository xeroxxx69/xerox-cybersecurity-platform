import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class FeedbackCreateRequest(BaseModel):
    scan_id: uuid.UUID = Field(..., description="ID of the scan being evaluated")
    feedback: Optional[str] = Field(None, max_length=2000, description="Analyst feedback or tuning commentary")
    rating: Optional[int] = Field(None, ge=1, le=5, description="Optional 1-5 rating score")
    is_accurate: Optional[bool] = Field(None, description="Whether analysis was accurate")
    user_notes: Optional[str] = Field(None, max_length=2000, description="User or analyst notes")
    suggested_label: Optional[str] = Field(None, max_length=128, description="Analyst suggested label")

    def get_effective_feedback(self) -> str:
        """Constructs a consolidated feedback message from structured or text inputs."""
        if self.feedback and self.feedback.strip():
            return self.feedback.strip()

        parts = []
        if self.is_accurate is not None:
            parts.append(f"Accuracy: {'Accurate' if self.is_accurate else 'Inaccurate / False Positive'}")
        if self.suggested_label:
            parts.append(f"Suggested Label: {self.suggested_label}")
        if self.user_notes:
            parts.append(f"Notes: {self.user_notes}")
        if self.rating:
            parts.append(f"Rating: {self.rating}/5")
        
        result = " | ".join(parts).strip()
        return result if result else "Analyst feedback recorded."


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    scan_id: uuid.UUID
    feedback: str
    created_at: datetime
