from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class NormalizedCategory(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    IDENTITY = "IDENTITY"
    CONTENT = "CONTENT"
    REPUTATION = "REPUTATION"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"


class NormalizedSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NormalizedIndicator(BaseModel):
    indicator_type: str
    category: NormalizedCategory
    severity: NormalizedSeverity
    weight: int = Field(..., ge=0, le=100, description="Risk point contribution (0-100)")
    description: str
    technical_proof: str
    why_this_matters: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)


class NormalizedInput(BaseModel):
    target_type: str  # URL, MESSAGE, EMAIL, SCREENSHOT, FILE
    raw_target: str
    defanged_target: str
    target_hash: str
    indicators: List[NormalizedIndicator] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
