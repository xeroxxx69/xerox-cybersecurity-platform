from typing import Optional, Dict, Any
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    database: Optional[str] = "not_connected"
    cache: Optional[str] = "not_connected"
    checks: Optional[Dict[str, str]] = None


class LivenessReadinessResponse(BaseModel):
    status: str
    service: str
    checks: Dict[str, str]


class RootResponse(BaseModel):
    brand: str
    product: str
    status: str
    version: str
    docs_url: str

