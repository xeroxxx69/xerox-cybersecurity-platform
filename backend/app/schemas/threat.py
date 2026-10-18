from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    BENIGN = "BENIGN"
    LOW_RISK = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"

class TargetType(str, Enum):
    URL = "URL"
    MESSAGE = "MESSAGE"
    EMAIL = "EMAIL"
    SCREENSHOT = "SCREENSHOT"
    FILE = "FILE"

class EvidenceCategory(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    IDENTITY = "IDENTITY"
    CONTENT = "CONTENT"
    REPUTATION = "REPUTATION"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"

class EvidenceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EvidenceItem(BaseModel):
    category: EvidenceCategory
    severity: EvidenceSeverity
    title: str
    description: str
    technical_proof: str
    why_this_matters: str

class RedirectHop(BaseModel):
    hop_number: int
    from_url: str
    to_url: str
    status_code: int
    ip_address: Optional[str] = None
    response_time_ms: Optional[float] = None

class RecommendedAction(BaseModel):
    priority: str = Field(..., description="IMMEDIATE, PREVENTATIVE, or REPORTING")
    action: str
    rationale: str
    action_type: str = Field(..., description="DO_NOT_CLICK, CHANGE_PASSWORD, REPORT_PHISHING, VERIFY_SENDER, SAFE_TO_PROCEED")

class DNSRecords(BaseModel):
    a: List[str] = []
    aaaa: List[str] = []
    mx: List[str] = []
    ns: List[str] = []
    txt: List[str] = []

class SSLCertInfo(BaseModel):
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    is_valid: bool = False
    is_self_signed: bool = False
    days_remaining: Optional[int] = None

class TechnicalMetadata(BaseModel):
    domain: str = ""
    subdomain: str = ""
    registered_domain: str = ""
    tld: str = ""
    ip_addresses: List[str] = []
    dns: Optional[DNSRecords] = None
    ssl: Optional[SSLCertInfo] = None
    redirect_hops: List[RedirectHop] = []
    entropy: float = 0.0
    detected_brands: List[str] = []
    extracted_urls: List[str] = []
    social_engineering_flags: List[str] = []
    file_name: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_hash_sha256: Optional[str] = None
    file_hash_md5: Optional[str] = None
    mime_type: Optional[str] = None
    is_executable: Optional[bool] = None
    threat_intel_summary: Optional[str] = None
    threat_intel_permalink: Optional[str] = None

class ThreatReport(BaseModel):
    scan_id: str
    target_type: TargetType
    raw_target: str
    defanged_target: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    confidence_score: float = Field(..., ge=0.0, le=100.0)
    executive_summary: str
    layman_verdict: str
    evidence_items: List[EvidenceItem]
    recommended_actions: List[RecommendedAction]
    technical_metadata: TechnicalMetadata
    analyzed_at: str

class URLScanRequest(BaseModel):
    url: str
    deep_scan: bool = True

class MessageScanRequest(BaseModel):
    content: str
    sender_metadata: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None

class ScanHistoryItem(BaseModel):
    scan_id: str
    target_type: TargetType
    defanged_target: str
    risk_level: RiskLevel
    risk_score: int
    analyzed_at: str
    executive_summary: str

class StatsSummary(BaseModel):
    total_scans: int
    threats_blocked: int
    benign_verified: int
    suspicious_flagged: int
    scans_by_type: Dict[str, int]
