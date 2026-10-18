import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.file_storage import LocalFileStorage, StoredFileMetadata
from app.analyzers.file.validator import FileValidator, ValidatedFile, FileValidationError
from app.analyzers.file.inspector import FileInspector, FileInspectionResult
from app.schemas.normalized import (
    NormalizedInput,
    NormalizedIndicator,
    NormalizedCategory,
    NormalizedSeverity,
)
from app.analyzers.security_engine import UnifiedSecurityEngine
from app.cache.redis_client import ThreatIntelCache
from app.threat_intel.base import ThreatIntelProvider
from app.threat_intel.virustotal import VirusTotalProvider
from app.threat_intel.schemas import ThreatIntelResult
from app.ai.explainer import ThreatExplainer
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.core.datetime_utils import get_monotonic_utc_now
from app.schemas.threat import (
    ThreatReport,
    TargetType,
    RiskLevel,
    EvidenceItem,
    EvidenceCategory,
    EvidenceSeverity,
    RecommendedAction,
    TechnicalMetadata,
)

logger = logging.getLogger("xerox.services.file_analysis")

SEV_MAP = {
    "CRITICAL": NormalizedSeverity.CRITICAL,
    "HIGH": NormalizedSeverity.HIGH,
    "MEDIUM": NormalizedSeverity.MEDIUM,
    "LOW": NormalizedSeverity.LOW,
}


class FileAnalysisService:
    """Orchestrates secure file upload validation, isolated filesystem storage,
    safe static structural inspection (PDF, Office, EML, ZIP, Text),
    threat intelligence reputation cache/lookup by SHA-256 hash,
    normalized risk scoring via UnifiedSecurityEngine, AI explanation synthesis,
    and database persistence with strict user-scoped tenant isolation.
    """

    def __init__(
        self,
        storage: Optional[LocalFileStorage] = None,
        threat_intel_provider: Optional[ThreatIntelProvider] = None,
        cache: Optional[ThreatIntelCache] = None,
        explainer: Optional[ThreatExplainer] = None,
    ):
        self.storage = storage or LocalFileStorage()
        self.threat_intel_provider = threat_intel_provider or VirusTotalProvider()
        self.cache = cache or ThreatIntelCache()
        self.explainer = explainer or ThreatExplainer()

    async def analyze_file(
        self,
        file_bytes: bytes,
        declared_mime: Optional[str] = None,
        client_filename: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        db: Optional[AsyncSession] = None,
    ) -> ThreatReport:
        """Executes the complete safe file security analysis pipeline."""

        # 1. Validation & Magic Bytes Detection
        validated_file: ValidatedFile = FileValidator.validate(
            file_bytes=file_bytes,
            declared_mime=declared_mime,
            client_filename=client_filename,
        )

        # 2. Persist in Isolated Storage (For authenticated users only; avoid permanent storage for guests)
        if user_id is not None:
            stored_meta = await self.storage.save(
                file_bytes=validated_file.content,
                extension=validated_file.safe_extension,
                mime_type=validated_file.mime_type,
                sha256_hash=validated_file.sha256_hash,
            )
        else:
            stored_meta = StoredFileMetadata(
                storage_key="transient-guest",
                file_path="",
                file_size_bytes=validated_file.file_size_bytes,
                sha256_hash=validated_file.sha256_hash,
                mime_type=validated_file.mime_type,
                created_at=get_monotonic_utc_now().isoformat(),
            )

        # 3. Safe Static Structural Inspection
        inspection: FileInspectionResult = FileInspector.inspect(validated_file)

        # 4. Threat Intelligence Hash Lookup (Cache-First)
        threat_intel: Optional[ThreatIntelResult] = None
        try:
            cached = await self.cache.get_file(validated_file.sha256_hash)
            if cached is not None:
                threat_intel = cached
            else:
                threat_intel = await self.threat_intel_provider.lookup_file_hash(validated_file.sha256_hash)
                if threat_intel:
                    await self.cache.set_file(validated_file.sha256_hash, threat_intel)
        except Exception as exc:
            logger.warning(f"File threat intelligence lookup failed: {exc}")
            threat_intel = None

        # 5. Build Normalized Indicators
        indicators: List[NormalizedIndicator] = []
        for finding in inspection.findings:
            n_sev = SEV_MAP.get(finding.severity, NormalizedSeverity.LOW)
            indicators.append(
                NormalizedIndicator(
                    indicator_type=finding.indicator_type,
                    category=NormalizedCategory.CONTENT if finding.indicator_type != "EXECUTABLE_BINARY_DETECTED" else NormalizedCategory.INFRASTRUCTURE,
                    severity=n_sev,
                    weight=50 if n_sev == NormalizedSeverity.CRITICAL else (25 if n_sev == NormalizedSeverity.HIGH else (12 if n_sev == NormalizedSeverity.MEDIUM else 5)),
                    description=finding.description,
                    technical_proof=f"Format: {validated_file.detected_format} | Evidence: {str(finding.evidence)}",
                    why_this_matters="Suspicious document structures or script patterns frequently deliver payloads or exploit local vulnerabilities.",
                    confidence=finding.confidence,
                    raw_evidence=finding.evidence,
                )
            )

        defanged_name = f"[FILE] {validated_file.client_filename}"
        normalized_input = NormalizedInput(
            target_type="FILE",
            raw_target=validated_file.client_filename,
            defanged_target=defanged_name,
            target_hash=validated_file.sha256_hash,
            indicators=indicators,
            metadata=inspection.metadata,
        )

        # 6. Evaluate via Unified Security Engine
        assessment = UnifiedSecurityEngine.evaluate(normalized_input, threat_intel)

        # 7. AI Explanation Synthesis with Deterministic Fallback
        exec_summary, layman_verdict = await self.explainer.explain(
            findings=assessment["evidence_items"],
            risk_score=assessment["risk_score"],
            risk_level=assessment["risk_level"],
            fallback_summary=assessment["executive_summary"],
            fallback_verdict=assessment["layman_verdict"],
            context_notes=f"File: {validated_file.client_filename} ({validated_file.detected_format.upper()}, {validated_file.file_size_bytes} bytes)",
        )

        # 8. Populate Technical Metadata
        tech_meta = TechnicalMetadata(
            domain="",
            subdomain="",
            registered_domain="",
            tld="",
            ip_addresses=[],
            entropy=0.0,
            detected_brands=[],
            extracted_urls=inspection.extracted_urls,
            social_engineering_flags=[],
            file_name=validated_file.client_filename,
            file_size_bytes=validated_file.file_size_bytes,
            file_hash_sha256=validated_file.sha256_hash,
            file_hash_md5=validated_file.md5_hash,
            mime_type=validated_file.mime_type,
            is_executable=validated_file.is_executable,
            threat_intel_summary=threat_intel.raw_summary if threat_intel else None,
            threat_intel_permalink=threat_intel.permalink if threat_intel else None,
        )

        now_dt = get_monotonic_utc_now()
        now_str = now_dt.isoformat()
        scan_id = uuid.uuid4()

        # 9. Database Persistence (Strict user isolation; skipped for guests)
        if user_id is not None and db is not None:
            try:
                scan = Scan(
                    id=scan_id,
                    user_id=user_id,
                    input_type="FILE",
                    input_hash=validated_file.sha256_hash,
                    risk_score=assessment["risk_score"],
                    verdict=assessment["risk_level"].value,
                    created_at=now_dt,
                )
                db.add(scan)

                # Persist structured findings
                for item in assessment["evidence_items"]:
                    db_finding = Finding(
                        id=uuid.uuid4(),
                        scan_id=scan_id,
                        indicator_type=item.title[:64],
                        indicator=item.technical_proof[:512],
                        severity=item.severity.value,
                        source="FILE_INSPECTOR" if "Threat Intel" not in item.title else "VIRUSTOTAL",
                        explanation=item.description,
                        created_at=now_dt,
                    )
                    db.add(db_finding)

                # Persist Audit Log
                audit_entry = AuditLog(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    scan_id=scan_id,
                    event_type="FILE_SCAN_COMPLETED",
                    details={
                        "target_type": "FILE",
                        "client_filename": validated_file.client_filename,
                        "file_size_bytes": validated_file.file_size_bytes,
                        "mime_type": validated_file.mime_type,
                        "sha256": validated_file.sha256_hash,
                        "is_executable": validated_file.is_executable,
                        "storage_key": stored_meta.storage_key,
                        "risk_score": assessment["risk_score"],
                        "verdict": assessment["risk_level"].value,
                        "threat_intel_status": threat_intel.status.value if threat_intel else "NONE",
                    },
                    created_at=now_dt,
                )
                db.add(audit_entry)
                await db.commit()
            except Exception as db_exc:
                logger.error(f"Failed to persist authenticated file scan to database: {db_exc}", exc_info=True)

        return ThreatReport(
            scan_id=str(scan_id),
            target_type=TargetType.FILE,
            raw_target=validated_file.client_filename,
            defanged_target=defanged_name,
            risk_score=assessment["risk_score"],
            risk_level=assessment["risk_level"],
            confidence_score=assessment["confidence_score"],
            executive_summary=exec_summary,
            layman_verdict=layman_verdict,
            evidence_items=assessment["evidence_items"],
            recommended_actions=assessment["recommended_actions"],
            technical_metadata=tech_meta,
            analyzed_at=now_str,
        )
