import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.message.normalizer import normalize_message, NormalizedMessage
from app.analyzers.message.extractor import extract_iocs, ExtractedIOCs
from app.analyzers.message.engine import analyze_message_heuristics, MessageHeuristicResult
from app.analyzers.message.scorer import calculate_message_risk_score, MessageRiskAssessment
from app.analyzers.url.normalizer import normalize_url
from app.analyzers.url.engine import analyze_url_heuristics
from app.analyzers.url.scorer import calculate_risk_score
from app.ai.explainer import ThreatExplainer
from app.cache.redis_client import ThreatIntelCache
from app.threat_intel.base import ThreatIntelProvider
from app.threat_intel.virustotal import VirusTotalProvider
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
    TechnicalMetadata,
)

logger = logging.getLogger("xerox.services.message_analysis")


class MessageAnalysisService:
    """Orchestrates message normalization, IOC extraction, deterministic phishing analysis,
    M5 URL security engine evaluation with Redis threat-intel caching, correlation,
    and database persistence with strict per-user tenant isolation.
    """

    def __init__(
        self,
        threat_intel_provider: Optional[ThreatIntelProvider] = None,
        cache: Optional[ThreatIntelCache] = None,
        explainer: Optional[ThreatExplainer] = None,
    ):
        self.threat_intel_provider = threat_intel_provider or VirusTotalProvider()
        self.cache = cache or ThreatIntelCache()
        self.explainer = explainer or ThreatExplainer()

    async def analyze_message(
        self,
        content: str,
        user_id: uuid.UUID,
        db: AsyncSession,
        subject: Optional[str] = None,
        sender: Optional[str] = None,
        sender_metadata: Optional[str] = None,
    ) -> ThreatReport:
        """Executes the complete message and phishing security analysis pipeline.
        
        CRITICAL SECURITY ARCHITECTURE:
        - Content -> Normalization -> IOC Extraction -> Deterministic Heuristics -> M5 URL Engine -> Threat Intel -> Scorer -> DB
        - No outbound socket or network requests are ever made to targets or message-linked resources.
        - Strict tenant isolation: persisted records are scoped to `user_id`.
        """
        # 1. Normalize Message
        norm_msg: NormalizedMessage = normalize_message(
            content=content,
            subject=subject,
            sender=sender,
            sender_metadata=sender_metadata,
        )

        # 2. Extract IOCs and URLs passively
        iocs: ExtractedIOCs = extract_iocs(norm_msg)

        # 3. Deterministic Message-Level Phishing Heuristics
        heuristics_result: MessageHeuristicResult = analyze_message_heuristics(norm_msg, iocs)
        combined_findings: List[EvidenceItem] = list(heuristics_result.findings)

        # 4. Reuse M5 URL Security Engine for each extracted URL
        url_findings: List[EvidenceItem] = []
        max_url_score = 0
        has_high_risk_url = False
        url_detected_brands: List[str] = []

        for raw_url in iocs.urls[:10]:  # Evaluate up to 10 unique embedded URLs
            try:
                norm_url = normalize_url(raw_url)
                url_res = analyze_url_heuristics(norm_url)
                url_detected_brands.extend(url_res.metadata.detected_brands)

                # Cache-first threat intelligence lookup (SSRF safe: skipped for private networks)
                threat_intel = None
                malicious_count = 0
                suspicious_count = 0

                if not url_res.is_private_network:
                    cached_intel = await self.cache.get(norm_url.url_hash)
                    if cached_intel is not None:
                        threat_intel = cached_intel
                    else:
                        try:
                            threat_intel = await self.threat_intel_provider.lookup_url(norm_url.normalized_url)
                            await self.cache.set(norm_url.url_hash, threat_intel)
                        except Exception as exc:
                            logger.warning(f"Threat intel lookup failed for embedded URL: {exc}")
                            threat_intel = None

                    if threat_intel:
                        malicious_count = threat_intel.malicious_count
                        suspicious_count = threat_intel.suspicious_count

                # Calculate individual URL score
                url_assessment = calculate_risk_score(
                    findings=url_res.findings,
                    threat_intel_malicious_count=malicious_count,
                    threat_intel_suspicious_count=suspicious_count,
                )

                if url_assessment.score > max_url_score:
                    max_url_score = url_assessment.score

                if url_assessment.score >= 70:
                    has_high_risk_url = True

                # Prefix URL findings so they are transparently attributed in the dossier
                for finding in url_res.findings:
                    if finding.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL):
                        url_findings.append(
                            EvidenceItem(
                                category=finding.category,
                                severity=finding.severity,
                                title=f"Embedded Link Risk: {finding.title}"[:64],
                                description=f"[Target: {norm_url.defanged_url}] {finding.description}",
                                technical_proof=finding.technical_proof,
                                why_this_matters=finding.why_this_matters,
                            )
                        )
            except Exception as exc:
                logger.warning(f"Error evaluating embedded URL '{raw_url}': {exc}")

        # 5. Cross-Correlation Analysis
        has_social_coercion = bool(heuristics_result.social_engineering_flags)
        has_correlation = False

        if has_social_coercion and has_high_risk_url:
            has_correlation = True
            combined_findings.append(
                EvidenceItem(
                    category=EvidenceCategory.CONTENT,
                    severity=EvidenceSeverity.CRITICAL,
                    title="Coercive Social Engineering Paired with Malicious Link"[:64],
                    description=(
                        "The message combines urgent psychological pressure or credential solicitation "
                        "with an embedded link that points to high-risk or deceptive web infrastructure."
                    ),
                    technical_proof=(
                        f"Urgency/Lure Triggers: {', '.join(heuristics_result.social_engineering_flags[:3])} | "
                        f"Embedded URL Max Risk: {max_url_score}/100"
                    ),
                    why_this_matters=(
                        "The pairing of artificial urgency with an unaccredited landing destination is the definitive "
                        "operational signature of active credential harvesting and targeted smishing/phishing."
                    ),
                )
            )

        # Append unique URL findings
        combined_findings.extend(url_findings)

        # 6. Combined Transparent Risk Scoring
        assessment: MessageRiskAssessment = calculate_message_risk_score(
            message_findings=heuristics_result.findings,
            url_findings=url_findings,
            url_max_score=max_url_score,
            has_correlation=has_correlation,
        )

        # AI Explanation Synthesis with Deterministic Fallback
        exec_summary, layman_verdict = await self.explainer.explain(
            findings=combined_findings,
            risk_score=assessment.score,
            risk_level=assessment.level,
            fallback_summary=assessment.executive_summary,
            fallback_verdict=assessment.layman_verdict,
            context_notes=f"Message subject: {norm_msg.subject or 'None'}, sender: {norm_msg.sender or 'None'}",
        )

        now_dt = get_monotonic_utc_now()
        # 7. Database Persistence (Strict user_id tenant isolation)
        scan = Scan(
            user_id=user_id,
            input_type="MESSAGE",
            input_hash=norm_msg.content_hash,
            risk_score=assessment.score,
            verdict=assessment.level.value,
            created_at=now_dt,
        )
        db.add(scan)
        await db.flush()  # Populates scan.id

        # Persist structured findings (enforcing schema bounds)
        for finding in combined_findings:
            db_finding = Finding(
                scan_id=scan.id,
                indicator_type=finding.title[:64],
                indicator=finding.technical_proof[:512],
                severity=finding.severity.value,
                source="PHISHING_DETECTOR" if "Embedded Link" not in finding.title else "URL_ENGINE",
                explanation=finding.description,
            )
            db.add(db_finding)

        # Assemble TechnicalMetadata
        all_detected_brands = list(set(heuristics_result.detected_brands + url_detected_brands))
        metadata = TechnicalMetadata(
            extracted_urls=iocs.urls,
            detected_brands=all_detected_brands,
            social_engineering_flags=heuristics_result.social_engineering_flags,
            domain=iocs.domains[0] if iocs.domains else "",
            ip_addresses=iocs.ipv4_addresses + iocs.ipv6_addresses,
        )

        # Record Audit Log
        audit_entry = AuditLog(
            user_id=user_id,
            scan_id=scan.id,
            event_type="MESSAGE_SCAN_COMPLETED",
            details={
                "target_type": "MESSAGE",
                "raw_target": norm_msg.raw_content[:200],
                "defanged_target": norm_msg.defanged_content[:200],
                "subject": norm_msg.subject,
                "sender": norm_msg.sender,
                "sender_metadata": norm_msg.sender_metadata,
                "risk_score": assessment.score,
                "verdict": assessment.level.value,
                "confidence_score": assessment.confidence,
                "executive_summary": exec_summary,
                "layman_verdict": layman_verdict,
                "findings_count": len(combined_findings),
                "extracted_urls_count": len(iocs.urls),
                "extracted_iocs": {
                    "urls": iocs.urls,
                    "domains": iocs.domains,
                    "ipv4": iocs.ipv4_addresses,
                    "emails": iocs.email_addresses,
                    "phones": iocs.phone_numbers,
                },
                "recommended_actions": [a.model_dump() for a in assessment.recommended_actions],
                "technical_metadata": metadata.model_dump(),
            },
        )
        db.add(audit_entry)

        await db.commit()
        await db.refresh(scan)

        # 8. Assemble ThreatReport
        analyzed_at_str = scan.created_at.isoformat()

        return ThreatReport(
            scan_id=str(scan.id),
            target_type=TargetType.MESSAGE,
            raw_target=norm_msg.raw_content,
            defanged_target=norm_msg.defanged_content,
            risk_score=assessment.score,
            risk_level=assessment.level,
            confidence_score=assessment.confidence,
            executive_summary=exec_summary,
            layman_verdict=layman_verdict,
            evidence_items=combined_findings,
            recommended_actions=assessment.recommended_actions,
            technical_metadata=metadata,
            analyzed_at=analyzed_at_str,
        )
