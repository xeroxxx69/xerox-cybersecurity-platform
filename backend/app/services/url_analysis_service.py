import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.url.normalizer import normalize_url
from app.analyzers.url.engine import analyze_url_heuristics
from app.analyzers.url.scorer import calculate_risk_score, _generate_recommended_actions
from app.ai.explainer import ThreatExplainer
from app.cache.redis_client import ThreatIntelCache
from app.threat_intel.base import ThreatIntelProvider
from app.threat_intel.virustotal import VirusTotalProvider
from app.threat_intel.schemas import ThreatIntelResult, ThreatIntelStatus
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
    ScanHistoryItem,
    StatsSummary,
    RecommendedAction,
    TechnicalMetadata,
)

logger = logging.getLogger("xerox.services.url_analysis")


class URLAnalysisService:
    """Orchestrates URL normalization, deterministic heuristics, threat intelligence cache/provider,
    risk scoring, and database persistence with strict user-scoped tenant isolation.
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

    async def analyze_url(
        self,
        raw_url: str,
        user_id: Optional[uuid.UUID] = None,
        db: Optional[AsyncSession] = None,
    ) -> ThreatReport:
        """Executes the complete URL security analysis pipeline.
        
        CRITICAL ARCHITECTURE:
        - Input -> Normalization -> Deterministic Engine -> Redis Cache -> Threat Intel -> Scorer -> DB
        - No outbound connection to the target URL is ever made.
        - Strict tenant data isolation: persisted records are scoped to `user_id`.
        """
        # 1. Normalize URL
        norm_url = normalize_url(raw_url)

        # 2. Execute Deterministic Static Heuristic Engine
        heuristic_result = analyze_url_heuristics(norm_url)
        findings = list(heuristic_result.findings)

        # 3. Cache-First Threat Intelligence Gate
        threat_intel: Optional[ThreatIntelResult] = None
        malicious_count = 0
        suspicious_count = 0

        # Do NOT query external threat intel for internal/private destinations (SSRF defense)
        if not heuristic_result.is_private_network:
            # Check Redis Cache
            cached_intel = await self.cache.get(norm_url.url_hash)
            if cached_intel is not None:
                threat_intel = cached_intel
            else:
                # Cache miss: query threat intelligence provider
                try:
                    threat_intel = await self.threat_intel_provider.lookup_url(norm_url.normalized_url)
                    # Cache the result
                    await self.cache.set(norm_url.url_hash, threat_intel)
                except Exception as exc:
                    logger.warning(f"Threat intel provider lookup failed: {exc}")
                    threat_intel = None

            if threat_intel:
                malicious_count = threat_intel.malicious_count
                suspicious_count = threat_intel.suspicious_count

                # Add finding if external vendors flag it
                if threat_intel.malicious_count > 0:
                    severity = (
                        EvidenceSeverity.CRITICAL
                        if threat_intel.malicious_count >= 3
                        else EvidenceSeverity.HIGH
                    )
                    findings.append(
                        EvidenceItem(
                            category=EvidenceCategory.REPUTATION,
                            severity=severity,
                            title=f"Flagged by External Threat Intelligence ({threat_intel.provider_name})"[:64],
                            description=(
                                f"{threat_intel.malicious_count} independent security vendors classify this target "
                                "as malicious in global threat telemetry."
                            ),
                            technical_proof=(
                                f"Provider: {threat_intel.provider_name} | Malicious: {threat_intel.malicious_count} | "
                                f"Suspicious: {threat_intel.suspicious_count} | Total Engines: {threat_intel.total_engines}"
                            ),
                            why_this_matters=(
                                "Multi-engine consensus indicates the infrastructure has been previously linked to active "
                                "malware distribution, phishing, or command-and-control operations."
                            ),
                        )
                    )

        # 4. Transparent Weighted Risk Scoring
        assessment = calculate_risk_score(
            findings=findings,
            threat_intel_malicious_count=malicious_count,
            threat_intel_suspicious_count=suspicious_count,
        )

        # AI Explanation Synthesis with Deterministic Fallback
        exec_summary, layman_verdict = await self.explainer.explain(
            findings=findings,
            risk_score=assessment.score,
            risk_level=assessment.level,
            fallback_summary=assessment.executive_summary,
            fallback_verdict=assessment.layman_verdict,
            context_notes=f"URL: {norm_url.raw_url}",
        )

        now_dt = get_monotonic_utc_now()
        scan_id = uuid.uuid4()
        analyzed_at_str = now_dt.isoformat()

        # 5. Database Persistence (Strict user_id tenant isolation for authenticated users)
        if user_id is not None and db is not None:
            try:
                scan = Scan(
                    id=scan_id,
                    user_id=user_id,
                    input_type="URL",
                    input_hash=norm_url.url_hash,
                    risk_score=assessment.score,
                    verdict=assessment.level.value,
                    created_at=now_dt,
                )
                db.add(scan)
                await db.flush()  # Populates scan.id

                # Persist structured findings (enforcing schema bounds)
                for finding in findings:
                    db_finding = Finding(
                        scan_id=scan.id,
                        indicator_type=finding.title[:64],
                        indicator=finding.technical_proof[:512],
                        severity=finding.severity.value,
                        source="STATIC_HEURISTICS" if "Threat Intelligence" not in finding.title else "VIRUSTOTAL",
                        explanation=finding.description,
                    )
                    db.add(db_finding)

                # Record Audit Log with full audit detail payload
                audit_entry = AuditLog(
                    user_id=user_id,
                    scan_id=scan.id,
                    event_type="URL_SCAN_COMPLETED",
                    details={
                        "target_type": "URL",
                        "raw_target": norm_url.raw_url,
                        "defanged_target": norm_url.defanged_url,
                        "risk_score": assessment.score,
                        "verdict": assessment.level.value,
                        "confidence_score": assessment.confidence,
                        "executive_summary": exec_summary,
                        "layman_verdict": layman_verdict,
                        "findings_count": len(findings),
                        "threat_intel_status": threat_intel.status.value if threat_intel else "SKIPPED",
                        "is_cached": threat_intel.cached if threat_intel else False,
                        "recommended_actions": [a.model_dump() for a in assessment.recommended_actions],
                        "technical_metadata": heuristic_result.metadata.model_dump(),
                    },
                )
                db.add(audit_entry)

                await db.commit()
                await db.refresh(scan)
                scan_id = scan.id
                analyzed_at_str = scan.created_at.isoformat()
            except Exception as db_exc:
                logger.error(f"Failed to persist authenticated URL scan to database: {db_exc}", exc_info=True)

        # 6. Assemble ThreatReport
        return ThreatReport(
            scan_id=str(scan_id),
            target_type=TargetType.URL,
            raw_target=norm_url.raw_url,
            defanged_target=norm_url.defanged_url,
            risk_score=assessment.score,
            risk_level=assessment.level,
            confidence_score=assessment.confidence,
            executive_summary=exec_summary,
            layman_verdict=layman_verdict,
            evidence_items=findings,
            recommended_actions=assessment.recommended_actions,
            technical_metadata=heuristic_result.metadata,
            analyzed_at=analyzed_at_str,
        )

    async def get_user_history(
        self,
        user_id: uuid.UUID,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScanHistoryItem]:
        """Returns scan history strictly scoped to the authenticated user."""
        stmt = (
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await db.execute(stmt)
        scans = result.scalars().all()

        items: List[ScanHistoryItem] = []
        for s in scans:
            audit = s.audit_logs[0] if s.audit_logs else None
            audit_details = audit.details if audit and audit.details else {}
            defanged = audit_details.get("defanged_target", f"Target [{s.input_hash[:12]}...]")
            exec_summary = audit_details.get(
                "executive_summary",
                f"Analysis completed with verdict {s.verdict} (Risk Score: {s.risk_score}/100).",
            )
            target_type_val = TargetType.URL
            try:
                target_type_val = TargetType(s.input_type)
            except Exception:
                pass

            items.append(
                ScanHistoryItem(
                    scan_id=str(s.id),
                    target_type=target_type_val,
                    defanged_target=defanged,
                    risk_level=RiskLevel(s.verdict),
                    risk_score=s.risk_score,
                    analyzed_at=s.created_at.isoformat(),
                    executive_summary=exec_summary,
                )
            )
        return items

    async def get_scan_report(
        self,
        scan_id: uuid.UUID,
        user_id: uuid.UUID,
        db: AsyncSession,
    ) -> Optional[ThreatReport]:
        """Loads a detailed ThreatReport for a specific scan, enforcing user tenant isolation."""
        stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            return None

        audit = scan.audit_logs[0] if scan.audit_logs else None
        details = audit.details if audit and audit.details else {}

        raw_target = details.get("raw_target", "unknown")
        defanged_target = details.get("defanged_target", "unknown")
        confidence = float(details.get("confidence_score", 90.0))
        executive_summary = details.get("executive_summary", f"Verdict: {scan.verdict}")
        layman_verdict = details.get("layman_verdict", f"Risk level assessed as {scan.verdict}.")

        evidence_items: List[EvidenceItem] = []
        for f in scan.findings:
            category = EvidenceCategory.REPUTATION if f.source == "VIRUSTOTAL" else EvidenceCategory.INFRASTRUCTURE
            if any(k in f.indicator_type for k in ("Brand", "Identity", "Credential")):
                category = EvidenceCategory.IDENTITY
            elif any(k in f.indicator_type for k in ("SSL", "TLS", "Cryptography")):
                category = EvidenceCategory.CRYPTOGRAPHY

            severity = (
                EvidenceSeverity(f.severity)
                if f.severity in EvidenceSeverity._value2member_map_
                else EvidenceSeverity.MEDIUM
            )
            evidence_items.append(
                EvidenceItem(
                    category=category,
                    severity=severity,
                    title=f.indicator_type,
                    description=f.explanation,
                    technical_proof=f.indicator,
                    why_this_matters="Potential indicator of threat activity.",
                )
            )

        actions_data = details.get("recommended_actions", [])
        if actions_data:
            actions = [RecommendedAction(**a) for a in actions_data]
        else:
            actions = _generate_recommended_actions(RiskLevel(scan.verdict))

        meta_data = details.get("technical_metadata", {})
        tech_metadata = TechnicalMetadata(**meta_data) if meta_data else TechnicalMetadata()

        target_type_val = TargetType.URL
        try:
            target_type_val = TargetType(scan.input_type)
        except Exception:
            pass

        return ThreatReport(
            scan_id=str(scan.id),
            target_type=target_type_val,
            raw_target=raw_target,
            defanged_target=defanged_target,
            risk_score=scan.risk_score,
            risk_level=RiskLevel(scan.verdict),
            confidence_score=confidence,
            executive_summary=executive_summary,
            layman_verdict=layman_verdict,
            evidence_items=evidence_items,
            recommended_actions=actions,
            technical_metadata=tech_metadata,
            analyzed_at=scan.created_at.isoformat(),
        )

    async def get_stats_summary(
        self,
        user_id: uuid.UUID,
        db: AsyncSession,
    ) -> StatsSummary:
        """Calculates security telemetry summary strictly for the authenticated user."""
        stmt = select(Scan).where(Scan.user_id == user_id)
        result = await db.execute(stmt)
        scans = result.scalars().all()

        total = len(scans)
        threats_blocked = sum(1 for s in scans if s.verdict in ("CRITICAL", "HIGH RISK"))
        benign = sum(1 for s in scans if s.verdict in ("BENIGN", "LOW RISK"))
        suspicious = sum(1 for s in scans if s.verdict == "SUSPICIOUS")

        by_type: Dict[str, int] = {}
        for s in scans:
            by_type[s.input_type] = by_type.get(s.input_type, 0) + 1

        return StatsSummary(
            total_scans=total,
            threats_blocked=threats_blocked,
            benign_verified=benign,
            suspicious_flagged=suspicious,
            scans_by_type=by_type,
        )
