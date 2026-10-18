import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.base import ScreenshotStorage
from app.storage.local import LocalScreenshotStorage
from app.analyzers.screenshot.validator import ScreenshotValidator, ValidatedImage
from app.analyzers.screenshot.normalizer import normalize_ocr_text, NormalizedOCR
from app.analyzers.screenshot.vision.base import VisionProvider
from app.analyzers.screenshot.vision.gemini import GeminiVisionProvider
from app.analyzers.screenshot.engine import analyze_screenshot_heuristics, ScreenshotHeuristicResult
from app.analyzers.screenshot.scorer import calculate_screenshot_risk_score, ScreenshotRiskAssessment
from app.ai.explainer import ThreatExplainer
from app.analyzers.message.normalizer import normalize_message, NormalizedMessage
from app.analyzers.message.extractor import extract_iocs, ExtractedIOCs
from app.analyzers.message.engine import analyze_message_heuristics, MessageHeuristicResult
from app.analyzers.url.normalizer import normalize_url
from app.analyzers.url.engine import analyze_url_heuristics
from app.analyzers.url.scorer import calculate_risk_score
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

logger = logging.getLogger("xerox.services.screenshot_analysis")


class ScreenshotAnalysisService:
    """Orchestrates secure screenshot upload validation, isolated filesystem storage,
    OCR/vision provider extraction, M6 phishing engine reuse on OCR text,
    M5 URL security engine evaluation on extracted links, deterministic screenshot heuristics,
    transparent risk scoring, AI explanation synthesis, and database persistence with strict user isolation.
    """

    def __init__(
        self,
        storage: Optional[ScreenshotStorage] = None,
        vision_provider: Optional[VisionProvider] = None,
        threat_intel_provider: Optional[ThreatIntelProvider] = None,
        cache: Optional[ThreatIntelCache] = None,
        explainer: Optional[ThreatExplainer] = None,
    ):
        self.storage = storage or LocalScreenshotStorage()
        self.vision_provider = vision_provider or GeminiVisionProvider()
        self.threat_intel_provider = threat_intel_provider or VirusTotalProvider()
        self.cache = cache or ThreatIntelCache()
        self.explainer = explainer or ThreatExplainer()

    async def analyze_screenshot(
        self,
        file_bytes: bytes,
        declared_mime: Optional[str],
        client_filename: Optional[str],
        user_id: uuid.UUID,
        db: AsyncSession,
    ) -> ThreatReport:
        """Executes the complete safe screenshot security analysis pipeline."""

        # 1. Strict Cryptographic & Structure Validation
        val_img: ValidatedImage = ScreenshotValidator.validate(
            file_bytes=file_bytes,
            declared_mime=declared_mime,
            client_filename=client_filename,
        )

        # 2. Persist in Isolated Storage (Outside application source tree, non-user filename)
        stored_meta = await self.storage.save(
            file_bytes=val_img.content,
            extension=val_img.safe_extension,
            mime_type=val_img.mime_type,
            sha256_hash=val_img.sha256_hash,
        )

        # 3. Vision & OCR Extraction
        vision_result = await self.vision_provider.extract(
            image_bytes=val_img.content,
            mime_type=val_img.mime_type,
        )

        # 4. OCR Normalization
        norm_ocr: NormalizedOCR = normalize_ocr_text(vision_result.raw_text)

        # 5. Extract IOCs passively (zero network calls)
        norm_msg: NormalizedMessage = normalize_message(content=norm_ocr.normalized_text)
        iocs: ExtractedIOCs = extract_iocs(norm_msg)

        # Combine URLs from passive regex + vision provider explicit URLs
        combined_urls = list(iocs.urls)
        for v_url in vision_result.visible_urls:
            if v_url not in combined_urls:
                combined_urls.append(v_url)

        combined_domains = list(iocs.domains)
        for v_dom in vision_result.visible_domains:
            if v_dom not in combined_domains:
                combined_domains.append(v_dom)

        # 6. Reuse M6 Message Phishing Engine on OCR text
        message_findings: List[EvidenceItem] = []
        if norm_ocr.char_count > 10:
            msg_heuristics: MessageHeuristicResult = analyze_message_heuristics(norm_msg, iocs)
            message_findings = list(msg_heuristics.findings)

        # 7. Reuse M5 URL Security Engine on all Extracted URLs
        url_findings: List[EvidenceItem] = []
        max_url_score = 0
        has_high_risk_url = False

        for raw_url in combined_urls[:10]:
            try:
                norm_url = normalize_url(raw_url)
                url_heuristics = analyze_url_heuristics(norm_url)
                url_findings.extend(url_heuristics.findings)

                # Threat intel cache gate
                malicious_count = 0
                suspicious_count = 0

                if not url_heuristics.is_private_network:
                    cached_intel = await self.cache.get(norm_url.url_hash)
                    if cached_intel:
                        malicious_count = cached_intel.malicious_count
                        suspicious_count = cached_intel.suspicious_count
                    else:
                        live_intel = await self.threat_intel_provider.lookup_url(norm_url.normalized_url)
                        if live_intel:
                            await self.cache.set(norm_url.url_hash, live_intel)
                            malicious_count = live_intel.malicious_count
                            suspicious_count = live_intel.suspicious_count

                url_score_result = calculate_risk_score(
                    findings=url_heuristics.findings,
                    threat_intel_malicious_count=malicious_count,
                    threat_intel_suspicious_count=suspicious_count,
                )

                if url_score_result.score > max_url_score:
                    max_url_score = url_score_result.score

                if url_score_result.score >= 70:
                    has_high_risk_url = True

            except Exception as exc:
                logger.warning(f"Error analyzing extracted screenshot URL '{raw_url}': {exc}")

        # 8. Deterministic Screenshot Visual Heuristics
        screenshot_heuristics: ScreenshotHeuristicResult = analyze_screenshot_heuristics(
            norm_ocr=norm_ocr,
            vision=vision_result,
            extracted_urls=combined_urls,
            extracted_domains=combined_domains,
        )

        # 9. Cross-Correlation and Transparent Risk Scoring
        all_detected_brands = list(set(screenshot_heuristics.detected_brands + vision_result.detected_brands))
        assessment: ScreenshotRiskAssessment = calculate_screenshot_risk_score(
            screenshot_result=screenshot_heuristics,
            message_findings=message_findings,
            url_findings=url_findings,
            has_high_risk_url=has_high_risk_url,
            max_url_score=max_url_score,
            detected_brands=all_detected_brands,
        )

        # 10. AI Explanation Synthesis (Grounded, with deterministic fallback)
        context_notes = f"Dimensions: {val_img.width}x{val_img.height}, Brands: {all_detected_brands}, Elements: {vision_result.visual_elements}"
        final_summary, final_verdict = await self.explainer.explain(
            findings=assessment.all_findings,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            fallback_summary=assessment.executive_summary,
            fallback_verdict=assessment.layman_verdict,
            context_notes=context_notes,
        )

        # 11. Database Persistence with Strict User Isolation
        scan_id = uuid.uuid4()
        now_dt = get_monotonic_utc_now()

        scan = Scan(
            id=scan_id,
            user_id=user_id,
            input_type="SCREENSHOT",
            input_hash=val_img.sha256_hash,
            risk_score=assessment.risk_score,
            verdict=assessment.risk_level.value,
            created_at=now_dt,
        )
        db.add(scan)

        # Persist findings
        for finding in assessment.all_findings:
            db_finding = Finding(
                id=uuid.uuid4(),
                scan_id=scan_id,
                indicator_type=finding.category.value,
                indicator=finding.title[:512],
                severity=finding.severity.value,
                source="SCREENSHOT_ENGINE",
                explanation=f"{finding.description}\nTechnical Proof: {finding.technical_proof}",
                created_at=now_dt,
            )
            db.add(db_finding)

        # Persist privacy-safe audit log (NO passwords, NO raw OCR text, NO PII)
        audit_details = {
            "storage_key": stored_meta.storage_key,
            "file_size_bytes": val_img.file_size_bytes,
            "mime_type": val_img.mime_type,
            "width": val_img.width,
            "height": val_img.height,
            "sha256": val_img.sha256_hash,
            "extracted_urls_count": len(combined_urls),
            "extracted_domains_count": len(combined_domains),
            "detected_brands": all_detected_brands,
            "visual_elements": vision_result.visual_elements,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value,
            "provider": vision_result.provider_name,
            "provider_available": vision_result.is_available,
        }
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            scan_id=scan_id,
            event_type="SCREENSHOT_ANALYZED",
            details=audit_details,
            created_at=now_dt,
        )
        db.add(audit_log)

        await db.commit()

        # 12. Assemble ThreatReport
        target_display = f"[SCREENSHOT]: {val_img.client_filename} ({val_img.width}x{val_img.height}, {val_img.mime_type})"
        defanged_display = f"[DEFANGED_SCREENSHOT]: {val_img.client_filename} (SHA256: {val_img.sha256_hash[:16]}...)"

        technical_metadata = TechnicalMetadata(
            domain=combined_domains[0] if combined_domains else "visual-capture.local",
            subdomain="",
            registered_domain=combined_domains[0] if combined_domains else "visual-capture.local",
            tld="",
            ip_addresses=iocs.ipv4_addresses[:5],
            entropy=4.2,
            detected_brands=all_detected_brands,
            extracted_urls=combined_urls[:10],
            social_engineering_flags=vision_result.visual_elements + (["Visual Login Form"] if screenshot_heuristics.has_login_form else []),
        )

        return ThreatReport(
            scan_id=str(scan_id),
            target_type=TargetType.SCREENSHOT,
            raw_target=target_display,
            defanged_target=defanged_display,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            confidence_score=assessment.confidence_score,
            executive_summary=final_summary,
            layman_verdict=final_verdict,
            evidence_items=assessment.all_findings,
            recommended_actions=assessment.recommended_actions,
            technical_metadata=technical_metadata,
            analyzed_at=now_dt.isoformat(),
        )
