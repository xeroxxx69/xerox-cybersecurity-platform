import logging
from typing import List, Optional, Dict, Any

from app.schemas.normalized import NormalizedInput, NormalizedIndicator, NormalizedSeverity, NormalizedCategory
from app.schemas.threat import (
    RiskLevel,
    EvidenceItem,
    EvidenceCategory,
    EvidenceSeverity,
    RecommendedAction,
)
from app.threat_intel.schemas import ThreatIntelResult

logger = logging.getLogger("xerox.security_engine")

SEVERITY_MAPPING = {
    NormalizedSeverity.CRITICAL: (EvidenceSeverity.CRITICAL, 50),
    NormalizedSeverity.HIGH: (EvidenceSeverity.HIGH, 25),
    NormalizedSeverity.MEDIUM: (EvidenceSeverity.MEDIUM, 12),
    NormalizedSeverity.LOW: (EvidenceSeverity.LOW, 5),
    NormalizedSeverity.INFO: (EvidenceSeverity.INFO, 0),
}

CATEGORY_MAPPING = {
    NormalizedCategory.INFRASTRUCTURE: EvidenceCategory.INFRASTRUCTURE,
    NormalizedCategory.IDENTITY: EvidenceCategory.IDENTITY,
    NormalizedCategory.CONTENT: EvidenceCategory.CONTENT,
    NormalizedCategory.REPUTATION: EvidenceCategory.REPUTATION,
    NormalizedCategory.CRYPTOGRAPHY: EvidenceCategory.CRYPTOGRAPHY,
}


class UnifiedSecurityEngine:
    """Unified Security Engine for normalized XEROX threat indicators.
    Consistently scores, correlates multi-vector evidence, and renders actionable guidance
    across URLs, Messages, Screenshots, and Files.
    """

    @classmethod
    def evaluate(
        cls,
        normalized: NormalizedInput,
        threat_intel: Optional[ThreatIntelResult] = None,
    ) -> Dict[str, Any]:
        """Evaluates normalized indicators and returns a unified security assessment dictionary:
        {
            "risk_score": int,
            "risk_level": RiskLevel,
            "confidence_score": float,
            "executive_summary": str,
            "layman_verdict": str,
            "evidence_items": List[EvidenceItem],
            "recommended_actions": List[RecommendedAction]
        }
        """
        evidence_items: List[EvidenceItem] = []
        raw_score = 0
        max_severity = EvidenceSeverity.INFO

        # 1. Ingest Normalized Indicators
        for ind in normalized.indicators:
            ev_sev, default_weight = SEVERITY_MAPPING.get(ind.severity, (EvidenceSeverity.LOW, 5))
            ev_cat = CATEGORY_MAPPING.get(ind.category, EvidenceCategory.CONTENT)
            weight = ind.weight if ind.weight > 0 else default_weight

            raw_score += weight

            # Track maximum severity
            if ev_sev == EvidenceSeverity.CRITICAL:
                max_severity = EvidenceSeverity.CRITICAL
            elif ev_sev == EvidenceSeverity.HIGH and max_severity != EvidenceSeverity.CRITICAL:
                max_severity = EvidenceSeverity.HIGH
            elif ev_sev == EvidenceSeverity.MEDIUM and max_severity not in (EvidenceSeverity.CRITICAL, EvidenceSeverity.HIGH):
                max_severity = EvidenceSeverity.MEDIUM
            elif ev_sev == EvidenceSeverity.LOW and max_severity == EvidenceSeverity.INFO:
                max_severity = EvidenceSeverity.LOW

            evidence_items.append(
                EvidenceItem(
                    category=ev_cat,
                    severity=ev_sev,
                    title=ind.indicator_type[:64],
                    description=ind.description,
                    technical_proof=ind.technical_proof[:512],
                    why_this_matters=ind.why_this_matters,
                )
            )

        # 2. Factor External Threat Intelligence
        malicious_count = 0
        suspicious_count = 0
        if threat_intel:
            malicious_count = threat_intel.malicious_count
            suspicious_count = threat_intel.suspicious_count

            if malicious_count > 0:
                ti_sev = EvidenceSeverity.CRITICAL if malicious_count >= 3 else EvidenceSeverity.HIGH
                if ti_sev == EvidenceSeverity.CRITICAL:
                    max_severity = EvidenceSeverity.CRITICAL
                elif max_severity != EvidenceSeverity.CRITICAL:
                    max_severity = EvidenceSeverity.HIGH

                evidence_items.append(
                    EvidenceItem(
                        category=EvidenceCategory.REPUTATION,
                        severity=ti_sev,
                        title=f"Flagged by External Threat Intel ({threat_intel.provider_name})"[:64],
                        description=threat_intel.raw_summary or f"{malicious_count} security engines flagged this item.",
                        technical_proof=(
                            f"Provider: {threat_intel.provider_name} | Malicious: {malicious_count} | "
                            f"Suspicious: {suspicious_count} | Engines: {threat_intel.total_engines}"
                        ),
                        why_this_matters="Consensus detection by global threat intelligence feeds indicates known malicious infrastructure or payload.",
                    )
                )

                if malicious_count >= 5:
                    raw_score = max(raw_score, 92)
                else:
                    raw_score += 35 * malicious_count
            elif suspicious_count >= 2:
                raw_score += 15

        # 3. Minimum floors for severe findings
        if max_severity == EvidenceSeverity.CRITICAL:
            raw_score = max(raw_score, 75)
        elif max_severity == EvidenceSeverity.HIGH:
            raw_score = max(raw_score, 50)

        # Enforce bounds [0, 100]
        final_score = min(100, max(0, raw_score))

        # 4. Map Score to RiskLevel
        if final_score >= 90:
            level = RiskLevel.CRITICAL
        elif final_score >= 70:
            level = RiskLevel.HIGH_RISK
        elif final_score >= 40:
            level = RiskLevel.SUSPICIOUS
        elif final_score >= 16:
            level = RiskLevel.LOW_RISK
        else:
            level = RiskLevel.BENIGN

        # 5. Calculate Confidence Score
        indicator_count = len(evidence_items)
        if indicator_count >= 3 or malicious_count > 0:
            confidence = 95.0
        elif indicator_count >= 1:
            confidence = 88.0
        else:
            confidence = 85.0

        # 6. Generate Layman Verdict & Executive Summary
        layman_verdict, exec_summary = cls._generate_narrative(
            normalized.target_type, level, final_score, evidence_items, normalized.defanged_target
        )

        # 7. Generate Actionable Guidance
        actions = cls._generate_actions(normalized.target_type, level, evidence_items)

        return {
            "risk_score": final_score,
            "risk_level": level,
            "confidence_score": confidence,
            "executive_summary": exec_summary,
            "layman_verdict": layman_verdict,
            "evidence_items": evidence_items,
            "recommended_actions": actions,
        }

    @classmethod
    def _generate_narrative(
        cls,
        target_type: str,
        level: RiskLevel,
        score: int,
        evidence_items: List[EvidenceItem],
        target_name: str,
    ) -> tuple[str, str]:
        if level == RiskLevel.CRITICAL:
            verdict = f"🚨 CRITICAL THREAT DETECTED — DO NOT ENGAGE ({target_type})"
            summary = (
                f"Analysis of '{target_name}' identified critical malicious indicators (Risk Score: {score}/100). "
                f"Defensive engine detected high-severity threats: "
                f"{'; '.join(e.title for e in evidence_items if e.severity == EvidenceSeverity.CRITICAL)[:200]}. "
                "Immediate containment recommended."
            )
        elif level == RiskLevel.HIGH_RISK:
            verdict = f"⚠️ HIGH RISK — SUSPICIOUS PATTERNS IDENTIFIED ({target_type})"
            summary = (
                f"Multiple high-severity risk signals observed in '{target_name}' (Risk Score: {score}/100). "
                "The target strongly exhibits hallmarks of adversarial manipulation, deceptive structure, or untrusted payload delivery."
            )
        elif level == RiskLevel.SUSPICIOUS:
            verdict = f"⚠️ ELEVATED SUSPICION — PROCEED WITH CAUTION ({target_type})"
            summary = (
                f"Target '{target_name}' exhibits anomalous properties (Risk Score: {score}/100). "
                "While not definitively weaponized, observed anomalies warrant elevated caution before interaction."
            )
        elif level == RiskLevel.LOW_RISK:
            verdict = f"ℹ️ LOW RISK — MINOR ANOMALIES NOTED ({target_type})"
            summary = (
                f"Automated static and intelligence checks for '{target_name}' returned low risk (Score: {score}/100). "
                "Minor deviations noted, but no affirmative threats detected."
            )
        else:
            verdict = f"✅ SAFE / BENIGN — NO THREAT INDICATORS FOUND ({target_type})"
            summary = (
                f"Comprehensive defensive evaluation of '{target_name}' found no malicious indicators. "
                "All heuristic and structural checks completed with clean status."
            )
        return verdict, summary

    @classmethod
    def _generate_actions(
        cls,
        target_type: str,
        level: RiskLevel,
        evidence_items: List[EvidenceItem],
    ) -> List[RecommendedAction]:
        actions: List[RecommendedAction] = []

        if level in (RiskLevel.CRITICAL, RiskLevel.HIGH_RISK):
            if target_type in ("URL", "MESSAGE"):
                actions.append(RecommendedAction(
                    priority="IMMEDIATE",
                    action=f"Do not open, click, or authenticate via this {target_type.lower()}.",
                    rationale="High probability of credential interception or malware delivery.",
                    action_type="DO_NOT_CLICK",
                ))
            elif target_type in ("FILE", "SCREENSHOT"):
                actions.append(RecommendedAction(
                    priority="IMMEDIATE",
                    action=f"Do not open, execute, or extract contents of this {target_type.lower()}.",
                    rationale="Defensive analysis detected weaponized or dangerous structures.",
                    action_type="DO_NOT_CLICK",
                ))

            actions.append(RecommendedAction(
                priority="PREVENTATIVE",
                action="If credentials or authentication tokens were entered, reset passwords immediately.",
                rationale="Compromised credentials can be exploited for lateral movement.",
                action_type="CHANGE_PASSWORD",
            ))

            actions.append(RecommendedAction(
                priority="REPORTING",
                action="Report this threat artifact to your organization's Security Operations (SOC) or IT team.",
                rationale="Enables perimeter blocking and protects other team members.",
                action_type="REPORT_PHISHING",
            ))

        elif level == RiskLevel.SUSPICIOUS:
            actions.append(RecommendedAction(
                priority="IMMEDIATE",
                action=f"Verify sender or origin before opening or interacting with this {target_type.lower()}.",
                rationale="Anomalous characteristics require secondary verification.",
                action_type="VERIFY_SENDER",
            ))
            actions.append(RecommendedAction(
                priority="PREVENTATIVE",
                action="Avoid entering personal credentials, financial data, or MFA codes.",
                rationale="Protects against deceptive phishing lures.",
                action_type="DO_NOT_CLICK",
            ))

        else:
            actions.append(RecommendedAction(
                priority="PREVENTATIVE",
                action="Safe to proceed under standard cyber hygiene protocols.",
                rationale="No affirmative threat indicators were identified.",
                action_type="SAFE_TO_PROCEED",
            ))

        return actions
