import logging
from typing import List, Tuple, Optional
from app.core.config import settings
from app.schemas.threat import EvidenceItem, RiskLevel

logger = logging.getLogger("xerox.ai.explainer")


class ThreatExplainer:
    """Provides human-readable security explanations synthesized from verified findings.
    Uses Google Gemini when configured, or deterministic rule-based explanations as fallback.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key if api_key is not None else settings.GEMINI_API_KEY
        self.model = model

    async def explain(
        self,
        findings: List[EvidenceItem],
        risk_score: int,
        risk_level: RiskLevel,
        fallback_summary: str,
        fallback_verdict: str,
        context_notes: str = "",
    ) -> Tuple[str, str]:
        """Synthesizes an executive summary and layman verdict.
        Returns: (executive_summary, layman_verdict)
        """
        if not self.api_key or not self.api_key.strip() or not findings:
            return fallback_summary, fallback_verdict

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            finding_bullets = "\n".join(
                [f"- [{f.severity.value}] {f.title}: {f.description}" for f in findings[:6]]
            )

            prompt = (
                f"You are a cybersecurity expert on the XEROX platform.\n"
                f"Risk Level: {risk_level.value} (Score: {risk_score}/100)\n"
                f"Context: {context_notes}\n"
                f"Verified Findings:\n{finding_bullets}\n\n"
                f"Task: Write two things strictly based on the findings above:\n"
                f"1. A 1-sentence plain-English layman verdict (e.g., 'Critical Threat: Fake Microsoft Login Lure').\n"
                f"2. A 2-sentence executive summary explaining why it is suspicious and what the attacker is attempting.\n"
                f"Rules: Do NOT invent facts not listed in the findings. Do NOT mention code or internal variables.\n"
                f"Format as JSON: {{\"layman_verdict\": \"...\", \"executive_summary\": \"...\"}}"
            )

            import asyncio

            response = await asyncio.to_thread(
                client.models.generate_content,
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )

            if response.text:
                import json
                data = json.loads(response.text)
                summary = data.get("executive_summary", fallback_summary)
                verdict = data.get("layman_verdict", fallback_verdict)
                return summary, verdict

        except Exception as exc:
            logger.warning(f"ThreatExplainer Gemini error: {exc}. Using deterministic fallback.")

        return fallback_summary, fallback_verdict
