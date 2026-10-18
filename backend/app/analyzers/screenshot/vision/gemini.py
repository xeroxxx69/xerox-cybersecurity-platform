import json
import logging
from typing import Optional
from app.core.config import settings
from app.analyzers.screenshot.vision.base import VisionProvider, VisionExtractionResult

logger = logging.getLogger("xerox.analyzers.screenshot.vision.gemini")


class GeminiVisionProvider(VisionProvider):
    """Google Gemini Vision OCR and visual layout analyzer using google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key if api_key is not None else settings.GEMINI_API_KEY
        self.model = model

    async def extract(self, image_bytes: bytes, mime_type: str) -> VisionExtractionResult:
        """Extracts OCR text and visual elements using Gemini multimodal vision."""
        if not self.api_key or not self.api_key.strip():
            logger.info("GeminiVisionProvider: GEMINI_API_KEY is not configured. Skipping live vision extraction.")
            return VisionExtractionResult(
                raw_text="",
                visible_urls=[],
                visible_domains=[],
                visible_emails=[],
                detected_brands=[],
                visual_elements=[],
                confidence_score=0.0,
                provider_name="gemini",
                is_available=False,
                status_message="Gemini Vision provider unavailable: API key not configured.",
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            system_instruction = (
                "You are an automated OCR and visual cybersecurity parser. "
                "Analyze this screenshot image and extract all visible text, visible URLs, "
                "visible domain names, visible email addresses, detected brand logos/names, "
                "and visual UI elements (such as 'login_form', 'password_field', 'qr_code', "
                "'security_alert_banner', 'countdown_timer', 'captcha_verification'). "
                "Respond ONLY with a valid JSON object matching this structure:\n"
                "{\n"
                '  "raw_text": "all visible text extracted verbatim",\n'
                '  "visible_urls": ["url1", "url2"],\n'
                '  "visible_domains": ["domain1", "domain2"],\n'
                '  "visible_emails": ["email1"],\n'
                '  "detected_brands": ["brand1"],\n'
                '  "visual_elements": ["login_form", "security_alert_banner"],\n'
                '  "confidence_score": 95.0\n'
                "}\n"
                "Do not invent text or URLs not present in the image. Do not include markdown formatting or backticks."
            )

            import asyncio

            image_part = types.Part.from_bytes(
                data=image_bytes,
                mime_type=mime_type,
            )

            response = await asyncio.to_thread(
                client.models.generate_content,
                model=self.model,
                contents=[image_part, "Extract all OCR text and visual elements."],
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    temperature=0.0,
                ),
            )

            if not response.text:
                return VisionExtractionResult(
                    raw_text="",
                    visible_urls=[],
                    visible_domains=[],
                    visible_emails=[],
                    detected_brands=[],
                    visual_elements=[],
                    confidence_score=0.0,
                    provider_name="gemini",
                    is_available=True,
                    status_message="Gemini returned empty response.",
                )

            data = json.loads(response.text)

            return VisionExtractionResult(
                raw_text=data.get("raw_text", ""),
                visible_urls=data.get("visible_urls", []) or [],
                visible_domains=data.get("visible_domains", []) or [],
                visible_emails=data.get("visible_emails", []) or [],
                detected_brands=data.get("detected_brands", []) or [],
                visual_elements=data.get("visual_elements", []) or [],
                confidence_score=float(data.get("confidence_score", 90.0)),
                provider_name="gemini",
                is_available=True,
                status_message="Successfully extracted visual indicators and OCR text.",
                metadata={"model": self.model},
            )

        except Exception as exc:
            logger.warning(f"GeminiVisionProvider extraction error: {exc}")
            return VisionExtractionResult(
                raw_text="",
                visible_urls=[],
                visible_domains=[],
                visible_emails=[],
                detected_brands=[],
                visual_elements=[],
                confidence_score=0.0,
                provider_name="gemini",
                is_available=False,
                status_message=f"Gemini Vision extraction failed: {str(exc)}",
            )
