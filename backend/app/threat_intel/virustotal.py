import base64
import logging
from typing import Optional
import httpx

from app.core.config import settings
from app.threat_intel.base import ThreatIntelProvider
from app.threat_intel.schemas import ThreatIntelResult, ThreatIntelStatus

logger = logging.getLogger("xerox.threat_intel.virustotal")


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 Threat Intelligence Adapter.
    
    CRITICAL:
    - Never queries the target website; queries VirusTotal's indexed reputation database.
    - Gracefully handles missing credentials, rate-limiting, and network timeouts.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        self.api_key = api_key if api_key is not None else settings.VIRUSTOTAL_API_KEY
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "VirusTotal v3"

    def _generate_url_id(self, url: str) -> str:
        """Generates base64url identifier according to VirusTotal v3 specifications."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

    async def lookup_url(self, normalized_url: str) -> ThreatIntelResult:
        """Queries VirusTotal API v3 for URL reputation metrics."""
        if not self.api_key or not self.api_key.strip():
            logger.info("VirusTotal lookup skipped: No API key configured.")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.NOT_CONFIGURED,
                raw_summary="VirusTotal API key not configured in environment.",
            )

        url_id = self._generate_url_id(normalized_url)
        endpoint = f"{self.BASE_URL}/urls/{url_id}"
        headers = {
            "x-apikey": self.api_key.strip(),
            "User-Agent": "Xerox-Cyber-Defensive-Engine/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    # Categorize overall status
                    if malicious >= 3:
                        status = ThreatIntelStatus.MALICIOUS
                    elif malicious >= 1 or suspicious >= 2:
                        status = ThreatIntelStatus.SUSPICIOUS
                    elif harmless > 0:
                        status = ThreatIntelStatus.CLEAN
                    else:
                        status = ThreatIntelStatus.UNKNOWN

                    categories = list(attributes.get("categories", {}).values())

                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=status,
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        undetected_count=undetected,
                        total_engines=total,
                        categories=categories,
                        raw_summary=f"{malicious}/{total} security vendors flagged this URL as malicious.",
                    )

                elif response.status_code == 404:
                    # URL has not been submitted or observed by VirusTotal yet
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.UNKNOWN,
                        raw_summary="Unobserved in global VirusTotal threat database.",
                    )

                elif response.status_code == 429:
                    logger.warning("VirusTotal API rate limit reached (HTTP 429).")
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.RATE_LIMITED,
                        raw_summary="VirusTotal quota/rate limit reached.",
                    )

                else:
                    logger.warning(f"VirusTotal lookup unexpected status: {response.status_code}")
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.UNAVAILABLE,
                        raw_summary=f"VirusTotal returned HTTP {response.status_code}.",
                    )

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.warning(f"VirusTotal lookup connection error: {exc}")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.UNAVAILABLE,
                raw_summary=f"VirusTotal service unreachable: {type(exc).__name__}",
            )
        except Exception as exc:
            logger.error(f"Unexpected error in VirusTotal lookup: {exc}")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.UNAVAILABLE,
                raw_summary="Internal error during provider parsing.",
            )

    async def lookup_file_hash(self, sha256_hash: str) -> ThreatIntelResult:
        """Queries VirusTotal API v3 for file hash reputation metrics."""
        clean_hash = sha256_hash.strip().lower()
        if not self.api_key or not self.api_key.strip():
            logger.info("VirusTotal file hash lookup skipped: No API key configured.")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.NOT_CONFIGURED,
                raw_summary="VirusTotal API key not configured in environment.",
            )

        endpoint = f"{self.BASE_URL}/files/{clean_hash}"
        headers = {
            "x-apikey": self.api_key.strip(),
            "User-Agent": "Xerox-Cyber-Defensive-Engine/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    # Categorize overall status
                    if malicious >= 3:
                        status = ThreatIntelStatus.MALICIOUS
                    elif malicious >= 1 or suspicious >= 2:
                        status = ThreatIntelStatus.SUSPICIOUS
                    elif harmless > 0:
                        status = ThreatIntelStatus.CLEAN
                    else:
                        status = ThreatIntelStatus.UNKNOWN

                    popular_threat = attributes.get("popular_threat_classification", {})
                    suggested_label = popular_threat.get("suggested_threat_label", "")
                    categories = [suggested_label] if suggested_label else []

                    permalink = f"https://www.virustotal.com/gui/file/{clean_hash}"

                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=status,
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        harmless_count=harmless,
                        undetected_count=undetected,
                        total_engines=total,
                        permalink=permalink,
                        categories=categories,
                        raw_summary=f"{malicious}/{total} security engines flagged this file hash as malicious.",
                    )

                elif response.status_code == 404:
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.UNKNOWN,
                        permalink=f"https://www.virustotal.com/gui/file/{clean_hash}",
                        raw_summary="File hash unobserved in global VirusTotal threat database.",
                    )

                elif response.status_code == 429:
                    logger.warning("VirusTotal API rate limit reached (HTTP 429).")
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.RATE_LIMITED,
                        raw_summary="VirusTotal quota/rate limit reached.",
                    )

                else:
                    logger.warning(f"VirusTotal file hash lookup unexpected status: {response.status_code}")
                    return ThreatIntelResult(
                        provider_name=self.name,
                        status=ThreatIntelStatus.UNAVAILABLE,
                        raw_summary=f"VirusTotal returned HTTP {response.status_code}.",
                    )

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.warning(f"VirusTotal file hash lookup connection error: {exc}")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.UNAVAILABLE,
                raw_summary=f"VirusTotal service unreachable: {type(exc).__name__}",
            )
        except Exception as exc:
            logger.error(f"Unexpected error in VirusTotal file hash lookup: {exc}")
            return ThreatIntelResult(
                provider_name=self.name,
                status=ThreatIntelStatus.UNAVAILABLE,
                raw_summary="Internal error during provider parsing.",
            )
