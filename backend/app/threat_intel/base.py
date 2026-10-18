from abc import ABC, abstractmethod
from app.threat_intel.schemas import ThreatIntelResult


class ThreatIntelProvider(ABC):
    """Abstract interface for external threat intelligence adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the threat intelligence service."""
        pass

    @abstractmethod
    async def lookup_url(self, normalized_url: str) -> ThreatIntelResult:
        """Queries the provider for reputation and detection telemetry on a URL."""
        pass

    @abstractmethod
    async def lookup_file_hash(self, sha256_hash: str) -> ThreatIntelResult:
        """Queries the provider for reputation and detection telemetry on a file hash."""
        pass
