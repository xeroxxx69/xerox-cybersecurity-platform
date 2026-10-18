import json
import logging
from typing import Optional
import redis.asyncio as aioredis
from app.core.config import settings
from app.threat_intel.schemas import ThreatIntelResult

logger = logging.getLogger("xerox.cache.redis")

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> Optional[aioredis.Redis]:
    """Returns the global Redis client or None if connection fails."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    try:
        client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
        )
        # Test connection ping
        await client.ping()
        _redis_client = client
        return _redis_client
    except Exception as exc:
        logger.warning(f"Redis unavailable ({exc}). Continuing with caching bypassed.")
        return None


def set_redis_client(client: Optional[aioredis.Redis]) -> None:
    """Allows injecting mock or fakeredis client for testing."""
    global _redis_client
    _redis_client = client


async def check_redis_health() -> dict[str, str]:
    """Probes Redis connection health using PING."""
    client = await get_redis()
    if client is None:
        return {"status": "bypassed", "details": "Redis unavailable or unconfigured; caching bypassed"}
    try:
        pong = await client.ping()
        if pong:
            return {"status": "connected", "details": "Redis responding normally"}
        return {"status": "degraded", "details": f"Unexpected ping response: {pong}"}
    except Exception as exc:
        return {"status": "unreachable", "details": str(exc)}


class ThreatIntelCache:
    """Redis-backed cache service for threat intelligence lookups."""

    KEY_PREFIX = "xerox:intel:url:"
    FILE_KEY_PREFIX = "xerox:intel:file:"

    def __init__(self, client: Optional[aioredis.Redis] = None, ttl: int = settings.CACHE_TTL_SECONDS):
        self._client = client
        self.ttl = ttl

    async def _get_client(self) -> Optional[aioredis.Redis]:
        if self._client is not None:
            return self._client
        return await get_redis()

    def _make_key(self, url_hash: str) -> str:
        return f"{self.KEY_PREFIX}{url_hash}"

    def _make_file_key(self, file_hash: str) -> str:
        return f"{self.FILE_KEY_PREFIX}{file_hash.lower().strip()}"

    async def get(self, url_hash: str) -> Optional[ThreatIntelResult]:
        """Retrieves cached ThreatIntelResult by URL hash. Returns None on miss or error."""
        try:
            client = await self._get_client()
            if client is None:
                return None

            key = self._make_key(url_hash)
            raw = await client.get(key)
            if not raw:
                return None

            data = json.loads(raw)
            result = ThreatIntelResult(**data)
            result.cached = True
            logger.info(f"Threat intel cache HIT for hash {url_hash[:12]}")
            return result
        except Exception as exc:
            logger.warning(f"Redis get error for hash {url_hash[:12]}: {exc}")
            return None

    async def set(self, url_hash: str, result: ThreatIntelResult) -> bool:
        """Stores ThreatIntelResult in Redis with TTL. Returns True if stored, False otherwise."""
        try:
            client = await self._get_client()
            if client is None:
                return False

            key = self._make_key(url_hash)
            payload = result.model_dump(mode="json")
            await client.set(key, json.dumps(payload), ex=self.ttl)
            logger.info(f"Threat intel cached for hash {url_hash[:12]} (TTL: {self.ttl}s)")
            return True
        except Exception as exc:
            logger.warning(f"Redis set error for hash {url_hash[:12]}: {exc}")
            return False

    async def get_file(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Retrieves cached ThreatIntelResult by file SHA-256 hash."""
        try:
            client = await self._get_client()
            if client is None:
                return None

            key = self._make_file_key(file_hash)
            raw = await client.get(key)
            if not raw:
                return None

            data = json.loads(raw)
            result = ThreatIntelResult(**data)
            result.cached = True
            logger.info(f"File threat intel cache HIT for hash {file_hash[:12]}")
            return result
        except Exception as exc:
            logger.warning(f"Redis get_file error for hash {file_hash[:12]}: {exc}")
            return None

    async def set_file(self, file_hash: str, result: ThreatIntelResult) -> bool:
        """Stores file ThreatIntelResult in Redis with TTL."""
        try:
            client = await self._get_client()
            if client is None:
                return False

            key = self._make_file_key(file_hash)
            payload = result.model_dump(mode="json")
            await client.set(key, json.dumps(payload), ex=self.ttl)
            logger.info(f"File threat intel cached for hash {file_hash[:12]} (TTL: {self.ttl}s)")
            return True
        except Exception as exc:
            logger.warning(f"Redis set_file error for hash {file_hash[:12]}: {exc}")
            return False

