import pytest
from app.threat_intel.virustotal import VirusTotalProvider
from app.threat_intel.schemas import ThreatIntelResult, ThreatIntelStatus
from app.cache.redis_client import ThreatIntelCache


@pytest.mark.asyncio
async def test_virustotal_file_hash_unconfigured():
    provider = VirusTotalProvider(api_key="")
    res = await provider.lookup_file_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res.status == ThreatIntelStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_threat_intel_cache_file_methods():
    # Cache without redis defaults to None / bypass gracefully
    cache = ThreatIntelCache(client=None)
    hash_val = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    
    # Should not raise exception
    res = await cache.get_file(hash_val)
    assert res is None

    test_result = ThreatIntelResult(
        provider_name="VirusTotal v3",
        status=ThreatIntelStatus.CLEAN,
        malicious_count=0,
        total_engines=70,
    )
    saved = await cache.set_file(hash_val, test_result)
    assert saved is False  # No client connected
