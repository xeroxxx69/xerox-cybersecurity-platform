from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.schemas.health import HealthResponse, LivenessReadinessResponse
from app.database.session import check_db_health
from app.cache.redis_client import check_redis_health

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    db_result = await check_db_health()
    db_status = db_result.get("status", "unknown")

    cache_result = await check_redis_health()
    cache_status = cache_result.get("status", "unknown")

    is_healthy = db_status == "connected"
    overall_status = "healthy" if is_healthy else "degraded"

    checks = {
        "liveness": "ok",
        "readiness": "ok" if is_healthy else "failed",
        "database": "ok" if db_status == "connected" else "failed",
        "cache": "ok" if cache_status == "connected" else ("bypassed" if cache_status == "bypassed" else "failed"),
    }

    payload = HealthResponse(
        status=overall_status,
        service="XEROX Autonomous Cybersecurity Engine",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        database=db_status,
        cache=cache_status,
        checks=checks,
    )

    if not is_healthy:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload.model_dump(),
        )

    return payload


@router.get("/health/live", response_model=LivenessReadinessResponse)
async def health_liveness():
    """Liveness probe: verifies the backend web process is running and accepting HTTP requests."""
    return LivenessReadinessResponse(
        status="ok",
        service="XEROX Autonomous Cybersecurity Engine",
        checks={"liveness": "ok"},
    )


@router.get("/health/ready", response_model=LivenessReadinessResponse)
async def health_readiness():
    """Readiness probe: verifies critical dependencies (database) are operational."""
    db_result = await check_db_health()
    db_ok = db_result.get("status") == "connected"

    payload = LivenessReadinessResponse(
        status="ok" if db_ok else "degraded",
        service="XEROX Autonomous Cybersecurity Engine",
        checks={"database": "ok" if db_ok else "failed"},
    )

    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload.model_dump(),
        )

    return payload

