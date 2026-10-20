import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.v1.router import api_router
from app.schemas.health import RootResponse
from app.database.session import check_db_health

logger = logging.getLogger("xerox.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence: Ensure all database tables exist
    try:
        from alembic.config import Config
        from alembic import command
        import asyncio
        import os
        alembic_ini_path = "alembic.ini" if os.path.exists("alembic.ini") else os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
        if os.path.exists(alembic_ini_path):
            cfg = Config(alembic_ini_path)
            await asyncio.to_thread(command.upgrade, cfg, "head")
            logger.info("Alembic database migrations applied successfully on startup.")
    except Exception as m_exc:
        logger.warning("Alembic startup migration warning: %s. Ensuring tables with metadata fallback.", m_exc)

    try:
        from app.models import Base
        from app.database.session import engine
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema tables verified/created successfully.")
    except Exception as c_exc:
        logger.error("Critical: Database table initialization failed: %s", c_exc, exc_info=True)

    yield
    # Shutdown sequence


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="XEROX Autonomous Cybersecurity Analysis Platform API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https://[a-zA-Z0-9-]+\.github\.io$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Global fallback exception handler ensuring CORS headers are always returned on 500s."""
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    response = JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
    origin = request.headers.get("origin")
    allowed_origins = {o.rstrip("/") for o in settings.CORS_ORIGINS}
    is_github_io = bool(origin and origin.startswith("https://") and origin.endswith(".github.io"))
    if origin and (origin.rstrip("/") in allowed_origins or origin in settings.CORS_ORIGINS or "*" in settings.CORS_ORIGINS or is_github_io):
        req_headers = request.headers.get("access-control-request-headers")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
        response.headers["Access-Control-Allow-Headers"] = req_headers if req_headers else "Content-Type, Authorization, X-Session-Token"
    return response


# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health")
@app.get("/api/health")
async def health_alias():
    db_res = await check_db_health()
    db_status = db_res.get("status", "unknown")
    is_healthy = db_status == "connected"
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "XEROX Cybersecurity Core",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "checks": {
            "liveness": "ok",
            "readiness": "ok" if is_healthy else "failed",
            "database": "ok" if is_healthy else "failed",
        },
    }


@app.get("/health/live")
async def health_live_root():
    return {
        "status": "ok",
        "service": "XEROX Cybersecurity Core",
        "checks": {"liveness": "ok"},
    }


@app.get("/health/ready")
async def health_ready_root():
    db_res = await check_db_health()
    is_ok = db_res.get("status") == "connected"
    res = {
        "status": "ok" if is_ok else "degraded",
        "service": "XEROX Cybersecurity Core",
        "checks": {"database": "ok" if is_ok else "failed"},
    }
    if not is_ok:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=res)
    return res



@app.get("/", response_model=RootResponse)
async def root():
    return RootResponse(
        brand="XEROX",
        product="Autonomous AI Cybersecurity Analysis Platform",
        status="OPERATIONAL",
        version=settings.VERSION,
        docs_url="/docs",
    )
