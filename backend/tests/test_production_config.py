import uuid
import pytest
from httpx import AsyncClient
from app.core.config import Settings
from app.cache.redis_client import check_redis_health


def test_database_url_normalization():
    """Verify that postgres:// and postgresql:// are normalized to postgresql+asyncpg://."""
    s1 = Settings(DATABASE_URL="postgres://user:pass@ep-cool-db.us-east-2.aws.neon.tech/xerox_db")
    assert s1.DATABASE_URL.startswith("postgresql+asyncpg://")

    s2 = Settings(DATABASE_URL="postgresql://user:pass@containers-us-west.railway.app:5432/railway")
    assert s2.DATABASE_URL.startswith("postgresql+asyncpg://")

    s3 = Settings(DATABASE_URL="sqlite+aiosqlite:///./test.db")
    assert s3.DATABASE_URL == "sqlite+aiosqlite:///./test.db"


@pytest.mark.asyncio
async def test_dual_auth_via_bearer_token(async_client: AsyncClient):
    """Verify that an API client can authenticate using Authorization: Bearer <session_token> without cookies."""
    email = f"bearer_{uuid.uuid4().hex[:8]}@xerox.sec"
    pwd = "StrongPassword123!"

    # 1. Register
    reg = await async_client.post("/api/v1/auth/register", json={"email": email, "password": pwd})
    assert reg.status_code == 201

    # 2. Login and extract session_token
    login = await async_client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
    assert login.status_code == 200
    token = login.json().get("session_token")
    assert token is not None and len(token) > 16

    # 3. Create a clean client with NO cookies
    from httpx import ASGITransport, AsyncClient as CleanClient
    from app.main import app

    async with CleanClient(transport=ASGITransport(app=app), base_url="http://test") as headless_client:
        # Access /auth/me without header -> 401
        unauth = await headless_client.get("/api/v1/auth/me")
        assert unauth.status_code == 401

        # Access with Authorization: Bearer header -> 200
        auth_header_resp = await headless_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert auth_header_resp.status_code == 200
        assert auth_header_resp.json()["email"] == email

        # Access with X-Session-Token custom header -> 200
        x_token_resp = await headless_client.get(
            "/api/v1/auth/me",
            headers={"X-Session-Token": token},
        )
        assert x_token_resp.status_code == 200
        assert x_token_resp.json()["email"] == email


@pytest.mark.asyncio
async def test_redis_health_probe():
    """Verify check_redis_health returns structured status dictionary."""
    res = await check_redis_health()
    assert "status" in res
    assert res["status"] in ("connected", "bypassed", "degraded", "unreachable")


def test_production_environment_cookie_and_security_defaults():
    """Verify that in production environment, secure cross-site cookie settings are automatically applied."""
    prod_settings = Settings(ENVIRONMENT="production")
    assert prod_settings.ENVIRONMENT == "production"
    assert prod_settings.COOKIE_SECURE is True
    assert prod_settings.COOKIE_SAMESITE == "none"
    assert prod_settings.COOKIE_HTTPONLY is True
    assert prod_settings.DEBUG is False


@pytest.mark.asyncio
async def test_health_alias_endpoints(async_client: AsyncClient):
    """Verify that /health, /api/health, and /api/v1/health return healthy 200 responses."""
    r1 = await async_client.get("/health")
    assert r1.status_code == 200
    assert r1.json()["status"] == "healthy"

    r2 = await async_client.get("/api/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "healthy"

    r3 = await async_client.get("/api/v1/health")
    assert r3.status_code == 200
    assert r3.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_cors_preflight_for_production_origin(async_client: AsyncClient):
    """Verify that OPTIONS preflight requests from https://xeroxxx69.github.io receive valid CORS headers."""
    resp = await async_client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://xeroxxx69.github.io",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://xeroxxx69.github.io"
    assert resp.headers.get("access-control-allow-credentials") == "true"


def test_cors_origins_always_includes_xerox_production():
    """Verify that Settings.CORS_ORIGINS always guarantees inclusion of xeroxxx69.github.io."""
    s = Settings(CORS_ORIGINS=["http://custom.example.com"])
    assert "https://xeroxxx69.github.io" in s.CORS_ORIGINS
    assert "http://custom.example.com" in s.CORS_ORIGINS

    s2 = Settings(CORS_ORIGINS="https://another-domain.com")
    assert "https://xeroxxx69.github.io" in s2.CORS_ORIGINS


@pytest.mark.asyncio
async def test_unhandled_exception_preserves_cors():
    """Verify that an unhandled 500 exception returns JSON with CORS headers intact for xeroxxx69."""
    from httpx import ASGITransport, AsyncClient as CleanClient
    from app.main import app

    # Temporarily register a test route that raises an unhandled error
    @app.get("/api/test-crash-cors")
    async def crash_endpoint():
        raise RuntimeError("Simulated unhandled internal database failure")

    async with CleanClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        resp = await client.get(
            "/api/test-crash-cors",
            headers={"Origin": "https://xeroxxx69.github.io"},
        )
        assert resp.status_code == 500
        assert resp.headers.get("access-control-allow-origin") == "https://xeroxxx69.github.io"
        assert resp.headers.get("access-control-allow-credentials") == "true"
        data = resp.json()
        assert data["detail"] == "Internal server error"
