from datetime import datetime, timedelta, timezone
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.core.config import settings
from app.database.session import AsyncSessionLocal
from app.models.session import UserSession
from app.models.user import User


@pytest.mark.asyncio
async def test_successful_registration(async_client: AsyncClient):
    """Test standard registration with strong password."""
    email = f"analyst_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "StrongPassword123!"

    response = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email.lower()
    assert "id" in data
    assert "created_at" in data
    assert "password_hash" not in data
    assert "password" not in data


@pytest.mark.asyncio
async def test_duplicate_email_rejection(async_client: AsyncClient):
    """Test duplicate registration fails with 400."""
    email = f"duplicate_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "StrongPassword123!"

    # First registration
    res1 = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert res1.status_code == 201

    # Second registration with same email
    res2 = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_invalid_email_format(async_client: AsyncClient):
    """Test registration rejects malformed email addresses."""
    res = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": "not-an-email", "password": "StrongPassword123!"},
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_weak_password_rejection(async_client: AsyncClient):
    """Test registration enforces strong password validation rules."""
    email = f"weak_{uuid.uuid4().hex[:8]}@xerox.sec"

    # Too short
    res_short = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": "Short1!"},
    )
    assert res_short.status_code == 422

    # Missing special character
    res_no_sym = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": "Password123"},
    )
    assert res_no_sym.status_code == 422

    # Missing digit
    res_no_digit = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": "Password!"},
    )
    assert res_no_digit.status_code == 422


@pytest.mark.asyncio
async def test_password_is_hashed_in_database(async_client: AsyncClient):
    """Verify directly in the database that passwords are encrypted with bcrypt, not plaintext."""
    email = f"hashed_{uuid.uuid4().hex[:8]}@xerox.sec"
    plain_password = "SecurePassword2026!"

    res = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": plain_password},
    )
    assert res.status_code == 201

    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one()

        assert user.password_hash != plain_password
        assert user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$")


@pytest.mark.asyncio
async def test_login_success_and_cookie_attributes(async_client: AsyncClient):
    """Verify login authenticates and sets a secure HttpOnly session cookie."""
    email = f"login_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "CorrectPassword123!"

    # Register
    reg_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_res.status_code == 201

    # Login
    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    user_data = login_res.json()
    assert user_data["email"] == email.lower()
    assert "password_hash" not in user_data

    # Check session cookie
    assert settings.SESSION_COOKIE_NAME in login_res.cookies
    cookie_header = login_res.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header or "samesite=lax" in cookie_header.lower()


@pytest.mark.asyncio
async def test_login_incorrect_password(async_client: AsyncClient):
    """Verify incorrect password returns 401 with generic message."""
    email = f"wrongpw_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "CorrectPassword123!"

    await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )

    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": "WrongPassword999!"},
    )
    assert login_res.status_code == 401
    assert "Incorrect email or password" in login_res.json()["detail"]


@pytest.mark.asyncio
async def test_login_unknown_account_enumeration_protection(async_client: AsyncClient):
    """Verify unknown account receives identical generic error to prevent email enumeration."""
    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "nonexistent_account@xerox.sec", "password": "AnyPassword123!"},
    )
    assert login_res.status_code == 401
    assert "Incorrect email or password" in login_res.json()["detail"]


@pytest.mark.asyncio
async def test_current_user_me_authenticated_and_unauthenticated(async_client: AsyncClient):
    """Verify /auth/me returns user profile when authenticated and 401 when not."""
    # 1. Unauthenticated check
    unauth_res = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert unauth_res.status_code == 401

    # 2. Register & Login
    email = f"me_test_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "MySecurePassword123!"

    await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200

    # 3. Authenticated check with cookie
    me_res = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == email.lower()
    assert "password_hash" not in me_data


@pytest.mark.asyncio
async def test_logout_invalidates_session(async_client: AsyncClient):
    """Verify logout deletes the database session and clears the cookie."""
    email = f"logout_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "LogoutPassword123!"

    await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200

    # Check authenticated
    me_before = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert me_before.status_code == 200

    # Logout
    logout_res = await async_client.post(f"{settings.API_V1_STR}/auth/logout")
    assert logout_res.status_code == 200

    # Verify subsequent request is rejected
    me_after = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert me_after.status_code == 401


@pytest.mark.asyncio
async def test_session_expiration_rejection(async_client: AsyncClient):
    """Verify expired sessions in the database are rejected with 401."""
    email = f"expired_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "ExpiredPassword123!"

    await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    login_res = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200

    # Manually expire the session in the database
    async with AsyncSessionLocal() as session:
        user = (await session.execute(select(User).where(User.email == email))).scalar_one()
        user_session = (
            await session.execute(
                select(UserSession).where(UserSession.user_id == user.id)
            )
        ).scalar_one()
        user_session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await session.commit()

    # Attempt access with expired session
    res = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_security_never_returns_password_hash(async_client: AsyncClient):
    """Verify no auth endpoint exposes password_hash or secret credentials."""
    email = f"audit_{uuid.uuid4().hex[:8]}@xerox.sec"
    password = "AuditPassword123!"

    reg = await async_client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={"email": email, "password": password},
    )
    assert "password_hash" not in reg.text

    login = await async_client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert "password_hash" not in login.text

    me = await async_client.get(f"{settings.API_V1_STR}/auth/me")
    assert "password_hash" not in me.text
