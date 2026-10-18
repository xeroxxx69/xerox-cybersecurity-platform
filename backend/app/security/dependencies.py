from datetime import datetime, timezone
from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.database.session import get_db, get_optional_db
from app.models.session import UserSession
from app.models.user import User
from app.security.tokens import hash_session_token


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency validating the HttpOnly session cookie against database records.
    Returns the authenticated User or raises HTTP 401.
    """
    # 1. Check HttpOnly session cookie
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)

    # 2. Check Authorization Bearer header (cross-origin / third-party cookie fallback)
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header[7:].strip()

    # 3. Check X-Session-Token custom header
    if not session_token:
        session_token = request.headers.get("X-Session-Token")

    NO_CACHE_AUTH_HEADERS = {
        "Cache-Control": "no-cache, no-store, must-revalidate, private",
        "Pragma": "no-cache",
    }

    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers=NO_CACHE_AUTH_HEADERS,
        )

    token_hash = hash_session_token(session_token)
    now = datetime.now(timezone.utc)

    # Query active session
    stmt = (
        select(UserSession)
        .where(
            UserSession.session_token_hash == token_hash,
            UserSession.expires_at > now,
        )
    )
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers=NO_CACHE_AUTH_HEADERS,
        )

    # Query user associated with session
    user_stmt = select(User).where(User.id == session.user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with session does not exist",
            headers=NO_CACHE_AUTH_HEADERS,
        )

    return user


async def get_optional_current_user(
    request: Request,
    db: Optional[AsyncSession] = Depends(get_optional_db),
) -> Optional[User]:
    """
    FastAPI dependency validating session authentication if provided.
    Returns the authenticated User if credentials are valid, or None if:
    - No authentication token is supplied (guest visitor)
    - The provided session token is expired or invalid
    - The database is currently unavailable or disconnected
    Never raises HTTPException, allowing endpoints with optional auth to serve guests smoothly.
    """
    if db is None:
        return None

    # 1. Check HttpOnly session cookie
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)

    # 2. Check Authorization Bearer header
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header[7:].strip()

    # 3. Check X-Session-Token custom header
    if not session_token:
        session_token = request.headers.get("X-Session-Token")

    if not session_token:
        return None

    try:
        token_hash = hash_session_token(session_token)
        now = datetime.now(timezone.utc)

        # Query active session
        stmt = (
            select(UserSession)
            .where(
                UserSession.session_token_hash == token_hash,
                UserSession.expires_at > now,
            )
        )
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        if not session:
            return None

        # Query user associated with session
        user_stmt = select(User).where(User.id == session.user_id)
        user_result = await db.execute(user_stmt)
        return user_result.scalar_one_or_none()
    except Exception:
        # Graceful fallback: treat unexpected session lookup errors as guest
        return None
