from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.database.session import get_db
from app.models.session import UserSession
from app.models.user import User
from app.schemas.auth import LoginRequest, MessageResponse, RegisterRequest, UserResponse
from app.security.dependencies import get_current_user
from app.security.passwords import hash_password, verify_password
from app.security.rate_limiter import login_rate_limiter
from app.security.tokens import generate_session_token, hash_session_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str:
    """Extracts client IP address safely from request headers or socket."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _resolve_cookie_security(request: Request) -> tuple[bool, str]:
    """
    Dynamically determines (secure, samesite) settings based on HTTPS context.
    When served over HTTPS (direct or behind reverse proxies like Railway),
    we set secure=True and samesite="none" to support cross-site requests (e.g. from GitHub Pages)
    and WebKit/iOS Safari ITP.
    For local development over plain HTTP, we retain secure=False and samesite="lax".
    """
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    is_https = (
        settings.COOKIE_SECURE
        or (settings.ENVIRONMENT == "production")
        or (settings.COOKIE_SAMESITE.lower() == "none")
        or (request.url.scheme == "https")
        or (forwarded_proto == "https")
    )
    if is_https:
        return True, "none"
    return False, settings.COOKIE_SAMESITE


def _set_no_cache_headers(response: Response) -> None:
    """Explicitly prevent browser/WebKit caching of auth endpoints."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new analyst account",
)
async def register_user(
    req: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _set_no_cache_headers(response)
    # Check for duplicate email
    stmt = select(User).where(User.email == req.email)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # Hash password securely
    hashed = hash_password(req.password)

    new_user = User(
        email=req.email,
        password_hash=hashed,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post(
    "/login",
    response_model=UserResponse,
    summary="Authenticate and establish an HttpOnly cookie session",
)
async def login_user(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _set_no_cache_headers(response)
    client_ip = _get_client_ip(request)
    rate_limit_key = f"{client_ip}:{req.email}"

    # Verify brute-force threshold
    login_rate_limiter.check_rate_limit(rate_limit_key)

    # Query user account
    stmt = select(User).where(User.email == req.email)
    user = (await db.execute(stmt)).scalar_one_or_none()

    # Generic credential check preventing email enumeration
    if not user or not verify_password(req.password, user.password_hash):
        login_rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    # Reset failure counter on success
    login_rate_limiter.record_success(rate_limit_key)

    # Generate session token and store hash in database
    session_token = generate_session_token()
    token_hash = hash_session_token(session_token)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.SESSION_EXPIRE_SECONDS)

    new_session = UserSession(
        user_id=user.id,
        session_token_hash=token_hash,
        expires_at=expires_at,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent", "")[:512],
    )
    db.add(new_session)
    await db.commit()

    # Set secure HttpOnly session cookie dynamically based on HTTPS context
    is_secure, samesite = _resolve_cookie_security(request)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=settings.SESSION_EXPIRE_SECONDS,
        httponly=settings.COOKIE_HTTPONLY,
        secure=is_secure,
        samesite=samesite,
        domain=settings.COOKIE_DOMAIN,
        path="/",
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
        session_token=session_token,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Invalidate current session and clear HttpOnly cookie",
)
async def logout_user(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    _set_no_cache_headers(response)
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header[7:].strip()
    if not session_token:
        session_token = request.headers.get("X-Session-Token")

    if session_token:
        token_hash = hash_session_token(session_token)
        await db.execute(
            delete(UserSession).where(UserSession.session_token_hash == token_hash)
        )
        await db.commit()

    # Invalidate cookie on browser matching same secure/samesite attributes
    is_secure, samesite = _resolve_cookie_security(request)
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        httponly=settings.COOKIE_HTTPONLY,
        secure=is_secure,
        samesite=samesite,
        domain=settings.COOKIE_DOMAIN,
        path="/",
    )

    return MessageResponse(message="Successfully logged out.")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
async def get_current_user_profile(
    response: Response,
    current_user: User = Depends(get_current_user),
):
    _set_no_cache_headers(response)
    return current_user
