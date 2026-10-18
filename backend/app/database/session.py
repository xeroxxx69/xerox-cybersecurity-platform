import logging
from typing import AsyncGenerator, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.core.config import settings

logger = logging.getLogger("xerox.database")

# Create asynchronous SQLAlchemy engine
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing a transactional async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_optional_db() -> AsyncGenerator[Optional[AsyncSession], None]:
    """Dependency providing an async database session if the database is operational,
    or yielding None if the database is disconnected or unreachable.
    Allows guest analysis pipelines to operate even during database outages.
    """
    session: Optional[AsyncSession] = None
    try:
        session = AsyncSessionLocal()
    except Exception as exc:
        logger.warning("Database session unavailable, continuing with None DB session: %s", exc)
        yield None
        return

    try:
        yield session
        if session:
            await session.commit()
    except Exception:
        if session:
            try:
                await session.rollback()
            except Exception:
                pass
        raise
    finally:
        if session:
            try:
                await session.close()
            except Exception:
                pass


async def check_db_health() -> dict[str, str]:
    """Probes the database connection using a minimal SELECT 1 query."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("SELECT 1"))
            scalar = result.scalar()
            if scalar == 1:
                return {"status": "connected", "details": "Database responding normally"}
            return {"status": "unhealthy", "details": f"Unexpected response: {scalar}"}
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return {"status": "unreachable", "details": str(exc)}
