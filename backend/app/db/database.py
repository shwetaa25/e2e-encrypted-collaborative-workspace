# app/db/database.py
# ─────────────────────────────────────────────────────────
# Async PostgreSQL database connection using SQLAlchemy 2.0
# with asyncpg driver.
# ─────────────────────────────────────────────────────────

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# Create async engine
# pool_pre_ping=True: check connection health before use
# pool_size=10: max 10 persistent connections
# max_overflow=20: up to 20 extra connections under load
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,         # log SQL queries in debug mode
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,      # don't expire objects after commit (async-safe)
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


async def get_db() -> AsyncSession:
    """
    FastAPI dependency that provides a database session.

    Usage:
        @router.get("/something")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
