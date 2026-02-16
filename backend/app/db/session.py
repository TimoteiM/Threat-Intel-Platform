"""
Database session management.

Provides async session factory for FastAPI dependency injection
and a sync engine for Alembic migrations.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import create_engine

from app.config import get_settings


settings = get_settings()

# ─── Async engine (for FastAPI / app code) ───
async_engine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ─── Sync engine (for Alembic / Celery workers) ───
sync_engine = create_engine(
    settings.database_sync_url,
    echo=settings.is_development,
    pool_size=10,
    max_overflow=5,
    pool_pre_ping=True,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
