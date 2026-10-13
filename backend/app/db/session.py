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
from sqlalchemy.pool import NullPool

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

# ─── Async engine for Celery, deliberately unpooled ───
#
# Celery runs a *threads* pool here (worker_concurrency=8), and every async
# task wraps its work in `asyncio.run()`, which builds a fresh event loop per
# call. A pooled async connection belongs to the loop that opened it, so the
# moment two tasks overlap, one of them is handed a connection whose Future
# belongs to a loop that has already closed:
#
#     RuntimeError: Task ... got Future ... attached to a different loop
#
# Measured over 89 minutes on 2026-10-13, before this engine existed: 36
# graph-materialisation sweeps and 21 pipeline-stall watches failed that way —
# including the stall alarm, which exists precisely because a worker dying on
# every task and a worker with nothing to do produce the same queue. It had
# been failing for about a month, invisible because nothing reads those tasks'
# return values and the log recorded only `type(exc).__name__`.
#
# NullPool removes the collision class rather than narrowing it: there is no
# connection reuse, so there is nothing to carry a loop affinity. The cost is
# a connect per task on a box doing tens of tasks a minute, which is
# acceptable, and the change is one line to revert.
#
# The proper fix is one persistent event loop per worker process, with the
# pooled engine bound to it — see docs/problems/asyncio-in-celery-threads.md.
# It is more invasive and was not taken on a live box at the end of a long
# session.
celery_async_engine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,
    poolclass=NullPool,
)

CeleryAsyncSessionLocal = async_sessionmaker(
    bind=celery_async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ─── Sync engine (for Alembic / Celery workers) ───


def _explicit_driver(url: str) -> str:
    """Name the driver, because the default for `postgresql://` is not stable.

    SQLAlchemy 2.1 resolves a bare `postgresql://` to psycopg v3 where 2.0
    resolved it to psycopg2. We install psycopg2, so a rebuild that happened to
    pick up 2.1 took the worker down on import — with no code change behind it.
    Spelling the driver out costs nothing and cannot drift.
    """
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


sync_engine = create_engine(
    _explicit_driver(settings.database_sync_url),
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
