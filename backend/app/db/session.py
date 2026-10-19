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


# ─── The token boundary's own connection ───
#
# `investigation_token_maps` maps `[HOST_a3f9c1_1]` back to a real machine
# name: it is the one table whose rows are, by construction, the identifiers
# every other protection exists to remove. `tip_app` — the role the API, the
# worker and beat connect as — has no privilege on it at all, so the boundary
# cannot borrow the engines above and has to hold its own.
#
# The separation is enforced by the database rather than by this comment:
# scripts/check_db_privileges.sql fails if `tip_app` can reach the table or if
# `tip_sanitizer` can reach anything else, and scripts/liveness.sh runs it.
#
# Lazy, and unpooled. Lazy because a deployment that has not provisioned the
# sanitizer role should fail when the boundary is used rather than when the
# application imports — the boundary has no consumer in production yet, and
# an import-time connection would take the whole API down for a feature
# nothing calls. Unpooled for the reason celery_async_engine is: Celery runs a
# threads pool here, and the purge sweep is the only caller.
_sanitizer_engine = None


def sanitizer_engine():
    """The engine for the token map, built on first use.

    Not a module-level global like the others: see above. Callers get the
    same engine on every call, so the connection is still reused within a
    process.
    """
    global _sanitizer_engine
    if _sanitizer_engine is None:
        _sanitizer_engine = create_engine(
            _explicit_driver(settings.database_sanitizer_url),
            # `echo` is NOT settings.is_development here, unlike every engine
            # above. SQLAlchemy's echo logs statements with their bound
            # parameters, and this connection's parameters are hostnames and
            # account names — the exact values the boundary exists to keep out
            # of model-facing text and out of logs.
            echo=False,
            poolclass=NullPool,
        )
    return _sanitizer_engine


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
