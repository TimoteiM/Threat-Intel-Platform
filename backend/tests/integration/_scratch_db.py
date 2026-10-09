"""A throwaway Postgres database with the application schema.

Created on the configured server and dropped afterwards, so a test can exercise
behaviour a dict-backed fake cannot model — conflicts, sequences, concurrent
transactions — without writing to the application database.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


def server_url():
    from app.config import get_settings

    return make_url(get_settings().database_url)


async def _reachable(url) -> bool:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
    finally:
        await engine.dispose()


@asynccontextmanager
async def scratch_database():
    """Yield (url, session factory) for a fresh database; skip if no server."""
    from app.models.database import Base

    server = server_url()
    if not await _reachable(server):
        pytest.skip(f"No Postgres reachable at {server.render_as_string(hide_password=True)}")

    name = f"tip_scratch_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    admin = create_async_engine(server, poolclass=NullPool, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = server.set(database=name)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("CREATE SEQUENCE alert_case_number_seq AS BIGINT START 1"))
        yield url, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()
