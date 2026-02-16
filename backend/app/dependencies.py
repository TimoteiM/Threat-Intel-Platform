"""
FastAPI dependency injection.

Endpoints declare what they need via Depends() and FastAPI wires it up.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import get_db
from app.storage import get_storage
from app.storage.base import BaseStorage

# Type aliases for clean endpoint signatures
DBSession = Annotated[AsyncSession, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]
Storage = Annotated[BaseStorage, Depends(get_storage)]
