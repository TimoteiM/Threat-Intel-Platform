"""
Local filesystem storage — for development and single-server deployments.

Artifacts stored at: {base_path}/{investigation_id}/{artifact_name}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import aiofiles
import aiofiles.os

from app.storage.base import BaseStorage


class LocalStorage(BaseStorage):

    def __init__(self, base_path: str = "./artifacts"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _get_path(self, investigation_id: str, artifact_name: str) -> Path:
        safe_name = artifact_name.replace("/", "_").replace("..", "_")
        return self.base_path / investigation_id / safe_name

    async def save(
        self,
        investigation_id: str,
        artifact_name: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        path = self._get_path(investigation_id, artifact_name)
        path.parent.mkdir(parents=True, exist_ok=True)

        async with aiofiles.open(path, "wb") as f:
            await f.write(data)

        return str(path)

    async def load(self, storage_path: str) -> bytes:
        async with aiofiles.open(storage_path, "rb") as f:
            return await f.read()

    async def exists(self, storage_path: str) -> bool:
        return os.path.exists(storage_path)

    async def delete(self, storage_path: str) -> None:
        if os.path.exists(storage_path):
            os.remove(storage_path)
