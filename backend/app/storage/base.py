"""
Abstract storage interface.

Collectors produce raw artifacts (HTML, certs, headers).
Storage backends persist them for audit trails.
"""

from __future__ import annotations

import abc
from typing import Optional


class BaseStorage(abc.ABC):
    """
    All storage backends implement this interface.
    Artifacts are stored by investigation_id + artifact_name.
    """

    @abc.abstractmethod
    async def save(
        self,
        investigation_id: str,
        artifact_name: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        """
        Store an artifact.
        Returns the storage path (used for retrieval and DB recording).
        """
        ...

    @abc.abstractmethod
    async def load(self, storage_path: str) -> bytes:
        """Load an artifact by its storage path."""
        ...

    @abc.abstractmethod
    async def exists(self, storage_path: str) -> bool:
        """Check if an artifact exists."""
        ...

    @abc.abstractmethod
    async def delete(self, storage_path: str) -> None:
        """Delete an artifact."""
        ...
