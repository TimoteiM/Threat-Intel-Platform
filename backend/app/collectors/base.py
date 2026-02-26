"""
Base collector — abstract class all collectors inherit from.

Provides:
- Automatic timing (started_at, completed_at, duration_ms)
- Error handling (failed status + error message)
- Raw artifact storage with SHA-256 hashing
- Consistent return type: (evidence, meta, artifacts_dict)

To create a new collector:
1. Inherit from BaseCollector
2. Set `name` class attribute
3. Implement `_collect()` returning the typed evidence object
4. Implement `_empty_evidence()` for failure fallback
5. Call `self._store_artifact()` to save raw data
"""

from __future__ import annotations

import abc
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app.models.enums import CollectorStatus
from app.models.schemas import CollectorMeta

logger = logging.getLogger(__name__)

COLLECTOR_VERSION = "1.0.0"


class BaseCollector(abc.ABC):

    name: str = "base"
    # Observable types this collector can handle (subclasses override)
    supported_types: frozenset[str] = frozenset({"domain"})

    def __init__(
        self,
        domain: str,
        investigation_id: str,
        observable_type: str = "domain",
        timeout: int = 30,
        file_artifact_id: str | None = None,
    ):
        self.domain = domain                    # Observable value (backwards-compat name)
        self.observable_type = observable_type  # domain | ip | url | hash | file
        self.investigation_id = investigation_id
        self.timeout = timeout
        self.file_artifact_id = file_artifact_id
        self._artifacts: dict[str, bytes] = {}

    @abc.abstractmethod
    def _collect(self) -> Any:
        """
        Run the actual collection logic.
        Return a typed evidence Pydantic model (DNSEvidence, TLSEvidence, etc.).
        """
        ...

    @abc.abstractmethod
    def _empty_evidence(self, meta: CollectorMeta) -> Any:
        """Return the evidence model in default/empty state (used on failure)."""
        ...

    def run(self) -> tuple[Any, CollectorMeta, dict[str, bytes]]:
        """
        Execute the collector with timing and error handling.

        Returns:
            (evidence_object, collector_meta, raw_artifacts_dict)

        The caller (task worker) is responsible for:
        - Persisting the evidence to the DB
        - Saving raw artifacts to storage
        """
        meta = CollectorMeta(
            collector=self.name,
            version=COLLECTOR_VERSION,
            status=CollectorStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        try:
            start = time.monotonic()
            evidence = self._collect()
            elapsed_ms = int((time.monotonic() - start) * 1000)

            meta.status = CollectorStatus.COMPLETED
            meta.completed_at = datetime.now(timezone.utc)
            meta.duration_ms = elapsed_ms

            # Compute artifact hashes
            for artifact_name, data in self._artifacts.items():
                meta.raw_artifact_hash = hashlib.sha256(data).hexdigest()

            evidence.meta = meta
            return evidence, meta, self._artifacts

        except Exception as e:
            meta.status = CollectorStatus.FAILED
            meta.completed_at = datetime.now(timezone.utc)
            meta.duration_ms = int((time.monotonic() - start) * 1000) if 'start' in dir() else 0
            meta.error = f"{type(e).__name__}: {e}"
            logger.error(f"Collector [{self.name}] failed for {self.domain}: {e}")

            empty = self._empty_evidence(meta)
            return empty, meta, {}

    def _store_artifact(self, name: str, data: bytes | str) -> None:
        """
        Buffer a raw artifact for later persistence.

        Args:
            name: Identifier like "raw_records", "response_body", "cert_der"
            data: Raw bytes or string
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._artifacts[f"{self.name}_{name}"] = data
