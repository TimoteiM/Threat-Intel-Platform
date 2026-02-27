"""
Investigation Service — business logic for creating and managing investigations.

API endpoints call this service. This service calls repositories.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.repository import (
    CollectorResultRepository,
    EvidenceRepository,
    InvestigationRepository,
    ReportRepository,
)
from app.models.database import Client, Investigation
from app.models.enums import InvestigationState
from app.models.schemas import InvestigationCreate
from app.tasks.investigation_task import run_investigation
from app.utils.domain_utils import normalize_domain, validate_domain
from app.collectors.registry import get_collectors_for_type

logger = logging.getLogger(__name__)

settings = get_settings()


class InvestigationService:

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = InvestigationRepository(session)
        self.evidence_repo = EvidenceRepository(session)
        self.report_repo = ReportRepository(session)

    async def _find_matching_clients(self, domain: str) -> list[Client]:
        """Return active clients whose primary domain or aliases match the given domain."""
        result = await self.session.execute(
            select(Client).where(Client.status == "active")
        )
        clients = result.scalars().all()
        d = domain.lower().removeprefix("www.")
        matched = []
        for c in clients:
            client_root = c.domain.lower().removeprefix("www.")
            aliases = [a.lower().removeprefix("www.") for a in (c.aliases or [])]
            kws = [k.lower() for k in (c.brand_keywords or [])]
            if d == client_root or d in aliases or any(kw in d for kw in kws):
                matched.append(c)
        return matched

    async def create(self, request: InvestigationCreate) -> dict:
        """
        Create a new investigation and dispatch the task pipeline.

        Applies per-client default collectors if the domain matches a registered client.
        Returns dict with investigation_id and initial state.
        """
        observable_type = request.observable_type or "domain"
        allowed_types = {"domain", "ip", "url", "hash", "file"}
        if observable_type not in allowed_types:
            raise ValueError(
                f"Unsupported observable_type '{observable_type}'. "
                f"Allowed: {', '.join(sorted(allowed_types))}"
            )

        # ── Type-aware observable normalization ──────────────────────────────
        if observable_type == "domain":
            domain = normalize_domain(request.domain)
            if not validate_domain(domain):
                raise ValueError(f"Invalid domain: {request.domain}")
        else:
            domain = request.domain.strip()
            if not domain:
                raise ValueError("Observable value cannot be empty")

        # Validate client_domain if provided (always a domain)
        client_domain = None
        if request.client_domain:
            client_domain = normalize_domain(request.client_domain)
            if not validate_domain(client_domain):
                raise ValueError(f"Invalid client domain: {request.client_domain}")

        # ── Cortex-style: find matched clients for default collector selection ──
        matched_clients = await self._find_matching_clients(domain)

        # ── Determine effective collectors ────────────────────────────────────
        # Priority: requested → client defaults → settings defaults
        # Always intersect with collectors that support this observable_type.
        supported_for_type = set(get_collectors_for_type(observable_type))

        effective_collectors = request.requested_collectors
        if not effective_collectors and matched_clients:
            for client in matched_clients:
                if client.default_collectors:
                    effective_collectors = client.default_collectors
                    logger.info(
                        "Applying default collectors from client '%s': %s",
                        client.name, effective_collectors,
                    )
                    break

        if effective_collectors:
            effective_collectors = [
                c for c in effective_collectors if c in supported_for_type
            ]
        else:
            effective_collectors = [
                c for c in settings.default_collectors_list
                if c in supported_for_type
            ]

        # Create DB record
        inv = await self.repo.create(
            domain=domain,
            observable_type=observable_type,
            context=request.context,
            client_domain=client_domain,
            max_iterations=settings.max_analyst_iterations,
        )
        await self.session.flush()

        investigation_id = str(inv.id)

        # Commit BEFORE dispatching the Celery task.
        # FastAPI's get_db() commits after the response is sent (ASGI cleanup phase),
        # which is too late — the Celery worker may pick up and process the task before
        # the investigation row is visible in the DB, causing FK violations on persist.
        await self.session.commit()

        # Dispatch async pipeline
        try:
            run_investigation.delay(
                investigation_id=investigation_id,
                domain=domain,
                observable_type=observable_type,
                context=request.context,
                client_domain=client_domain,
                investigated_url=request.investigated_url,
                client_url=request.client_url,
                external_context=(
                    request.external_context.model_dump()
                    if request.external_context else None
                ),
                requested_collectors=effective_collectors,
            )
        except Exception as exc:
            await self.repo.update_state(uuid.UUID(investigation_id), InvestigationState.FAILED.value)
            await self.session.commit()
            raise RuntimeError(f"Failed to queue investigation task: {exc}") from exc

        return {
            "investigation_id": investigation_id,
            "domain": domain,
            "observable_type": observable_type,
            "state": InvestigationState.CREATED.value,
            "message": f"Investigation started for {domain}",
        }

    async def create_file(
        self,
        request: InvestigationCreate,
        file_bytes: bytes,
        sha256: str,
        filename: str,
    ) -> dict:
        """
        Create an investigation for an uploaded file sample.

        Stores the uploaded file as an artifact on disk, then dispatches the
        task pipeline. For speed, callers can set observable_type="hash" and
        domain=<sha256> so VT performs direct hash lookup.
        """
        import asyncio
        from pathlib import Path
        from app.models.database import Artifact

        # Create DB record first so we have the investigation_id for the storage path
        observable_type = request.observable_type or "file"
        if observable_type not in {"file", "hash"}:
            raise ValueError(
                f"create_file only supports observable_type 'file' or 'hash', got '{observable_type}'"
            )

        inv = await self.repo.create(
            domain=request.domain,
            observable_type=observable_type,
            context=request.context,
            max_iterations=settings.max_analyst_iterations,
        )
        await self.session.flush()

        investigation_id = str(inv.id)

        # Write file bytes to local artifact storage.
        # Always resolve relative paths against the backend directory (where config.py lives),
        # not against the process CWD — FastAPI and Celery may run from different directories.
        from app.config import _BACKEND_DIR
        base = Path(settings.artifact_local_path)
        if not base.is_absolute():
            base = Path(_BACKEND_DIR) / base
        dest = base / investigation_id / filename
        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(dest.write_bytes, file_bytes)
        storage_path = str(dest)

        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"

        # Persist file artifact with correct model field names
        artifact = Artifact(
            investigation_id=inv.id,
            collector_name="upload",
            artifact_name=filename,
            sha256_hash=sha256,
            content_type=ext,
            size_bytes=len(file_bytes),
            storage_path=storage_path,
        )
        self.session.add(artifact)
        await self.session.flush()
        file_artifact_id = str(artifact.id)

        # Commit before dispatching (same race condition as create() — see comment above)
        await self.session.commit()

        # Dispatch pipeline with file_artifact_id
        try:
            run_investigation.delay(
                investigation_id=investigation_id,
                domain=request.domain,
                observable_type=observable_type,
                context=request.context,
                requested_collectors=request.requested_collectors or ["vt"],
                file_artifact_id=file_artifact_id,
            )
        except Exception as exc:
            await self.repo.update_state(uuid.UUID(investigation_id), InvestigationState.FAILED.value)
            await self.session.commit()
            raise RuntimeError(f"Failed to queue file investigation task: {exc}") from exc

        return {
            "investigation_id": investigation_id,
            "domain": request.domain,
            "observable_type": observable_type,
            "state": "created",
            "message": f"File investigation started for {filename} ({observable_type} mode)",
        }

    async def get(self, investigation_id: str) -> Optional[Investigation]:
        """Get an investigation by ID."""
        return await self.repo.get(uuid.UUID(investigation_id))

    async def list_all(
        self,
        limit: int = 50,
        offset: int = 0,
        state: Optional[str] = None,
        search: Optional[str] = None,
        observable_type: Optional[str] = None,
    ) -> Sequence[Investigation]:
        """List investigations with optional filtering."""
        return await self.repo.list_all(
            limit=limit, offset=offset, state=state, search=search,
            observable_type=observable_type,
        )

    async def count(
        self,
        state: Optional[str] = None,
        search: Optional[str] = None,
        observable_type: Optional[str] = None,
    ) -> int:
        """Count investigations matching filters."""
        return await self.repo.count(state=state, search=search, observable_type=observable_type)

    async def get_evidence(self, investigation_id: str) -> Optional[dict]:
        """Get collected evidence for an investigation."""
        ev = await self.evidence_repo.get(uuid.UUID(investigation_id))
        return ev.evidence_json if ev else None

    async def get_report(self, investigation_id: str) -> Optional[dict]:
        """Get the latest analyst report."""
        report = await self.report_repo.get_latest(uuid.UUID(investigation_id))
        return report.report_json if report else None
