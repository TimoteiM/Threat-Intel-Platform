"""
Investigation Service — business logic for creating and managing investigations.

API endpoints call this service. This service calls repositories.
"""

from __future__ import annotations

import uuid
from typing import Optional, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.repository import (
    CollectorResultRepository,
    EvidenceRepository,
    InvestigationRepository,
    ReportRepository,
)
from app.models.database import Investigation
from app.models.enums import InvestigationState
from app.models.schemas import InvestigationCreate
from app.tasks.investigation_task import run_investigation
from app.utils.domain_utils import normalize_domain, validate_domain

settings = get_settings()


class InvestigationService:

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = InvestigationRepository(session)
        self.evidence_repo = EvidenceRepository(session)
        self.report_repo = ReportRepository(session)

    async def create(self, request: InvestigationCreate) -> dict:
        """
        Create a new investigation and dispatch the task pipeline.

        Returns dict with investigation_id and initial state.
        """
        # Normalize and validate
        domain = normalize_domain(request.domain)
        if not validate_domain(domain):
            raise ValueError(f"Invalid domain: {request.domain}")

        # Validate client_domain if provided
        client_domain = None
        if request.client_domain:
            client_domain = normalize_domain(request.client_domain)
            if not validate_domain(client_domain):
                raise ValueError(f"Invalid client domain: {request.client_domain}")

        # Create DB record
        inv = await self.repo.create(
            domain=domain,
            context=request.context,
            client_domain=client_domain,
            max_iterations=settings.max_analyst_iterations,
        )
        await self.session.flush()

        investigation_id = str(inv.id)

        # Dispatch async pipeline
        run_investigation.delay(
            investigation_id=investigation_id,
            domain=domain,
            context=request.context,
            client_domain=client_domain,
            investigated_url=request.investigated_url,
            client_url=request.client_url,
            external_context=(
                request.external_context.model_dump()
                if request.external_context else None
            ),
            requested_collectors=request.requested_collectors,
        )

        return {
            "investigation_id": investigation_id,
            "domain": domain,
            "state": InvestigationState.CREATED.value,
            "message": f"Investigation started for {domain}",
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
    ) -> Sequence[Investigation]:
        """List investigations with optional filtering."""
        return await self.repo.list_all(limit=limit, offset=offset, state=state, search=search)

    async def count(
        self,
        state: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        """Count investigations matching filters."""
        return await self.repo.count(state=state, search=search)

    async def get_evidence(self, investigation_id: str) -> Optional[dict]:
        """Get collected evidence for an investigation."""
        ev = await self.evidence_repo.get(uuid.UUID(investigation_id))
        return ev.evidence_json if ev else None

    async def get_report(self, investigation_id: str) -> Optional[dict]:
        """Get the latest analyst report."""
        report = await self.report_repo.get_latest(uuid.UUID(investigation_id))
        return report.report_json if report else None
