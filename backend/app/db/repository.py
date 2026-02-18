"""
Generic repository — reusable CRUD operations.

Services call repository methods instead of writing raw SQLAlchemy queries.
This keeps database logic in one place and services clean.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import (
    Artifact,
    Base,
    Batch,
    CollectorResult,
    Evidence,
    Investigation,
    IOCRecord,
    LookupCache,
    Report,
)


class InvestigationRepository:
    """Database operations for investigations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        domain: str,
        context: Optional[str] = None,
        client_domain: Optional[str] = None,
        max_iterations: int = 3,
        batch_id: Optional[uuid.UUID] = None,
    ) -> Investigation:
        inv = Investigation(
            domain=domain,
            context=context,
            client_domain=client_domain,
            state="created",
            max_analyst_iterations=max_iterations,
            batch_id=batch_id,
        )
        self.session.add(inv)
        await self.session.flush()
        return inv

    async def get(self, investigation_id: uuid.UUID) -> Optional[Investigation]:
        result = await self.session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: int = 50,
        offset: int = 0,
        state: Optional[str] = None,
    ) -> Sequence[Investigation]:
        query = select(Investigation).order_by(Investigation.created_at.desc())
        if state:
            query = query.where(Investigation.state == state)
        query = query.limit(limit).offset(offset)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def update_state(
        self,
        investigation_id: uuid.UUID,
        state: str,
        **extra_fields,
    ) -> None:
        values: dict[str, Any] = {
            "state": state,
            "updated_at": datetime.now(timezone.utc),
        }
        if state == "concluded":
            values["concluded_at"] = datetime.now(timezone.utc)
        values.update(extra_fields)

        await self.session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(**values)
        )

    async def update_from_report(
        self,
        investigation_id: uuid.UUID,
        classification: str,
        confidence: str,
        risk_score: Optional[int],
        recommended_action: str,
    ) -> None:
        """Denormalize key report fields onto the investigation for quick queries."""
        await self.session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(
                classification=classification,
                confidence=confidence,
                risk_score=risk_score,
                recommended_action=recommended_action,
                state="concluded",
                concluded_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )


class CollectorResultRepository:
    """Database operations for individual collector results."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert(
        self,
        investigation_id: uuid.UUID,
        collector_name: str,
        status: str,
        evidence_json: dict,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
        raw_artifact_hash: Optional[str] = None,
    ) -> CollectorResult:
        # Check if exists
        result = await self.session.execute(
            select(CollectorResult).where(
                CollectorResult.investigation_id == investigation_id,
                CollectorResult.collector_name == collector_name,
            )
        )
        existing = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if existing:
            existing.status = status
            existing.evidence_json = evidence_json
            existing.completed_at = now
            existing.duration_ms = duration_ms
            existing.error = error
            existing.raw_artifact_hash = raw_artifact_hash
            return existing
        else:
            cr = CollectorResult(
                investigation_id=investigation_id,
                collector_name=collector_name,
                status=status,
                evidence_json=evidence_json,
                started_at=now,
                completed_at=now if status in ("completed", "failed") else None,
                duration_ms=duration_ms,
                error=error,
                raw_artifact_hash=raw_artifact_hash,
            )
            self.session.add(cr)
            await self.session.flush()
            return cr

    async def get_all_for_investigation(
        self, investigation_id: uuid.UUID
    ) -> Sequence[CollectorResult]:
        result = await self.session.execute(
            select(CollectorResult)
            .where(CollectorResult.investigation_id == investigation_id)
        )
        return result.scalars().all()


class EvidenceRepository:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(
        self,
        investigation_id: uuid.UUID,
        evidence_json: dict,
        signals: list,
        data_gaps: list,
        external_context: Optional[dict] = None,
    ) -> Evidence:
        # Upsert
        result = await self.session.execute(
            select(Evidence).where(Evidence.investigation_id == investigation_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.evidence_json = evidence_json
            existing.signals = signals
            existing.data_gaps = data_gaps
            existing.external_context = external_context
            return existing
        else:
            ev = Evidence(
                investigation_id=investigation_id,
                evidence_json=evidence_json,
                signals=signals,
                data_gaps=data_gaps,
                external_context=external_context,
            )
            self.session.add(ev)
            await self.session.flush()
            return ev

    async def get(self, investigation_id: uuid.UUID) -> Optional[Evidence]:
        result = await self.session.execute(
            select(Evidence).where(Evidence.investigation_id == investigation_id)
        )
        return result.scalar_one_or_none()


class ReportRepository:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(
        self,
        investigation_id: uuid.UUID,
        report_json: dict,
        iteration: int = 0,
        executive_summary: Optional[str] = None,
        technical_narrative: Optional[str] = None,
        recommendations: Optional[str] = None,
    ) -> Report:
        r = Report(
            investigation_id=investigation_id,
            iteration=iteration,
            report_json=report_json,
            executive_summary=executive_summary,
            technical_narrative=technical_narrative,
            recommendations=recommendations,
        )
        self.session.add(r)
        await self.session.flush()
        return r

    async def get_latest(self, investigation_id: uuid.UUID) -> Optional[Report]:
        result = await self.session.execute(
            select(Report)
            .where(Report.investigation_id == investigation_id)
            .order_by(Report.iteration.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class ArtifactRepository:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(
        self,
        investigation_id: uuid.UUID,
        collector_name: str,
        artifact_name: str,
        sha256_hash: str,
        storage_path: str,
        content_type: Optional[str] = None,
        size_bytes: Optional[int] = None,
    ) -> Artifact:
        a = Artifact(
            investigation_id=investigation_id,
            collector_name=collector_name,
            artifact_name=artifact_name,
            sha256_hash=sha256_hash,
            storage_path=storage_path,
            content_type=content_type,
            size_bytes=size_bytes,
        )
        self.session.add(a)
        await self.session.flush()
        return a


class BatchRepository:
    """Database operations for batch investigations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        name: Optional[str] = None,
        total_domains: int = 0,
    ) -> Batch:
        batch = Batch(
            name=name,
            total_domains=total_domains,
            status="created",
        )
        self.session.add(batch)
        await self.session.flush()
        return batch

    async def get(self, batch_id: uuid.UUID) -> Optional[Batch]:
        result = await self.session.execute(
            select(Batch).where(Batch.id == batch_id)
        )
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Batch]:
        query = (
            select(Batch)
            .order_by(Batch.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(query)
        return result.scalars().all()

    async def update_progress(
        self,
        batch_id: uuid.UUID,
        completed_count: int,
        status: Optional[str] = None,
    ) -> None:
        values: dict[str, Any] = {"completed_count": completed_count}
        if status:
            values["status"] = status
            if status == "completed":
                values["completed_at"] = datetime.now(timezone.utc)
        await self.session.execute(
            update(Batch).where(Batch.id == batch_id).values(**values)
        )

    async def get_investigations(
        self,
        batch_id: uuid.UUID,
    ) -> Sequence[Investigation]:
        result = await self.session.execute(
            select(Investigation)
            .where(Investigation.batch_id == batch_id)
            .order_by(Investigation.created_at)
        )
        return result.scalars().all()


class CacheRepository:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get(self, key: str) -> Optional[dict]:
        result = await self.session.execute(
            select(LookupCache).where(
                LookupCache.cache_key == key,
                LookupCache.expires_at > datetime.now(timezone.utc),
            )
        )
        row = result.scalar_one_or_none()
        return row.cache_value if row else None

    async def set(
        self,
        key: str,
        value: dict,
        source: str,
        expires_at: datetime,
    ) -> None:
        # Upsert
        result = await self.session.execute(
            select(LookupCache).where(LookupCache.cache_key == key)
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.cache_value = value
            existing.expires_at = expires_at
        else:
            self.session.add(LookupCache(
                cache_key=key,
                cache_value=value,
                source=source,
                expires_at=expires_at,
            ))
