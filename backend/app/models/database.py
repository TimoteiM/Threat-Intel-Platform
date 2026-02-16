"""
SQLAlchemy ORM models — maps to Postgres tables.

These are the persistence layer. Pydantic schemas (schemas.py) handle
validation and serialization. This file handles storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    state: Mapped[str] = mapped_column(
        String(50), nullable=False, default="created"
    )
    context: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )
    concluded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Denormalized from report (for quick queries / list views)
    classification: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Iteration tracking
    analyst_iterations: Mapped[int] = mapped_column(Integer, default=0)
    max_analyst_iterations: Mapped[int] = mapped_column(Integer, default=3)

    # Relationships
    collector_results: Mapped[list[CollectorResult]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    evidence: Mapped[Evidence | None] = relationship(
        back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    iocs: Mapped[list[IOCRecord]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("idx_investigations_state", "state"),
        Index("idx_investigations_created", "created_at"),
        Index("idx_investigations_classification", "classification"),
    )


class CollectorResult(Base):
    __tablename__ = "collector_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    collector_name: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    version: Mapped[str] = mapped_column(String(20), default="1.0.0")

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    # Data
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    raw_artifact_hash: Mapped[str | None] = mapped_column(String(64))

    investigation: Mapped[Investigation] = relationship(back_populates="collector_results")

    __table_args__ = (
        Index("idx_collector_results_inv", "investigation_id"),
        # One result per collector per investigation
        Index(
            "uq_collector_per_investigation",
            "investigation_id", "collector_name",
            unique=True,
        ),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # The full CollectedEvidence JSON
    evidence_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    signals: Mapped[list] = mapped_column(JSONB, default=list)
    data_gaps: Mapped[list] = mapped_column(JSONB, default=list)
    external_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="evidence")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Full structured report
    report_json: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Denormalized for full-text search
    executive_summary: Mapped[str | None] = mapped_column(Text)
    technical_narrative: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="reports")

    __table_args__ = (
        Index("idx_reports_inv", "investigation_id"),
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    collector_name: Mapped[str] = mapped_column(String(50), nullable=False)
    artifact_name: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content_type: Mapped[str | None] = mapped_column(String(100))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="artifacts")

    __table_args__ = (
        Index("idx_artifacts_inv", "investigation_id"),
    )


class IOCRecord(Base):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    context: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(20))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="iocs")

    __table_args__ = (
        Index("idx_iocs_inv", "investigation_id"),
    )


class LookupCache(Base):
    """Cache for external lookups (ASN, RDAP, crt.sh) to reduce API calls."""
    __tablename__ = "lookup_cache"

    cache_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    cache_value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
