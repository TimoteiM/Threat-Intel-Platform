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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class Batch(Base):
    __tablename__ = "batches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    total_domains: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="created")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    investigations: Mapped[list[Investigation]] = relationship(
        back_populates="batch"
    )

    __table_args__ = (
        Index("idx_batches_created", "created_at"),
        Index("idx_batches_status", "status"),
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    observable_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True, default="domain"
    )
    state: Mapped[str] = mapped_column(
        String(50), nullable=False, default="created"
    )
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Batch reference
    batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("batches.id", ondelete="SET NULL"),
        nullable=True,
    )

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
    anyrun_use_residential_proxy: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    anyrun_proxy_country: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Iteration tracking
    analyst_iterations: Mapped[int] = mapped_column(Integer, default=0)
    max_analyst_iterations: Mapped[int] = mapped_column(Integer, default=3)

    # Relationships
    batch: Mapped[Batch | None] = relationship(back_populates="investigations")
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
    assistant_sessions: Mapped[list["AssistantSession"]] = relationship(
        back_populates="investigation"
    )
    case_chat_messages: Mapped[list["InvestigationCaseChatMessage"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("idx_investigations_state", "state"),
        Index("idx_investigations_created", "created_at"),
        Index("idx_investigations_classification", "classification"),
        Index("idx_investigations_batch", "batch_id"),
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


class Exclusion(Base):
    """
    An indicator the platform is told to treat as benign without looking.

    The corporate estate — its own domains, its office ranges, the hashes of the
    software it ships — turns up in alert after alert and costs a collector round
    trip every time to conclude what the analyst already knows. An exclusion says
    so once: the indicator is reported benign with this row as the reason, and no
    collector, VirusTotal quota or AI token is spent on it.
    """
    __tablename__ = "exclusions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # domain | ip | url | hash — what `value` is, so a hash and a domain that
    # happen to look alike never match each other.
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # As the analyst typed it, kept for display.
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Lower-cased, defanged, IDNA-normalised — what matching actually compares.
    normalized_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Why this is safe to skip. Required: an unexplained whitelist entry is how
    # a real detection gets silenced for a year without anyone noticing.
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # A domain exclusion normally covers its subdomains; an IP one may be a CIDR.
    match_subdomains: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Optional review date — a temporary exclusion that stops applying by itself
    # is safer than one somebody has to remember to remove.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # What it has actually saved, so a useless entry is visible as one.
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("indicator_type", "normalized_value", name="uq_exclusion_type_value"),
        Index("idx_exclusions_active", "active", "indicator_type"),
    )


class WatchlistEntry(Base):
    __tablename__ = "watchlist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schedule_interval: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    next_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Risk score history: [{score, at, investigation_id}, ...] (last 30 runs)
    risk_score_history: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # Diff vs previous run: structured changes detected on last re-check
    evidence_diff_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    alerts: Mapped[list[WatchlistAlert]] = relationship(
        back_populates="watchlist_entry", cascade="all, delete-orphan"
    )


class WatchlistAlert(Base):
    __tablename__ = "watchlist_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    watchlist_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("watchlist.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    details_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    watchlist_entry: Mapped[WatchlistEntry] = relationship(back_populates="alerts")

    __table_args__ = (
        Index("idx_watchlist_alerts_wl", "watchlist_id"),
    )


class Client(Base):
    """Registered client organizations whose assets we monitor."""
    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    aliases: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    brand_keywords: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_alert_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Default collectors to run for this client's domains (empty = run all)
    default_collectors: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    alerts: Mapped[list[ClientAlert]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )


class ClientAlert(Base):
    """Alert triggered when an investigation impacts a registered client."""
    __tablename__ = "client_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="high")
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    details_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    client: Mapped[Client] = relationship(back_populates="alerts")

    __table_args__ = (
        Index("idx_client_alerts_client", "client_id"),
    )


class WHOISHistory(Base):
    __tablename__ = "whois_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    whois_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    changes_from_previous: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("idx_whois_history_domain", "domain"),
        Index("idx_whois_history_captured", "captured_at"),
    )


class IPLookup(Base):
    """Persisted history of standalone IP reputation lookups."""
    __tablename__ = "ip_lookups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    abuse_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    isp: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(10), nullable=True)
    threatfox_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("idx_ip_lookups_ip", "ip"),
        Index("idx_ip_lookups_queried", "queried_at"),
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


class EmailInvestigationRun(Base):
    __tablename__ = "email_investigation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    email_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sender_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_source: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    result_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("idx_email_runs_created", "created_at"),
    )


class AlertBodyInvestigationRun(Base):
    """One pasted alert body, its extracted indicators, and their JSON reports."""
    __tablename__ = "alert_body_investigation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_body: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    indicator_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    highest_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # sha256 of the normalised alert body — lets a repeated delivery reuse the
    # run it already produced instead of investigating the same alert twice.
    alert_body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The sending platform's own alert id (Wazuh/OpenSearch `_id`, a ticket ref).
    # Unlike the body hash this identifies the alert itself, so a re-delivery
    # whose formatting or enrichment changed is still recognised as the same one.
    external_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Which *detection* produced this alert — the rule, not the alert instance.
    # external_ref identifies one alert; these identify the thing that keeps
    # producing them, which is what detection-quality reporting groups by.
    detection_rule_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detection_rule_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Where to POST the finished report list, when the sender asked for one.
    callback_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("idx_alert_body_runs_created", "created_at"),
        Index("idx_alert_body_runs_status", "status"),
        Index("idx_alert_body_runs_hash_created", "alert_body_hash", "created_at"),
        Index("idx_alert_body_runs_extref_created", "external_ref", "created_at"),
        Index("idx_alert_body_runs_rule_created", "detection_rule_id", "created_at"),
    )


class AnalystFeedback(Base):
    """
    An analyst's verdict on what the platform concluded.

    Without this the decision engine cannot be measured: every tuning decision
    is a guess about whether a classification was right. One row per judgement,
    keyed loosely by subject so an investigation and an alert run can both be
    judged without a table each.
    """
    __tablename__ = "analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # investigation | alert_run
    subject_type: Mapped[str] = mapped_column(String(30), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # true_positive | false_positive | unclear
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    # What the platform said at the time, copied rather than joined: the run can
    # be re-analysed later, and the feedback is about the answer as it was given.
    platform_classification: Mapped[str | None] = mapped_column(String(20), nullable=True)
    platform_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Which detection produced it, so rule quality can be read off feedback.
    detection_rule_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )

    __table_args__ = (
        # One standing judgement per subject — re-submitting updates it.
        UniqueConstraint("subject_type", "subject_id", name="uq_feedback_subject"),
        Index("idx_feedback_rule", "detection_rule_id"),
        Index("idx_feedback_created", "created_at"),
    )


class AssistantSession(Base):
    __tablename__ = "assistant_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    source_type: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    linked_investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    sanitization_summary_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    result_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation: Mapped[Investigation | None] = relationship(back_populates="assistant_sessions")
    entries: Mapped[list["AssistantEntry"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_assistant_sessions_created", "created_at"),
        Index("idx_assistant_sessions_mode", "mode"),
        Index("idx_assistant_sessions_status", "status"),
        Index("idx_assistant_sessions_investigation", "linked_investigation_id"),
    )


class InvestigationCaseChatMessage(Base):
    """A durable message in the evidence-grounded chat for one investigation."""

    __tablename__ = "investigation_case_chat_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evidence_refs_json: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    limitations_json: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    suggested_followups_json: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="case_chat_messages")

    __table_args__ = (
        Index("idx_case_chat_investigation", "investigation_id"),
        Index("idx_case_chat_investigation_created", "investigation_id", "created_at"),
    )


class AssistantEntry(Base):
    __tablename__ = "assistant_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assistant_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    entry_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    entry_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_text: Mapped[str] = mapped_column(Text, nullable=False)
    token_map_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    session: Mapped[AssistantSession] = relationship(back_populates="entries")

    __table_args__ = (
        Index("idx_assistant_entries_session", "session_id"),
        Index("idx_assistant_entries_session_order", "session_id", "entry_index"),
    )
