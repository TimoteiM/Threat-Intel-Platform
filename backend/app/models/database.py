"""
SQLAlchemy ORM models — maps to Postgres tables.

These are the persistence layer. Pydantic schemas (schemas.py) handle
validation and serialization. This file handles storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Computed,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
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
    # The ANY.RUN task whose screencast can be played, when one exists.
    # Derived at conclusion rather than searched for per request: the fact
    # sits six levels inside a collector's stored JSON.
    sandbox_video_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
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

    # Two fields the dashboard groups by, lifted out of the JSON at write time.
    # `evidence_json` averages ~300 KB, so reading one string out of it made
    # Postgres detoast the whole value — 3 seconds per aggregate. Postgres
    # maintains these itself, so nothing writes them and they cannot drift.
    # Read-only: assigning to them raises. See migration 019.
    whois_registrar: Mapped[str | None] = mapped_column(
        Text,
        Computed("evidence_json->'whois'->>'registrar'", persisted=True),
        nullable=True,
    )
    hosting_asn_org: Mapped[str | None] = mapped_column(
        Text,
        Computed("evidence_json->'hosting'->>'asn_org'", persisted=True),
        nullable=True,
    )

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
    # What reading this file's contents found, when the reading had to happen
    # at upload time. That is the case for a password-protected archive: the
    # password opens it in the request that carried it and is then discarded,
    # rather than being handed to a worker through the broker. Null for
    # everything else, which the analysis task extracts itself as before.
    extraction_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

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


class User(Base):
    """Someone who can log in.

    Passwords are stored as scrypt hashes with a per-user salt. scrypt is in the
    standard library, so this costs no new dependency in an image that had no
    password hashing of any kind.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Null for an account that signs in through Entra ID: there is no password
    # to store, and inventing one would be a credential nobody asked for.
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "local" or "microsoft". Kept so the UI can say how someone gets in, and so
    # a password change cannot be offered to an account that has no password.
    auth_provider: Mapped[str] = mapped_column(String(20), nullable=False, default="local")
    # Entra's `oid` claim — immutable within the tenant. Matching on this rather
    # than on the address means a rename does not orphan someone's history.
    external_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # "owner" and "admin" may manage users and API keys; "analyst" may use the
    # platform. An owner additionally cannot be deleted, demoted or deactivated
    # by anyone — see _refuse_if_owner in app/api/auth.py.
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Internal staff see every tenant and the unassigned backlog. A
    # client-restricted account has this false and an explicit tenant list, and
    # cannot reach another tenant's data by changing a filter, a URL or a body.
    all_tenants: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tenant_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Set when the password was generated for them, so the UI can insist on a
    # change before the account is useful for anything else.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ApiKey(Base):
    """A credential for a machine caller — the alert ingest, mainly.

    Only the hash is stored, so a leaked database does not hand over working
    keys. `prefix` is the visible first characters, kept so a key can be
    identified in a list and revoked without anyone having to reveal it.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="ingest")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Which tenants this integration may submit alerts for. Empty means none:
    # a key cannot acquire a tenant by naming one in a request body.
    tenant_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


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
    # `alert` exclusions only. Field name → value, all of which must match, so an
    # analyst can silence one noisy shape ("rule 1002, this agent, Low") without
    # silencing a rule that also produced real detections. A single
    # normalized_value cannot express that, which is why this exists.
    match_fields: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
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


class Tenant(Base):
    """A client estate: whose alerts these are, and whose analysts may read them.

    Distinct from `Client`, which is the brand-monitoring register — whose name
    to watch for in a phishing kit. This is the opposite direction, and the two
    must not be the same row: deleting a monitored brand would otherwise destroy
    an access boundary.
    """

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # What the sending integration puts in `tenant_id`.
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
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

    # These four exist in the table but were left unmapped when the run state
    # moved into result_json, so every row read "queued" for ever and nothing
    # could be asked in SQL how long a run took. They are a projection of
    # result_json, not a second source of truth: _update_run is the only writer
    # and derives both from the same patch.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
    # The alert's indicator values, kept in step with result_json by a
    # database trigger (migration 040). Correlation reads this to ask what
    # two alerts have in common; deriving it from the JSON on every page
    # load cost 2.4 seconds a time.
    ioc_values: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
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
    # What the alert says it is, as opposed to the rule that carried it. See
    # alert_field_service.detection_name_of for why both are kept.
    detection_name: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Who the alert is about. An attack chain is (entity, time window, tactics),
    # and nothing here previously identified the device or the account — so no
    # query could ask what else happened on that machine in the last 24 hours.
    # Written at ingest from the alert body; null when the alert names neither,
    # or when it was forwarded by the manager rather than seen on an endpoint.
    entity_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entity_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Whose estate this alert is from, verified by the platform rather than
    # asserted by the payload. NULL means unassigned — visible only to internal
    # users, never to a client-restricted one. `alert_client` below is the
    # sender's own claim and is not a boundary.
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # How the tenant was decided: declared | marker | manager_source | api_key.
    # Kept so a dispute about an assignment is settled by reading the row.
    tenant_assignment: Mapped[str | None] = mapped_column(String(24), nullable=True)
    # Which platform sent it. Correlation partitions on this: two senders name
    # hosts their own way, and a chain assembled across them is a fabrication.
    alert_source: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Whose estate this is. Both feeds carry other organisations' alerts, and two
    # customers can each own a host called DC01.
    alert_client: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # "alert" — one detection — or "incident", a payload that already contains a
    # whole session. The second is a case, not a member of one.
    alert_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # When it happened on the host, not when we were told. Ingest order is the
    # order a sender chose to send in — replayed alerts arrive days late — so
    # every sequence question a case asks reads this instead of created_at.
    # Null only when the body carried nothing parseable and no fallback was set.
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # The parts of result_json the rollups read, lifted out at write time.
    # Detection quality, ATT&CK coverage and the cost dashboard each scan every
    # run in their window; reading these from the 14 KB payload cost 729 ms of
    # fetching to do 0.6 ms of arithmetic. Postgres maintains them, so nothing
    # writes them and they cannot drift from result_json. See migration 020.
    result_attack_assessment: Mapped[dict | None] = mapped_column(
        JSONB, Computed("result_json->'attack_assessment'", persisted=True), nullable=True
    )
    result_summary: Mapped[dict | None] = mapped_column(
        JSONB, Computed("result_json->'summary'", persisted=True), nullable=True
    )
    result_extraction: Mapped[dict | None] = mapped_column(
        JSONB, Computed("result_json->'extraction'", persisted=True), nullable=True
    )
    result_overall_verdict: Mapped[str | None] = mapped_column(
        Text, Computed("result_json->>'overall_verdict'", persisted=True), nullable=True
    )

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
        Index("idx_alert_body_runs_tenant_created", "tenant_id", "created_at"),
    )


class AlertLogContext(Base):
    """The logs retrieved around one alert, and how much of the window is read.

    Separate from the run's `result_json` on purpose: that payload is rewritten
    whole every time a run is re-analysed, and follow-up state a second writer
    can replace is not durable. See migration 028.
    """

    __tablename__ = "alert_log_context"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="partial")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Where the next read starts. Never moves backwards.
    covered_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    logs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    selectors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    sources: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # How much log context the verdict on screen was actually formed from.
    # `len(logs) - logs_at_analysis` is what the analyst needs to know.
    logs_at_analysis: Mapped[int | None] = mapped_column(Integer, nullable=True)
    analysed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint("run_id", name="uq_alert_log_context_run"),
        Index("idx_alert_log_context_due", "next_attempt_at",
              postgresql_where=text("status IN ('partial', 'unavailable')")),
    )


class SandboxAnalysis(Base):
    """One detonation, from the moment it is asked for to the stored verdict.

    Provider-tagged rather than CAPE-named: the platform already talks to two
    other sandboxes, and a table called `cape_analyses` would have to be
    duplicated the next time one is added.

    Idempotency is the whole reason this row exists before CAPE is contacted.
    A submission is expensive — it occupies one of six VMs for minutes — so a
    retried request, a double-clicked button and two workers racing must all
    converge on the same analysis. `idempotency_key` carries the tenant, the
    sample, the provider and the analysis policy, and is unique; a second
    attempt finds the row instead of creating one. Re-analysing on purpose
    bumps `run_seq`, which changes the key, so a deliberate re-run is possible
    and an accidental one is not.

    The provider's raw report is deliberately NOT stored here. `raw_summary`
    keeps a bounded reference — task id, format, size, section counts — so any
    finding can be traced back to the CAPE task without this table growing by
    tens of megabytes per sample.
    """

    __tablename__ = "sandbox_analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False, default="cape", index=True)

    # queued → submitting → submitted → pending → running → processing →
    # reported, or failed / timed_out / cancelled.
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)

    # What is being analysed. CAPE detonates a file or fetches a URL, and the
    # two have different identities — a URL has no file hash until CAPE has
    # downloaded something.
    target_kind: Mapped[str] = mapped_column(String(10), nullable=False, default="file")
    target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # The sample. Null for a URL analysis, where there is no local file.
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sample_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sample_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sample_type: Mapped[str | None] = mapped_column(String(120), nullable=True)

    # Whose estate. A string, matching Investigation.client_domain and
    # AlertBodyInvestigationRun.alert_client — this schema has no RLS, and
    # inventing a second tenancy model here would just be a third answer.
    client: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)

    # What asked for it. All optional: a detonation can be raised from an
    # investigation, from an alert run, or from an artifact on its own.
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True
    )
    alert_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_body_investigation_runs.id", ondelete="SET NULL"), nullable=True
    )
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True
    )

    # Tenant + sample + provider + policy + run_seq. Unique.
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    policy_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1")
    run_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # The provider's handle on this analysis.
    provider_task_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    # True when this row adopted an analysis CAPE had already run for this hash
    # rather than detonating again.
    reused_existing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Nullable on purpose and never defaulted to zero: unknown is not benign.
    malscore: Mapped[float | None] = mapped_column(Float, nullable=True)

    normalized_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    raw_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Every state change, with who and when. This is the audit trail for the
    # workflow itself; API mutations are additionally logged by the router.
    state_history: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Bounded so a wedged task cannot be polled forever by a restarted worker.
    poll_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    requested_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, onupdate=func.now()
    )
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_sandbox_analyses_created", "created_at"),
        Index("idx_sandbox_analyses_client_created", "client", "created_at"),
        Index("idx_sandbox_analyses_sha_provider", "sha256", "provider"),
        Index("idx_sandbox_analyses_alert_run", "alert_run_id"),
        # The worker's claim query: unfinished rows, oldest first.
        Index("idx_sandbox_analyses_status_created", "status", "created_at"),
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
    # The same report before its tokens were resolved. This is the only version
    # that may be given to a model again: report_markdown is de-anonymised for
    # the analyst and carries the token table. See migration 032.
    report_markdown_model_safe: Mapped[str | None] = mapped_column(Text, nullable=True)
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


class AlertCaseSpine(Base):
    """The part of a correlated case that outlives the read that computed it.

    Membership is not stored: which alerts belong together is recomputed from
    event time on every read. What lives here is the human overlay — who owns
    it, whether it is still open, and the worst it ever got.
    """
    __tablename__ = "alert_case_spine"

    case_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_source: Mapped[str] = mapped_column(String(128), nullable=False)
    alert_client: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_host: Mapped[str] = mapped_column(String(255), nullable=False)
    session_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Display only. Never an input to case_key — see alert_session_service.
    session_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    peak_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    peak_score_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    peak_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_by_case_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The handle a person uses. `case_key` is a sha256 and has to be, because it
    # is derived from the events; nobody says "case 9f3c…" out loud. Assigned
    # once from a sequence, never recomputed.
    case_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True, unique=True)
    # Frozen when the case closes. Recomputing it from members would let a
    # closed case's title drift as the estate changes around it.
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closure_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    alerts_at_close: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The earlier case this one carries on from. The opposite direction from
    # `superseded_by_case_key`, which means "this one was absorbed".
    continues_case_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    closure_claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The overall reading of the case, as distinct from the per-alert ones.
    narrative_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    narrative_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # score + member count + tactic set the narrative was written from, so a
    # stale one is detectable and an unchanged case is never re-analysed.
    narrative_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    narrative_session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    narrative_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class AlertCaseSnapshot(Base):
    """What a case looked like the last time it changed.

    Appended only when score, member count, or tactic set actually moved — a
    row per recompute would record page loads rather than history.
    """
    __tablename__ = "alert_case_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("alert_case_spine.case_key", ondelete="CASCADE"),
        nullable=False,
    )
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    surprise: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_version: Mapped[str] = mapped_column(String(64), nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False)
    tactics: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    escalated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    emitted_event: Mapped[str | None] = mapped_column(String(32), nullable=True)
    escalated_from_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    escalated_to_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    escalated_delta_config: Mapped[int | None] = mapped_column(Integer, nullable=True)
    escalated_min_score_config: Mapped[int | None] = mapped_column(Integer, nullable=True)
