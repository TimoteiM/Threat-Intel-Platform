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
    CheckConstraint,
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
    #: A truncated indicator is worse than an absent one: it never matches
    #: anything while still appearing recorded. 5 rows sat at exactly 512
    #: before migration 057, both long tracking URLs.
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
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
    #: `customer`, `internal_estate` or `unknown`. See migration 074 and
    #: `app/services/tenant_population.py` — a caller describing a population
    #: asks this rather than assuming, because `c00` is Expertware's own
    #: estate and six documents had called it a customer's.
    #:
    #: `customer` is the default for a tenant created by an arriving alert:
    #: presuming "someone else's data" is the safer presumption. `unknown`
    #: is for a tenant whose owner genuinely cannot be established — both
    #: Exabeam credentials are currently in that state.
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="customer")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class InvestigationTokenMap(Base):
    """The reversible identifier map for one investigation, with an end.

    Held so a model can reason in `[HOST_a3f9c1_1]` while the queries it asks
    for are executed against the real hostname — and so the results coming
    back can be tokenised with *the same* map, because a result tokenised
    under a fresh map is one the model cannot join to the alert it came from.

    Three columns carry the properties the assistant's `token_map_json` does
    not have. `tenant_id` and `investigation_id` scope it; `fingerprint` is
    stamped into every token this map issues, so a token names the scope it
    was minted under and another tenant's boundary refuses it rather than
    resolving it to a different machine. `expires_at` ends it: this table
    holds real identifiers in exchange for reversibility, and a map with no
    expiry is an indefinite copy of them.
    """

    __tablename__ = "investigation_token_maps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # 16 for a 12-character fingerprint, with room. The width is not cosmetic:
    # a collision makes two scopes indistinguishable and the cross-tenant
    # check passes — see migration 070 for the birthday bound.
    fingerprint: Mapped[str] = mapped_column(String(16), nullable=False)
    # Sealed, not JSONB. This column held real hostnames, accounts and
    # addresses in readable form — by construction, since reversibility is the
    # point — so anyone who could read the table had every identifier the
    # tokenisation existed to protect. Fernet under INTEGRATION_ENCRYPTION_KEY,
    # which lives in the environment and not in the database.
    #
    # Nothing is lost by making it opaque to SQL: the map was already read and
    # written whole and never queried by key.
    token_map_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_map_key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("uq_token_map_scope", "tenant_id", "investigation_id", unique=True),
        Index("ix_token_map_expires_at", "expires_at"),
    )


class TenantEvent(Base):
    """What happened to a tenant, append-only.

    `Tenant.status` answers *what is it now*. It cannot answer *who decided
    that, when, and what was it called before* — a current-state column is not
    a history, and reading one as a history is a mistake this platform has
    made before (`ip_lookups`).

    It exists because a tenant row created by an incoming alert carries a name
    nobody chose and a status nobody set, and the act of confirming it is a
    real administrative decision with no trace anywhere. That is backlog 29's
    finding — **no administrative action on this platform is recorded** —
    scoped to the one case that now has a user interface.

    Rows are written and never updated. `integration_audit` was not reused:
    it is integration configuration, and a table with two subjects is a table
    whose rows have to be filtered before they mean anything.
    """

    __tablename__ = "tenant_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Deliberately not a foreign key: the event outlives the tenant row it
    # describes, and "created by an alert, then removed" is the history most
    # worth keeping.
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Both sides of the change, so no reader has to reconstruct the previous
    # value from an earlier row that may not exist.
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    from_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    to_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
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

    #: Who uploaded it, as the attribution pair. Captured at upload, where the
    #: session exists — it was being discarded, which made every new run
    #: permanently unattributable for no reason. Existing rows are
    #: `predates_attribution`: an actor existed and was not recorded, which is
    #: a different claim from `automated_ingest` (no human was involved).
    actor_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="predates_attribution",
        server_default="predates_attribution",
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    actor_recorded: Mapped[str | None] = mapped_column(String(255), nullable=True)
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
        Index("idx_email_runs_actor", "actor_kind"),
    )


class AlertBodyInvestigationRun(Base):
    """One pasted alert body, its extracted indicators, and their JSON reports."""
    __tablename__ = "alert_body_investigation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    #: Sender-supplied free text, and the case label derives from the
    #: first alert's title — so a ceiling here becomes a truncated case
    #: name. 771 rows sat at exactly 255 before migration 057.
    title: Mapped[str] = mapped_column(Text, nullable=False)
    alert_body: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    indicator_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: The worst indicator-reputation score among this alert's indicators.
    #:
    #: NOT a severity, despite having been used as one. It is the maximum over
    #: the alert's indicators of a seven-component weighted sum, five of whose
    #: components are URL, email, attachment and sandbox signals, with a
    #: step-floor from OpenCTI — so it measures how much of a phishing formula
    #: a source can reach. Windows alerts average 8.8 and Fortigate 62.0.
    #: `source_severity` is the severity. See migration 055.
    indicator_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # The alert's indicator values, kept in step with result_json by a
    # database trigger (migration 040). Correlation reads this to ask what
    # two alerts have in common; deriving it from the JSON on every page
    # load cost 2.4 seconds a time.
    ioc_values: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    #: Which kind of alert this is, as the graph's field map names it. Written
    #: during extraction so an empty graph can say *which* source it could not
    #: read, instead of rendering a blank canvas that reads as "no attack".
    graph_source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: When this run's graph rows were last written. NULL means never.
    #: The graph tables are a cache, and before this column nothing
    #: recorded how old any figure drawn from them was.
    graph_materialised_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: The alert's severity as its own source states it, normalised to 0-100.
    #: Null where the source states none — never 0, because a blank encoded as
    #: a measurement is the bug this column exists to replace.
    source_severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: The native value and scale, so a normalised number can be traced back.
    source_severity_raw: Mapped[str | None] = mapped_column(String(96), nullable=True)
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
    __table_args__ = (
        # A pointer never travels without saying who wrote it. The live
        # correlation pass wrote two without, and they were the only rows in
        # 866 a reader could not account for. Migration 059.
        CheckConstraint(
            "superseded_by_case_key IS NULL OR supersession_state IS NOT NULL",
            name="ck_case_spine_pointer_has_provenance",
        ),
    )

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
    # The client this case belongs to, taken from the alerts it groups.
    #
    # Not `alert_client`, which is the sender's own label and reads "unknown"
    # for 1,079 of 1,098 cases — a filter built on it offers one option for
    # almost the whole estate.
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Who signed this case off, what they said, and which analysis was in
    # front of them when they did.
    #
    # The fingerprint is not redundant with `narrative_fingerprint`: that one
    # is rewritten whenever a fresh narrative is dispatched, which correlation
    # does for closed cases too, so without a frozen copy an analyst's
    # decision silently re-attaches to an analysis they never read.
    closed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closure_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_narrative_fingerprint: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    #: What became of a key that no longer re-derives:
    #: mapped | ambiguous | target_unknown | expired. Null means the key still
    #: resolves and the question does not arise.
    supersession_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    supersession_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Every live case this row might be, when it is ambiguous. A wrong
    #: pointer silently attributes one incident's analysis to another, so an
    #: unresolved row keeps all its candidates rather than picking one.
    supersession_candidates: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    #: Which key formula produced `case_key`. Bumped by whoever changes the
    #: formula, alongside a migration — the absence of this is why 880 rows
    #: were orphaned on 2026-10-07.
    case_key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    # How often the closing job has tried and failed to read this case back.
    #
    # A case whose membership no longer re-derives stayed open and kept its
    # place at the head of an oldest-activity-first queue, so every pass
    # selected it again, in the same position, and paid a full re-correlation
    # to fail in the same way. Six were enough to take throughput to zero.
    closure_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0", default=0
    )
    closure_attempted_at: Mapped[datetime | None] = mapped_column(
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


class AlertGraphEntity(Base):
    """One entity, as one alert witnessed it.

    Materialised rather than re-parsed. The case graph is then a join on
    `run_id`, and "where else has this thing been seen" is an index hit on
    `merge_key` instead of a scan that re-reads 15,000 alert bodies.

    One row per (alert, entity): the same binary seen by four alerts is four
    rows sharing a `merge_key`, and collapsing them into one node is the
    assembler's job. Storing the merged node instead would throw away which
    alert saw what, which is exactly what the side panel has to show.
    """

    __tablename__ = "alert_graph_entity"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: The identity. Two rows with the same value are the same thing.
    merge_key: Mapped[str] = mapped_column(String(512), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    #: observed | parsed | inferred — what the status is computed from.
    basis: Mapped[str] = mapped_column(String(16), nullable=False)
    attrs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Copied off the alert so ordering the graph needs no join.
    event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: The worst indicator-reputation score of any alert that touched this
    #: entity. NOT a severity: it is the aggregator's seven-component sum, and
    #: five of those components are URL, email, attachment or sandbox signals.
    indicator_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: The alert's own source severity, normalised 0-100. This is the severity.
    source_severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint("run_id", "merge_key", name="uq_graph_entity_run_key"),
        Index("ix_graph_entity_merge_key", "merge_key"),
        Index("ix_graph_entity_run", "run_id"),
    )


class AlertGraphEdge(Base):
    """One relationship, as one alert witnessed it.

    Endpoints are merge keys, not row ids, so an edge survives being written
    by an alert that never saw both ends as the same object.
    """

    __tablename__ = "alert_graph_edge"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_body_investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_key: Mapped[str] = mapped_column(String(512), nullable=False)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False)
    basis: Mapped[str] = mapped_column(String(16), nullable=False)
    attrs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint(
            "run_id", "kind", "source_key", "target_key",
            name="uq_graph_edge_run_triple",
        ),
        Index("ix_graph_edge_run", "run_id"),
        Index("ix_graph_edge_source", "source_key"),
        Index("ix_graph_edge_target", "target_key"),
    )


class AssetCriticality(Base):
    """Which machines matter more than others, as a person recorded it.

    Deliberately a table and not a name pattern. `EXP-DC-01` matches `-DC-`,
    and so does `EXP-DCOM-02`, while a domain controller named `EXP-SRV-09`
    matches nothing — the delimiter-boundary failure this codebase has already
    hit six times, failing silently in both directions. A crown jewel badge is
    the single most persuasive mark on the graph; it does not get to be a
    guess about a hostname.

    Three states, the same shape as a technique:

        confirmed   a person promoted it, and `set_by` says who
        proposed    a seeding helper suggested it from a name pattern or from
                    observed behaviour; nobody has agreed yet
        unknown     no row at all

    `unknown` renders as unknown. It never renders as "not a crown jewel":
    this estate has 1,878 cases and one seeded asset list, so absence of a row
    is absence of an opinion.
    """

    __tablename__ = "asset_criticality"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    #: The short host label, lowercased — the same key the graph merges hosts
    #: on, so a tier set against `EXP-DC-01` is found when an alert names
    #: `exp-dc-01.corp.local`.
    host: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    #: crown_jewel | high | normal, or NULL when no criticality judgement has
    #: been recorded. Nullable because one row now carries two independent
    #: judgements, and requiring a tier in order to record an environment would
    #: mean inventing the first to record the second.
    tier: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: production | test | unknown, or NULL for no judgement.
    #:
    #: Recorded because the estate's own figures were dominated by one machine:
    #: in the week before the ingestion collapse, 2,579 of 5,477 alerts (47%)
    #: came from `Windows-Test-Device`, and the top two hosts carried 77%. A
    #: statistic whose dominant term is a test rig is a statistic about the
    #: test rig.
    #:
    #: Classified, not hidden. Alerts from a test host still render and still
    #: investigate; what changes is that anything claiming to describe the
    #: estate leaves them out and says so.
    environment: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: confirmed | proposed, for the environment specifically. A proposal must
    #: not silently remove a host from the estate's numbers.
    environment_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: Why this host is classed as it is, in words.
    environment_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: confirmed | proposed
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    #: Why, in words. For a proposal, which signal suggested it; for a
    #: confirmation, what the person knows that the signal did not.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    set_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_asset_criticality_host", "host"),
        Index("ix_asset_criticality_state", "state"),
    )


class CaseReadSet(Base):
    """The alerts a narrative was actually written over.

    Not a freeze. A freeze happens on judgement; this records what was on
    screen when a read was taken, so a conclusion can be checked against the
    set it described and a later divergence is visible rather than silent.

    It exists because nothing else records a set. Of 1,698 narratives in this
    estate, zero name a single alert, and the five analyst-closed cases name no
    more than the 1,674 automatic ones — so this platform has never recorded
    what anyone was looking at when they formed a judgement.
    """

    __tablename__ = "case_read_set"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_key: Mapped[str] = mapped_column(String(64), nullable=False)
    read_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    #: narrative_auto | narrative_requested | judgement
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    derivation_version: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The alerts. A count is what every existing artefact already gives, and
    #: a count cannot be checked against anything.
    run_ids: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    narrative_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_case_read_set_case", "case_key"),
        Index("ix_case_read_set_read_at", "read_at"),
    )


#: The submitter attribution kinds, from `docs/design/submitter-attribution.md`.
#: A single NULL or a string like "unidentified" collapses four conditions
#: that mean different things to someone reading an investigation, which is
#: why this is an enum and not a nullable name.
ACTOR_HUMAN = "human"
ACTOR_SERVICE_ACCOUNT = "service_account"
ACTOR_AUTOMATED_INGEST = "automated_ingest"
ACTOR_PREDATES_ATTRIBUTION = "predates_attribution"
ACTOR_RECORDED_UNRESOLVABLE = "recorded_unresolvable"

ACTOR_KINDS = (
    ACTOR_HUMAN, ACTOR_SERVICE_ACCOUNT, ACTOR_AUTOMATED_INGEST,
    ACTOR_PREDATES_ATTRIBUTION, ACTOR_RECORDED_UNRESOLVABLE,
)


class InvestigationRecord(Base):
    """An ordered chain of claims, each with its evidence — the object three
    surfaces produce.

    Not a feature of a page. The email pipeline is already a fixed eight-step
    chain and simply never wrote it down; the alert surface has two steps
    nobody recorded; the indicator lookup produces one of these only on
    escalation, because it is a fan-out and not a chain, and a benign lookup
    must never grow a second page.

    **`incomplete` is the field that keeps this honest.** The recorder is
    fail-open in the pipeline — a recording bug must never take an
    investigation down — but a recorder that drops three of eight steps and
    then renders as a complete five-step chain is the defect this record
    exists to close, one level up. So a chain that did not record fully says
    so, above itself, and is never presented as the investigation.
    """

    __tablename__ = "investigation_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    #: Which surface produced it, and which run/alert/lookup it belongs to.
    #: Two columns rather than a polymorphic key, because a join that has to
    #: branch on a type column is a join nobody writes correctly twice.
    origin_surface: Mapped[str] = mapped_column(String(32), nullable=False)
    origin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    #: The attribution pair. Same column as the submitter attribution spec —
    #: one column, two features, designed once rather than invented twice.
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    #: What was recorded, when it cannot be resolved to an account. Kept
    #: because `recorded_unresolvable` means evidence exists — discarding the
    #: string would turn it into `predates_attribution`, a different claim.
    actor_recorded: Mapped[str | None] = mapped_column(String(255), nullable=True)

    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: One model call, at the very end, over the step records only.
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Entities the summary names that no step recorded. Non-empty means the
    #: summary is shown with them marked, and the steps remain the evidence.
    summary_unverified_entities: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    #: Quantities the summary states that appear in no step's structured
    #: fields. Names were not enough: "executed on five hosts" when the step
    #: recorded two introduces no new entity and is exactly what a reader
    #: acts on. The summary is meant to carry no quantities at all.
    summary_unverified_numerals: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )

    #: A chain that did not record fully. See the class docstring.
    incomplete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    incomplete_steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    #: The gate counters. `observables_stopped` is the prevalence shortcut's
    #: output and is the number that justifies the gate existing.
    steps_run: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    steps_escalated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observables_stopped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    model_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("idx_inv_records_origin", "origin_surface", "origin_id"),
        Index("idx_inv_records_created", "created_at"),
        Index("idx_inv_records_actor", "actor_kind"),
    )


class InvestigationStep(Base):
    """One claim, with the evidence for it and the warrant behind it.

    A step that **could not be asked** — a 403, a `no_field_map`, an
    `out_of_scope` — is a row here like any other, rendered as *No claim*
    with its reason. Dropping it would silently shorten the investigation and
    nobody could tell.
    """

    __tablename__ = "investigation_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    #: The template key. A kind with no template renders raw JSON, which the
    #: template-registry test exists to prevent.
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The question in plain words, so the chain reads without the templates.
    question: Mapped[str] = mapped_column(Text, nullable=False)

    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Endpoint or index — what was actually addressed.
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: The literal query. Ours, not the customer's, so it is kept verbatim.
    query: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Bounded, and the bound is recorded. A truncated response read as the
    #: whole response is the floor-as-fact shape. Sanitised before storage.
    response_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    response_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    observables_found: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observables_selected: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    #: Field-control state, observation floor, window — whatever this source's
    #: negative depends on. A negative without its warrant is not a negative.
    warrant: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Set when nothing was asked or the source refused. The kind is from
    #: `app/services/absence.py`; the reason is rendered as the step's text.
    absence_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    absence_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: What the step cost, by kind: quota call, sandbox credit, model call,
    #: or nothing. Structured so the gate can be evaluated before the call.
    cost: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("idx_inv_steps_record", "record_id", "ordinal"),
    )


class IndicatorLookup(Base):
    """One on-demand indicator lookup, and who asked for it.

    **The actor only, deliberately.** The full attribution schema
    (`docs/design/submitter-attribution.md`) is not built yet, and waiting for
    it would mean shipping a lookup surface with no record of who used it —
    which is the state the free-form query console is blocked on in backlog 17.
    So this records the one field that cannot be reconstructed later: a query
    log with no actor answers the only question it will ever be asked.

    `value` is stored because the question is the record — "who looked up
    what" is unanswerable without it, and these are indicators under
    investigation rather than customer content. The *results* are not stored:
    they are re-derivable, they age, and keeping them would make this a second
    copy of evidence with its own staleness.
    """

    __tablename__ = "indicator_lookups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    #: The attribution pair, converged onto the submitter attribution shape.
    #:
    #: This shipped as `actor: String(255)` with `"unidentified"` for absent —
    #: which is exactly the four-way collapse that spec exists to prevent, and
    #: made this the weaker of two implementations of one idea on the same day
    #: the other was written. Migrated rather than left to become the stale
    #: second copy.
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    actor_recorded: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Which customer's data was asked about.
    tenant_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: The detected kind, so a later reader can see which question was asked
    #: rather than inferring it from the value.
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Which sources were actually queried, as opposed to refused by routing.
    sources_asked: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("idx_indicator_lookups_created", "created_at"),
        Index("idx_indicator_lookups_actor", "actor_kind"),
    )


class WatchHeartbeat(Base):
    """When each scheduled watch last *finished*, as distinct from last alarmed.

    Five watch tasks ran on a schedule, returned a result, and the result was
    dropped — beat discards it and nothing else reads it. The only channel out
    was a log line, and when the tasks began failing in 2026-09 the line
    recorded `type(exc).__name__` and threw the message away. 36 graph sweeps
    and 21 stall-watch runs failed in one 89-minute window before anybody
    looked.

    A silent alarm and a quiet estate are indistinguishable. That is the exact
    condition `watch_pipeline` exists to detect, reproduced one level up by
    `watch_pipeline` itself, and no amount of fixing the return shape removes
    it while the outcome has nowhere to go.

    So the outcome gets a sink. Written **only on success** — a row updated in
    a `finally` would survive the failure it exists to expose — and read by
    `/health`, which runs in the API process, because a worker cannot report
    its own death.
    """

    __tablename__ = "watch_heartbeat"

    task: Mapped[str] = mapped_column(String(120), primary_key=True)
    last_ok_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: The result itself, so "it ran" and "what it found" are one read.
    last_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Consecutive failures since the last success. Reset on success, so a
    #: fresh `last_ok_at` with a non-zero count is a flapping task — which
    #: neither field says on its own.
    failures_since: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class TenantIntegration(Base):
    """One security tool configured for one tenant.

    Keyed on `tenant_id`, not on a client. Credentials have to live on the
    axis that carries authorisation: `users.tenant_ids`, `users.all_tenants`
    and `api_keys.tenant_ids` all scope by tenant, and nothing in this schema
    authorises on `clients`. A secret on an axis with no access control is a
    cross-tenant leak by default rather than by bug — "may this user see this
    credential?" would have no answer in the data, only an invented join.

    What this row deliberately does not have
    ----------------------------------------
    **No `enabled` column.** "Enabled" is the word that cost seven months: a
    ThreatFox integration that was enabled, configured, and answering 401 on
    every single call looked healthy by every flag the platform had. Status is
    *derived* — from whether a connector exists in the code, whether a
    credential is stored here, and what the last real authenticated call
    returned — and never asserted by a boolean somebody set.

    **No plaintext.** `secret_ciphertext` is Fernet output from
    `app/security/secret_box.py`; `secret_key_id` names the key that sealed
    it so a rotation can count the rows it has not reached yet. Nothing
    serialises this column — `test_integration_secrets.py` asserts no
    response model carries it.

    `health` is keyed by direction
    -----------------------------
    `{"enrichment": {...}, "ingest": {...}}`, because an integration that
    answers queries and has stopped delivering detections is healthy by one
    measure and dead by the other, and a single status would show green
    through exactly that. The set of directions comes from the connector, so
    it is derived like the catalogue; JSONB means the ingest pass needs no
    migration.
    """

    __tablename__ = "tenant_integrations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "tool", name="uq_tenant_integration"),
        Index("idx_tenant_integrations_tenant", "tenant_id"),
        Index("idx_tenant_integrations_key", "secret_key_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Non-secret settings only — base URL, region, cloud name.
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Nullable: a connector may legitimately need no secret.
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    secret_set_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    configured_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IntegrationAudit(Base):
    """Who configured which tool for which tenant, and when.

    No foreign key to `tenant_integrations`, deliberately. The audit of a
    configuration has to outlive the configuration being removed — the
    property that let a deleted investigation's alert run survive on
    2026-10-13 and remain the only inspectable record of a wrong verdict.

    `detail` records *what changed*, never what it changed to. A secret never
    reaches this table, and `test_integration_secrets.py` asserts it.
    """

    __tablename__ = "integration_audit"
    __table_args__ = (
        Index("idx_integration_audit_subject", "tenant_id", "tool", "at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    #: configured | secret_set | removed | verified | rotated
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
