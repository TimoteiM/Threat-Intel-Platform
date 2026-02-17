"""
Pydantic schemas — the data contract for the entire application.

Three categories:
1. Evidence schemas (collector outputs)
2. Analyst schemas (Claude's output)
3. API schemas (request/response models)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.models.enums import (
    Classification,
    CollectorStatus,
    Confidence,
    IOCType,
    InvestigationState,
    Severity,
    SOCAction,
)


# ═════════════════════════════════════════════════
# 1. EVIDENCE SCHEMAS (collector outputs)
# ═════════════════════════════════════════════════

class CollectorMeta(BaseModel):
    """Audit trail attached to every collector result."""
    collector: str
    version: str = "1.0.0"
    status: CollectorStatus = CollectorStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    raw_artifact_hash: Optional[str] = None


# ─── DNS ───

class DNSRecord(BaseModel):
    type: str
    name: str
    value: str
    ttl: Optional[int] = None


class DNSEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="dns"))
    records: list[DNSRecord] = []
    a: list[str] = []
    aaaa: list[str] = []
    cname: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    dmarc: Optional[str] = None
    spf: Optional[str] = None
    has_dnssec: Optional[bool] = None


# ─── WHOIS ───

class WHOISEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="whois"))
    registrar: Optional[str] = None
    created_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    privacy_protected: Optional[bool] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: list[str] = []
    statuses: list[str] = []


# ─── HTTP ───

class HTTPRedirect(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str] = {}


class HTTPEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="http"))
    reachable: bool = False
    final_url: Optional[str] = None
    final_status_code: Optional[int] = None
    redirect_chain: list[HTTPRedirect] = []
    response_headers: dict[str, str] = {}
    server: Optional[str] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    favicon_hash: Optional[str] = None
    has_login_form: Optional[bool] = None
    has_input_fields: Optional[bool] = None
    technologies_detected: list[str] = []
    security_headers: dict[str, str] = {}


# ─── TLS ───

class TLSEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="tls"))
    present: bool = False
    issuer: Optional[str] = None
    issuer_org: Optional[str] = None
    subject: Optional[str] = None
    sans: list[str] = []
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    valid_days_remaining: Optional[int] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_wildcard: Optional[bool] = None
    is_self_signed: Optional[bool] = None
    chain_length: Optional[int] = None
    chain_issuers: list[str] = []
    cert_sha256: Optional[str] = None


# ─── ASN / Hosting ───

class ASNEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="asn"))
    ip: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    asn_description: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    is_cdn: Optional[bool] = None
    is_cloud: Optional[bool] = None
    is_hosting: Optional[bool] = None
    reverse_dns: Optional[str] = None
    related_domains_same_ip: list[str] = []


# ─── Intel / Reputation ───

class IntelHit(BaseModel):
    source: str
    indicator: str
    category: Optional[str] = None
    severity: Optional[str] = None
    last_seen: Optional[datetime] = None
    details: Optional[str] = None


class IntelEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="intel"))
    blocklist_hits: list[IntelHit] = []
    allowlist_hits: list[IntelHit] = []
    related_certs: list[str] = []
    related_subdomains: list[str] = []
    notes: list[str] = []

# ─── VirusTotal Evidence ───

class VTVendorResult(BaseModel):
    vendor: str
    category: str  # malicious, suspicious, harmless, undetected
    result: str
    method: str = ""

class VTEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="vt"))
    found: bool = False
    # Detection stats
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_vendors: int = 0
    # Who flagged it
    flagged_malicious_by: list[str] = []
    flagged_suspicious_by: list[str] = []
    # Full vendor results
    vendor_results: list[VTVendorResult] = []
    # Categories from categorization services
    categories: dict[str, str] = {}
    # Popularity ranks
    popularity_ranks: dict[str, int] = {}
    # Community reputation
    reputation_score: int = 0
    # Dates
    vt_creation_date: Optional[str] = None
    vt_last_modified: Optional[str] = None
    last_analysis_date: Optional[str] = None
    # DNS from VT
    vt_dns_records: list[dict] = []
    # TLS from VT
    vt_cert_issuer: str = ""
    vt_cert_subject: str = ""
    # WHOIS from VT
    vt_registrar: str = ""
    # Tags
    tags: list[str] = []
    notes: list[str] = []

    

# ─── Domain Similarity (typosquatting / visual lookalike) ───

class TyposquattingTechnique(BaseModel):
    """A specific typosquatting technique detected between two domains."""
    technique: str
    description: str
    original_segment: str
    modified_segment: str


class HomoglyphMatch(BaseModel):
    """A visually confusable character substitution."""
    position: int
    original_char: str
    replaced_with: str
    description: str


class DomainSimilarityEvidence(BaseModel):
    """Result of comparing investigated domain against a client domain."""
    client_domain: str
    investigated_domain: str
    levenshtein_distance: int
    normalized_distance: float
    visual_similarity_score: float
    overall_similarity_score: int
    typosquatting_techniques: list[TyposquattingTechnique] = []
    homoglyph_matches: list[HomoglyphMatch] = []
    is_potential_typosquat: bool
    is_visual_lookalike: bool
    summary: str


# ─── Visual Comparison ───

class VisualComparisonEvidence(BaseModel):
    """Screenshot-based visual comparison between investigated and client domains."""
    investigated_domain: str
    client_domain: str
    investigated_screenshot_artifact_id: Optional[str] = None
    client_screenshot_artifact_id: Optional[str] = None
    reference_image_used: bool = False

    # Similarity metrics (0.0–1.0, higher = more similar)
    phash_similarity: Optional[float] = None
    histogram_similarity: Optional[float] = None
    overall_visual_similarity: Optional[float] = None

    # Classification
    is_visual_clone: bool = False       # overall >= 0.80
    is_partial_clone: bool = False      # overall 0.50–0.79

    summary: str = ""

    # Error details
    investigated_capture_error: Optional[str] = None
    client_capture_error: Optional[str] = None


# ─── Signals & Gaps ───

class Signal(BaseModel):
    """An investigative clue — NOT a conclusion."""
    id: str
    category: str
    description: str
    severity: str = "info"
    evidence_refs: list[str] = []


class DataGap(BaseModel):
    """Missing data that prevents certainty."""
    id: str
    description: str
    collector: str
    reason: str
    impact: str


# ─── External Context (user-provided CTI) ───

class ExternalContext(BaseModel):
    opencti_observables: list[dict[str, Any]] = []
    flare_findings: list[dict[str, Any]] = []
    soc_ticket_notes: Optional[str] = None
    additional_context: Optional[str] = None


# ─── Master Evidence Object ───

class CollectedEvidence(BaseModel):
    """
    Everything passed to the Claude analyst.
    Built by aggregating all collector outputs + signals + gaps.
    """
    domain: str
    investigation_id: str
    timestamps: dict[str, datetime] = {}

    # Facts (collector outputs)
    dns: DNSEvidence = Field(default_factory=DNSEvidence)
    whois: WHOISEvidence = Field(default_factory=WHOISEvidence)
    http: HTTPEvidence = Field(default_factory=HTTPEvidence)
    tls: TLSEvidence = Field(default_factory=TLSEvidence)
    hosting: ASNEvidence = Field(default_factory=ASNEvidence)
    intel: IntelEvidence = Field(default_factory=IntelEvidence)
    vt: VTEvidence = Field(default_factory=VTEvidence)

    # Observations
    signals: list[Signal] = []
    data_gaps: list[DataGap] = []

    # Domain similarity (when comparing against a client domain)
    domain_similarity: Optional[DomainSimilarityEvidence] = None

    # Visual comparison (screenshot-based, when client_domain provided)
    visual_comparison: Optional[VisualComparisonEvidence] = None

    # User-provided enrichment
    external_context: Optional[ExternalContext] = None

    # Artifact tracking
    artifact_hashes: dict[str, str] = {}


# ═════════════════════════════════════════════════
# 2. ANALYST SCHEMAS (Claude's output)
# ═════════════════════════════════════════════════

class AnalystFinding(BaseModel):
    id: str
    title: str
    description: str
    severity: str = "info"
    evidence_refs: list[str] = []
    ttp: Optional[str] = None


class IOC(BaseModel):
    type: IOCType
    value: str
    context: str
    confidence: Confidence = Confidence.LOW


class AnalystReport(BaseModel):
    """Structured output from the Claude analyst."""
    # Classification
    classification: Classification
    confidence: Confidence
    investigation_state: InvestigationState

    # Reasoning
    primary_reasoning: str
    legitimate_explanation: str
    malicious_explanation: str

    # Evidence assessment
    key_evidence: list[str] = []
    contradicting_evidence: list[str] = []
    data_needed: list[str] = []

    # Findings & IOCs
    findings: list[AnalystFinding] = []
    iocs: list[IOC] = []

    # Action
    recommended_action: SOCAction
    recommended_steps: list[str] = []

    # Risk
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    risk_rationale: Optional[str] = None

    # Narrative sections (for report UI)
    executive_summary: Optional[str] = None
    technical_narrative: Optional[str] = None
    recommendations_narrative: Optional[str] = None


# ═════════════════════════════════════════════════
# 3. API SCHEMAS (request / response)
# ═════════════════════════════════════════════════

class InvestigationCreate(BaseModel):
    """POST /investigations request body."""
    domain: str
    context: Optional[str] = None
    client_domain: Optional[str] = None
    investigated_url: Optional[str] = None   # Specific URL to screenshot (visual comparison)
    client_url: Optional[str] = None          # Client URL to compare against
    external_context: Optional[ExternalContext] = None
    requested_collectors: Optional[list[str]] = None


class InvestigationResponse(BaseModel):
    """GET /investigations/{id} response."""
    id: str
    domain: str
    state: InvestigationState
    created_at: datetime
    updated_at: Optional[datetime] = None
    concluded_at: Optional[datetime] = None
    classification: Optional[Classification] = None
    confidence: Optional[Confidence] = None
    risk_score: Optional[int] = None
    recommended_action: Optional[SOCAction] = None
    collector_statuses: dict[str, CollectorStatus] = {}


class InvestigationListItem(BaseModel):
    """Item in GET /investigations list response."""
    id: str
    domain: str
    state: InvestigationState
    classification: Optional[Classification] = None
    risk_score: Optional[int] = None
    created_at: datetime


class InvestigationCreatedResponse(BaseModel):
    """POST /investigations response."""
    investigation_id: str
    domain: str
    state: InvestigationState
    message: str


class ProgressUpdate(BaseModel):
    """SSE event payload."""
    investigation_id: str
    state: InvestigationState
    collectors: dict[str, CollectorStatus] = {}
    message: Optional[str] = None
    percent_complete: int = 0


class EnrichRequest(BaseModel):
    """POST /investigations/{id}/enrich request body."""
    opencti_observables: list[dict[str, Any]] = []
    flare_findings: list[dict[str, Any]] = []
    soc_ticket_notes: Optional[str] = None
    additional_context: Optional[str] = None
