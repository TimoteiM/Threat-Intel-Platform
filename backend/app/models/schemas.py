"""
Pydantic schemas â€” the data contract for the entire application.

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. EVIDENCE SCHEMAS (collector outputs)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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


# â”€â”€â”€ DNS â”€â”€â”€

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


# â”€â”€â”€ WHOIS â”€â”€â”€

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


# â”€â”€â”€ HTTP â”€â”€â”€

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

    # Content / phishing analysis
    brand_indicators: list[str] = []
    phishing_indicators: list[str] = []
    external_resources: list[str] = []


# â”€â”€â”€ TLS â”€â”€â”€

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


# â”€â”€â”€ ASN / Hosting â”€â”€â”€

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


# â”€â”€â”€ Intel / Reputation â”€â”€â”€

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
    # Raw cert entries from crt.sh for downstream timeline analysis
    cert_entries_raw: list[dict] = []

# â”€â”€â”€ VirusTotal Evidence â”€â”€â”€

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

    

# â”€â”€â”€ Certificate Transparency Timeline â”€â”€â”€

class CertTimelineEntry(BaseModel):
    serial_number: str
    issuer_name: str
    common_name: str
    not_before: str
    not_after: str
    entry_timestamp: str
    validity_days: int = 0
    is_short_lived: bool = False


class CertTimelineEvidence(BaseModel):
    domain: str
    total_certs: int = 0
    entries: list[CertTimelineEntry] = []
    unique_issuers: list[str] = []
    cert_burst_detected: bool = False
    burst_periods: list[dict] = []
    short_lived_count: int = 0
    earliest_cert: Optional[str] = None
    latest_cert: Optional[str] = None
    notes: list[str] = []


# â”€â”€â”€ Threat Feed Intelligence â”€â”€â”€

class AbuseIPDBResult(BaseModel):
    ip: str
    abuse_confidence_score: int = 0
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    categories: list[int] = []
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    country_code: Optional[str] = None


class PhishTankResult(BaseModel):
    in_database: bool = False
    phish_id: Optional[str] = None
    verified: Optional[bool] = None
    verified_at: Optional[str] = None
    target_brand: Optional[str] = None


class ThreatFoxResult(BaseModel):
    ioc_value: str
    ioc_type: str
    threat_type: str
    malware: Optional[str] = None
    confidence_level: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: list[str] = []


class ThreatFeedEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="threat_feeds"))
    abuseipdb: Optional[AbuseIPDBResult] = None
    phishtank: Optional[PhishTankResult] = None
    threatfox_matches: list[ThreatFoxResult] = []
    openphish_listed: bool = False
    feeds_checked: list[str] = []
    feeds_skipped: list[str] = []


# â”€â”€â”€ Infrastructure Pivot â”€â”€â”€

class ReverseIPResult(BaseModel):
    ip: str
    domains: list[str] = []
    total_domains: int = 0


class NSCluster(BaseModel):
    nameservers: list[str] = []
    domains: list[str] = []


class RegistrantPivot(BaseModel):
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    domains: list[str] = []


class InfrastructurePivotEvidence(BaseModel):
    reverse_ip: list[ReverseIPResult] = []
    ns_clusters: list[NSCluster] = []
    registrant_pivots: list[RegistrantPivot] = []
    total_related_domains: int = 0
    shared_hosting_detected: bool = False
    notes: list[str] = []


# â”€â”€â”€ Favicon Hash Intelligence â”€â”€â”€

class FaviconHost(BaseModel):
    ip: str
    hostnames: list[str] = []
    org: Optional[str] = None
    port: int = 80
    asn: Optional[str] = None
    country: Optional[str] = None


class FaviconIntelEvidence(BaseModel):
    favicon_hash: Optional[str] = None
    total_hosts_sharing: int = 0
    hosts: list[FaviconHost] = []
    is_unique_favicon: bool = True
    is_default_favicon: bool = False
    notes: list[str] = []


# â”€â”€â”€ Domain Similarity (typosquatting / visual lookalike) â”€â”€â”€

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


# â”€â”€â”€ Visual Comparison â”€â”€â”€

class VisualComparisonEvidence(BaseModel):
    """Screenshot-based visual comparison between investigated and client domains."""
    investigated_domain: str
    client_domain: str
    investigated_screenshot_artifact_id: Optional[str] = None
    client_screenshot_artifact_id: Optional[str] = None
    reference_image_used: bool = False
    investigated_final_url: Optional[str] = None
    client_final_url: Optional[str] = None

    # Similarity metrics (0.0â€“1.0, higher = more similar)
    phash_similarity: Optional[float] = None
    histogram_similarity: Optional[float] = None
    overall_visual_similarity: Optional[float] = None

    # Classification
    is_visual_clone: bool = False       # overall >= 0.80
    is_partial_clone: bool = False      # overall 0.50â€“0.79

    summary: str = ""

    # Error details
    investigated_capture_error: Optional[str] = None
    client_capture_error: Optional[str] = None


# â”€â”€â”€ Domain Screenshot â”€â”€â”€

class ScreenshotEvidence(BaseModel):
    """Standalone screenshot of the investigated domain."""
    artifact_id: Optional[str] = None
    final_url: Optional[str] = None
    capture_error: Optional[str] = None


# â”€â”€â”€ Subdomain Enumeration â”€â”€â”€

class SubdomainEntry(BaseModel):
    """A resolved subdomain with its IPs."""
    subdomain: str
    ips: list[str]
    is_interesting: bool


class SubdomainEvidence(BaseModel):
    """Active DNS resolution of discovered subdomains."""
    discovered_count: int = 0
    resolved: list[SubdomainEntry] = []
    unresolved: list[str] = []
    interesting_subdomains: list[SubdomainEntry] = []
    ip_groups: dict[str, list[str]] = {}  # IP -> [subdomains]


# â”€â”€â”€ Email Security â”€â”€â”€

class DKIMRecord(BaseModel):
    """A discovered DKIM selector and its key status."""
    selector: str
    public_key_present: bool
    key_type: Optional[str] = None
    notes: Optional[str] = None


class MXRecord(BaseModel):
    """A parsed MX record with resolved IPs and blocklist status."""
    priority: int
    hostname: str
    ips: list[str] = []
    blocklist_hits: list[str] = []


class EmailSecurityEvidence(BaseModel):
    """DMARC/SPF/DKIM policy analysis and MX reputation."""
    # DMARC
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_subdomain_policy: Optional[str] = None
    dmarc_pct: Optional[int] = None
    dmarc_rua: list[str] = []
    dmarc_ruf: list[str] = []
    dmarc_alignment_dkim: Optional[str] = None
    dmarc_alignment_spf: Optional[str] = None
    # SPF
    spf_record: Optional[str] = None
    spf_mechanisms: list[str] = []
    spf_all_qualifier: Optional[str] = None
    spf_includes: list[str] = []
    spf_ip_count: Optional[int] = None
    # DKIM
    dkim_selectors_found: list[str] = []
    dkim_records: list[DKIMRecord] = []
    # MX
    mx_records: list[MXRecord] = []
    # Assessment
    spoofability_score: Optional[str] = None
    spoofability_reasons: list[str] = []
    email_security_score: Optional[int] = None


# â”€â”€â”€ Redirect Analysis â”€â”€â”€

class RedirectProbe(BaseModel):
    """Result of probing a domain with a specific User-Agent."""
    user_agent_type: str
    user_agent: str
    status_code: int
    final_url: str
    redirect_count: int = 0
    title: Optional[str] = None
    content_hash: str


class IntermediateDomain(BaseModel):
    """A domain encountered during redirect chain traversal."""
    domain: str
    hop_number: int
    is_known_tracker: bool = False
    is_known_redirector: bool = False


class RedirectAnalysisEvidence(BaseModel):
    """Multi-UA redirect probing results and cloaking detection."""
    probes: list[RedirectProbe] = []
    cloaking_detected: bool = False
    cloaking_details: list[str] = []
    intermediate_domains: list[IntermediateDomain] = []
    evasion_techniques: list[str] = []
    max_chain_length: int = 0
    has_geo_block: Optional[bool] = None


# â”€â”€â”€ JavaScript Analysis â”€â”€â”€

class CapturedRequest(BaseModel):
    """A single network request captured during JS analysis."""
    url: str
    method: str = "GET"
    resource_type: str = "other"
    domain: str = ""
    is_external: bool = False


class PostEndpoint(BaseModel):
    """An HTTP POST endpoint captured during page load."""
    url: str
    content_type: Optional[str] = None
    is_external: bool = False
    is_credential_form: bool = False


class SuspiciousScript(BaseModel):
    """An external script loaded during page execution."""
    url: str
    domain: str
    size_bytes: Optional[int] = None
    reason: str


class JSAnalysisEvidence(BaseModel):
    """Playwright-based JavaScript behavior analysis."""
    total_requests: int = 0
    external_requests: int = 0
    request_domains: list[str] = []
    captured_requests: list[CapturedRequest] = []
    post_endpoints: list[PostEndpoint] = []
    tracking_pixels: list[str] = []
    fingerprinting_apis: list[str] = []
    suspicious_scripts: list[SuspiciousScript] = []
    websocket_connections: list[str] = []
    data_exfil_indicators: list[str] = []
    console_errors: list[str] = []
    har_artifact_id: Optional[str] = None


# â”€â”€â”€ URLScan Evidence â”€â”€â”€

class URLScanEvidence(BaseModel):
    meta: CollectorMeta = Field(default_factory=lambda: CollectorMeta(collector="urlscan"))
    scan_id: Optional[str] = None
    verdict: Optional[str] = None        # malicious | suspicious | benign
    score: Optional[int] = None          # 0-100
    page_url: Optional[str] = None
    page_ip: Optional[str] = None
    page_country: Optional[str] = None
    page_server: Optional[str] = None
    page_title: Optional[str] = None
    screenshot_artifact_id: Optional[str] = None
    requests_count: Optional[int] = None
    verdicts: dict[str, Any] = {}
    tags: list[str] = []
    notes: list[str] = []


# —— Signals & Gaps â”€â”€â”€

class Signal(BaseModel):
    """An investigative clue â€” NOT a conclusion."""
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


# â”€â”€â”€ External Context (user-provided CTI) â”€â”€â”€

class ExternalContext(BaseModel):
    opencti_observables: list[dict[str, Any]] = []
    flare_findings: list[dict[str, Any]] = []
    soc_ticket_notes: Optional[str] = None
    additional_context: Optional[str] = None


# â”€â”€â”€ Master Evidence Object â”€â”€â”€

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

    # Domain screenshot (always captured)
    screenshot: Optional[ScreenshotEvidence] = None

    # Subdomain enumeration (active resolution of crt.sh discoveries)
    subdomains: Optional[SubdomainEvidence] = None

    # Email security analysis (DMARC/SPF/DKIM/MX reputation)
    email_security: Optional[EmailSecurityEvidence] = None

    # Redirect chain analysis (multi-UA cloaking detection)
    redirect_analysis: Optional[RedirectAnalysisEvidence] = None

    # JavaScript behavior analysis (Playwright sandbox)
    js_analysis: Optional[JSAnalysisEvidence] = None

    # Threat feed intelligence (AbuseIPDB, PhishTank, ThreatFox, OpenPhish)
    threat_feeds: Optional[ThreatFeedEvidence] = None

    # Favicon hash pivot (Shodan infrastructure clustering)
    favicon_intel: Optional[FaviconIntelEvidence] = None

    # Certificate Transparency timeline (crt.sh full cert details)
    cert_timeline: Optional[CertTimelineEvidence] = None

    # Infrastructure pivot (reverse IP, NS clustering, registrant pivot)
    infrastructure_pivot: Optional[InfrastructurePivotEvidence] = None

    # URLScan.io full page scan (domain, ip, url types)
    urlscan: Optional[URLScanEvidence] = None

    # Observable type that was investigated
    observable_type: str = "domain"

    # User-provided enrichment
    external_context: Optional[ExternalContext] = None

    # Artifact tracking
    artifact_hashes: dict[str, str] = {}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. ANALYST SCHEMAS (Claude's output)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AnalystFinding(BaseModel):
    id: str
    title: str
    description: str
    severity: str = "info"
    evidence_refs: list[str] = []
    ttp: Optional[str] = None
    ttp_name: Optional[str] = None
    ttp_tactic: Optional[str] = None
    ttp_url: Optional[str] = None


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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. API SCHEMAS (request / response)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class InvestigationCreate(BaseModel):
    """POST /investigations request body."""
    domain: str                                     # Observable value (domain, IP, URL, hash, filename)
    observable_type: str = "domain"                 # domain | ip | url | hash | file
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
    observable_type: str = "domain"
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
    observable_type: str = "domain"
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


class WatchlistCreate(BaseModel):
    """POST /watchlist request body."""
    domain: str
    notes: Optional[str] = None
    added_by: Optional[str] = None
    schedule_interval: Optional[str] = None  # weekly, biweekly, monthly


class WatchlistUpdate(BaseModel):
    """PATCH /watchlist/{id} request body."""
    status: Optional[str] = None
    notes: Optional[str] = None
    schedule_interval: Optional[str] = None  # weekly, biweekly, monthly, or "none" to disable


# â”€â”€â”€ Client Management â”€â”€â”€

import uuid as _uuid
from pydantic import ConfigDict


class ClientCreate(BaseModel):
    """POST /api/clients request body."""
    name: str
    domain: str
    aliases: list[str] = []
    brand_keywords: list[str] = []
    contact_email: Optional[str] = None
    notes: Optional[str] = None
    default_collectors: list[str] = []   # Empty = run all collectors


class ClientUpdate(BaseModel):
    """PATCH /api/clients/{id} request body."""
    name: Optional[str] = None
    domain: Optional[str] = None
    aliases: Optional[list[str]] = None
    brand_keywords: Optional[list[str]] = None
    contact_email: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    default_collectors: Optional[list[str]] = None


class ClientRead(BaseModel):
    """Client in API responses."""
    id: _uuid.UUID
    name: str
    domain: str
    aliases: list[str]
    brand_keywords: list[str]
    contact_email: Optional[str]
    notes: Optional[str]
    status: str
    created_at: datetime
    alert_count: int
    last_alert_at: Optional[datetime]
    default_collectors: list[str]
    model_config = ConfigDict(from_attributes=True)


class ClientListResponse(BaseModel):
    items: list[ClientRead]
    total: int


class ClientAlertRead(BaseModel):
    """Alert record in API responses."""
    id: _uuid.UUID
    client_id: _uuid.UUID
    investigation_id: Optional[_uuid.UUID] = None
    alert_type: str
    severity: str
    title: str
    details_json: dict
    created_at: datetime
    acknowledged: bool
    resolved: bool
    model_config = ConfigDict(from_attributes=True)


class ClientAlertListResponse(BaseModel):
    items: list[ClientAlertRead]
    total: int


