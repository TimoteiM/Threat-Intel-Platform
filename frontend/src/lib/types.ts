/**
 * TypeScript types — mirrors backend Pydantic schemas.
 *
 * Keep in sync with: backend/app/models/schemas.py
 * Keep in sync with: backend/app/models/enums.py
 */

// --- Enums ---

export type InvestigationState =
  | "created"
  | "gathering"
  | "evaluating"
  | "insufficient_data"
  | "concluded"
  | "failed";

export type ObservableType = "domain" | "ip" | "url" | "hash" | "file";

export type Classification = "benign" | "suspicious" | "malicious" | "inconclusive";
export type Confidence = "low" | "medium" | "high";
export type SOCAction = "monitor" | "investigate" | "block" | "hunt";
export type CollectorStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type IOCType = "ip" | "domain" | "url" | "hash" | "email";

// --- Collector Evidence ---

export interface CollectorMeta {
  collector: string;
  version: string;
  status: CollectorStatus;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  error?: string;
}

export interface DNSRecord {
  type: string;
  name: string;
  value: string;
  ttl?: number;
}

export interface DNSEvidence {
  meta: CollectorMeta;
  records: DNSRecord[];
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  dmarc?: string;
  spf?: string;
}

export interface WHOISEvidence {
  meta: CollectorMeta;
  registrar?: string;
  created_date?: string;
  updated_date?: string;
  expiry_date?: string;
  domain_age_days?: number;
  privacy_protected?: boolean;
  registrant_org?: string;
  registrant_country?: string;
  name_servers: string[];
  statuses: string[];
}

export interface HTTPRedirect {
  url: string;
  status_code: number;
  headers: Record<string, string>;
}

export interface HTTPEvidence {
  meta: CollectorMeta;
  reachable: boolean;
  final_url?: string;
  final_status_code?: number;
  redirect_chain: HTTPRedirect[];
  response_headers: Record<string, string>;
  server?: string;
  title?: string;
  content_length?: number;
  content_type?: string;
  favicon_hash?: string;
  has_login_form?: boolean;
  has_input_fields?: boolean;
  technologies_detected: string[];
  security_headers: Record<string, string>;
  brand_indicators: string[];
  phishing_indicators: string[];
  external_resources: string[];
}

export interface TLSEvidence {
  meta: CollectorMeta;
  present: boolean;
  issuer?: string;
  issuer_org?: string;
  subject?: string;
  sans: string[];
  valid_from?: string;
  valid_to?: string;
  valid_days_remaining?: number;
  serial_number?: string;
  is_wildcard?: boolean;
  is_self_signed?: boolean;
  chain_length?: number;
  cert_sha256?: string;
}

export interface ASNEvidence {
  meta: CollectorMeta;
  ip?: string;
  asn?: number;
  asn_org?: string;
  asn_description?: string;
  country?: string;
  city?: string;
  is_cdn?: boolean;
  is_cloud?: boolean;
  is_hosting?: boolean;
  reverse_dns?: string;
  related_domains_same_ip: string[];
}

// --- Intel Evidence ---

export interface IntelHit {
  source: string;
  indicator: string;
  category?: string;
  severity?: string;
  last_seen?: string;
  details?: string;
}

export interface IntelEvidence {
  meta: CollectorMeta;
  blocklist_hits: IntelHit[];
  allowlist_hits: IntelHit[];
  related_certs: string[];
  related_subdomains: string[];
  notes: string[];
}

// --- VirusTotal Evidence ---

export interface VTVendorResult {
  vendor: string;
  category: string;
  result: string;
  method?: string;
}

export interface VTEvidence {
  meta: CollectorMeta;
  found: boolean;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  undetected_count: number;
  total_vendors: number;
  flagged_malicious_by: string[];
  flagged_suspicious_by: string[];
  vendor_results: VTVendorResult[];
  categories: Record<string, string>;
  popularity_ranks: Record<string, number>;
  reputation_score: number;
  vt_creation_date?: string;
  vt_last_modified?: string;
  last_analysis_date?: string;
  vt_dns_records: any[];
  vt_cert_issuer: string;
  vt_cert_subject: string;
  vt_registrar: string;
  tags: string[];
  notes: string[];
  file_name?: string;
  file_names: string[];
}

// --- Domain Similarity ---

export interface TyposquattingTechnique {
  technique: string;
  description: string;
  original_segment: string;
  modified_segment: string;
}

export interface HomoglyphMatch {
  position: number;
  original_char: string;
  replaced_with: string;
  description: string;
}

export interface DomainSimilarityEvidence {
  client_domain: string;
  investigated_domain: string;
  levenshtein_distance: number;
  normalized_distance: number;
  visual_similarity_score: number;
  overall_similarity_score: number;
  typosquatting_techniques: TyposquattingTechnique[];
  homoglyph_matches: HomoglyphMatch[];
  is_potential_typosquat: boolean;
  is_visual_lookalike: boolean;
  summary: string;
}

// --- Visual Comparison ---

export interface VisualComparisonEvidence {
  investigated_domain: string;
  client_domain: string;
  investigated_screenshot_artifact_id?: string;
  client_screenshot_artifact_id?: string;
  reference_image_used: boolean;
  investigated_final_url?: string;
  client_final_url?: string;
  phash_similarity?: number;
  histogram_similarity?: number;
  overall_visual_similarity?: number;
  is_visual_clone: boolean;
  is_partial_clone: boolean;
  summary: string;
  investigated_capture_error?: string;
  client_capture_error?: string;
}

// --- Domain Screenshot ---

export interface ScreenshotEvidence {
  artifact_id?: string;
  final_url?: string;
  capture_error?: string;
}

// --- Subdomain Enumeration ---

export interface SubdomainEntry {
  subdomain: string;
  ips: string[];
  is_interesting: boolean;
}

export interface SubdomainEvidence {
  discovered_count: number;
  resolved: SubdomainEntry[];
  unresolved: string[];
  interesting_subdomains: SubdomainEntry[];
  ip_groups: Record<string, string[]>;
}

// --- Email Security ---

export interface DKIMRecord {
  selector: string;
  public_key_present: boolean;
  key_type?: string;
  notes?: string;
}

export interface MXRecord {
  priority: number;
  hostname: string;
  ips: string[];
  blocklist_hits: string[];
}

export interface EmailSecurityEvidence {
  dmarc_record?: string;
  dmarc_policy?: string;
  dmarc_subdomain_policy?: string;
  dmarc_pct?: number;
  dmarc_rua: string[];
  dmarc_ruf: string[];
  dmarc_alignment_dkim?: string;
  dmarc_alignment_spf?: string;
  spf_record?: string;
  spf_mechanisms: string[];
  spf_all_qualifier?: string;
  spf_includes: string[];
  spf_ip_count?: number;
  dkim_selectors_found: string[];
  dkim_records: DKIMRecord[];
  mx_records: MXRecord[];
  spoofability_score?: string;
  spoofability_reasons: string[];
  email_security_score?: number;
}

// --- Redirect Analysis ---

export interface RedirectProbe {
  user_agent_type: string;
  user_agent: string;
  status_code: number;
  final_url: string;
  redirect_count: number;
  title?: string;
  content_hash: string;
}

export interface IntermediateDomain {
  domain: string;
  hop_number: number;
  is_known_tracker: boolean;
  is_known_redirector: boolean;
}

export interface RedirectAnalysisEvidence {
  probes: RedirectProbe[];
  cloaking_detected: boolean;
  cloaking_details: string[];
  intermediate_domains: IntermediateDomain[];
  evasion_techniques: string[];
  max_chain_length: number;
  has_geo_block?: boolean;
}

// --- JavaScript Analysis ---

export interface CapturedRequest {
  url: string;
  method: string;
  resource_type: string;
  domain: string;
  is_external: boolean;
}

export interface PostEndpoint {
  url: string;
  content_type?: string;
  is_external: boolean;
  is_credential_form: boolean;
}

export interface SuspiciousScript {
  url: string;
  domain: string;
  size_bytes?: number;
  reason: string;
}

export interface JSAnalysisEvidence {
  total_requests: number;
  external_requests: number;
  request_domains: string[];
  captured_requests: CapturedRequest[];
  post_endpoints: PostEndpoint[];
  tracking_pixels: string[];
  fingerprinting_apis: string[];
  suspicious_scripts: SuspiciousScript[];
  websocket_connections: string[];
  data_exfil_indicators: string[];
  console_errors: string[];
  har_artifact_id?: string;
}

// --- Signals & Gaps ---

export interface Signal {
  id: string;
  category: string;
  description: string;
  severity: string;
  evidence_refs: string[];
}

export interface DataGap {
  id: string;
  description: string;
  collector: string;
  reason: string;
  impact: string;
}

// --- Infrastructure Pivot ---

export interface ReverseIPResult {
  ip: string;
  domains: string[];
  total_domains: number;
}

export interface NSCluster {
  nameservers: string[];
  domains: string[];
}

export interface RegistrantPivot {
  registrar?: string;
  registrant_org?: string;
  domains: string[];
}

export interface InfrastructurePivotEvidence {
  reverse_ip: ReverseIPResult[];
  ns_clusters: NSCluster[];
  registrant_pivots: RegistrantPivot[];
  total_related_domains: number;
  shared_hosting_detected: boolean;
  notes: string[];
}

// --- Certificate Transparency Timeline ---

export interface CertTimelineEntry {
  serial_number: string;
  issuer_name: string;
  common_name: string;
  not_before: string;
  not_after: string;
  entry_timestamp: string;
  validity_days: number;
  is_short_lived: boolean;
}

export interface CertTimelineEvidence {
  domain: string;
  total_certs: number;
  entries: CertTimelineEntry[];
  unique_issuers: string[];
  cert_burst_detected: boolean;
  burst_periods: { start: string; end: string; count: number }[];
  short_lived_count: number;
  earliest_cert?: string;
  latest_cert?: string;
  notes: string[];
}

// --- Favicon Hash Intelligence ---

export interface FaviconHost {
  ip: string;
  hostnames: string[];
  org?: string;
  port: number;
  asn?: string;
  country?: string;
}

export interface FaviconIntelEvidence {
  favicon_hash?: string;
  total_hosts_sharing: number;
  hosts: FaviconHost[];
  is_unique_favicon: boolean;
  is_default_favicon: boolean;
  notes: string[];
}

// --- URLScan Evidence ---

export interface URLScanEvidence {
  meta: CollectorMeta;
  scan_id?: string;
  verdict?: string;         // malicious | suspicious | benign
  score?: number;           // 0-100
  page_url?: string;
  page_ip?: string;
  page_country?: string;
  page_server?: string;
  page_title?: string;
  screenshot_artifact_id?: string;
  requests_count?: number;
  verdicts: Record<string, any>;
  tags: string[];
  notes: string[];
}


// --- Threat Feed Intelligence ---

export interface AbuseIPDBResult {
  ip: string;
  abuse_confidence_score: number;
  total_reports: number;
  last_reported_at?: string;
  categories: number[];
  isp?: string;
  usage_type?: string;
  country_code?: string;
}

export interface PhishTankResult {
  in_database: boolean;
  phish_id?: string;
  verified?: boolean;
  verified_at?: string;
  target_brand?: string;
}

export interface ThreatFoxResult {
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  malware?: string;
  confidence_level?: number;
  first_seen?: string;
  last_seen?: string;
  tags: string[];
}

export interface ThreatFeedEvidence {
  meta: CollectorMeta;
  abuseipdb?: AbuseIPDBResult;
  phishtank?: PhishTankResult;
  threatfox_matches: ThreatFoxResult[];
  openphish_listed: boolean;
  feeds_checked: string[];
  feeds_skipped: string[];
}

// --- Master Evidence ---

export interface CollectedEvidence {
  domain: string;
  observable_type: ObservableType;
  investigation_id: string;
  timestamps: Record<string, string>;
  dns?: DNSEvidence;
  whois?: WHOISEvidence;
  http?: HTTPEvidence;
  tls?: TLSEvidence;
  hosting?: ASNEvidence;
  intel?: IntelEvidence;
  vt?: VTEvidence;
  urlscan?: URLScanEvidence;
  threat_feeds?: ThreatFeedEvidence;
  domain_similarity?: DomainSimilarityEvidence;
  visual_comparison?: VisualComparisonEvidence;
  screenshot?: ScreenshotEvidence;
  subdomains?: SubdomainEvidence;
  email_security?: EmailSecurityEvidence;
  redirect_analysis?: RedirectAnalysisEvidence;
  js_analysis?: JSAnalysisEvidence;
  favicon_intel?: FaviconIntelEvidence;
  cert_timeline?: CertTimelineEvidence;
  infrastructure_pivot?: InfrastructurePivotEvidence;
  signals: Signal[];
  data_gaps: DataGap[];
  artifact_hashes: Record<string, string>;
  external_context?: {
    opencti_observables: any[];
    flare_findings: any[];
    soc_ticket_notes?: string;
    additional_context?: string;
  };
}

// --- Infrastructure Pivot ---

export interface SharedInfrastructure {
  type: string;
  value: string;
}

export interface RelatedInvestigation {
  id: string;
  domain: string;
  classification?: Classification;
  risk_score?: number;
  state: InvestigationState;
  created_at?: string;
  shared_infrastructure: SharedInfrastructure[];
}

export interface PivotPoints {
  ips: string[];
  cert_sha256?: string;
  asn?: number;
  registrar?: string;
  name_servers: string[];
}

export interface PivotResponse {
  pivot_points: PivotPoints;
  related_investigations: RelatedInvestigation[];
}

// --- Analyst Report ---

export interface AnalystFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  evidence_refs: string[];
  ttp?: string;
  ttp_name?: string;
  ttp_tactic?: string;
  ttp_url?: string;
}

export interface IOC {
  type: IOCType;
  value: string;
  context: string;
  confidence: Confidence;
}

export interface AnalystReport {
  classification: Classification;
  confidence: Confidence;
  investigation_state: InvestigationState;
  primary_reasoning: string;
  legitimate_explanation: string;
  malicious_explanation: string;
  key_evidence: string[];
  contradicting_evidence: string[];
  data_needed: string[];
  findings: AnalystFinding[];
  iocs: IOC[];
  recommended_action: SOCAction;
  recommended_steps: string[];
  risk_score?: number;
  risk_rationale?: string;
  executive_summary?: string;
  technical_narrative?: string;
  recommendations_narrative?: string;
}

// --- API Responses ---

export interface InvestigationListItem {
  id: string;
  domain: string;
  observable_type?: ObservableType;
  state: InvestigationState;
  classification?: Classification;
  risk_score?: number;
  created_at: string;
}

export interface InvestigationDetail {
  id: string;
  domain: string;
  observable_type?: ObservableType;
  state: InvestigationState;
  classification?: Classification;
  confidence?: Confidence;
  risk_score?: number;
  recommended_action?: SOCAction;
  created_at: string;
  concluded_at?: string;
}

export interface ProgressEvent {
  type: string;
  investigation_id: string;
  state?: InvestigationState;
  collector?: string;
  collectors?: Record<string, CollectorStatus>;
  message?: string;
  percent_complete?: number;
  done?: boolean;
}

// --- Batch Investigation ---

export interface BatchListItem {
  id: string;
  name?: string;
  total_domains: number;
  completed_count: number;
  status: string;
  created_at?: string;
  completed_at?: string;
}

export interface BatchInvestigation {
  id: string;
  domain: string;
  state: InvestigationState;
  classification?: Classification;
  confidence?: Confidence;
  risk_score?: number;
  recommended_action?: SOCAction;
  created_at?: string;
  concluded_at?: string;
}

export interface BatchDetail extends BatchListItem {
  investigations: BatchInvestigation[];
}

export interface CampaignDomain {
  id: string;
  domain: string;
  classification?: Classification;
  risk_score?: number;
}

export interface CampaignSharedInfra {
  type: string;
  values: string[];
}

export interface CampaignGroup {
  domains: CampaignDomain[];
  shared_infrastructure: CampaignSharedInfra[];
  size: number;
}

export interface CampaignResponse {
  campaigns: CampaignGroup[];
  unclustered: CampaignDomain[];
}

// --- Dashboard ---

export interface RiskBucket {
  bucket: string;
  count: number;
}

export interface TimelineEntry {
  date: string;
  classification: string;
  count: number;
}

export interface TopEntry {
  name: string;
  count: number;
}

export interface RecentMalicious {
  id: string;
  domain: string;
  risk_score?: number;
  classification?: string;
  created_at?: string;
}

export interface DashboardStats {
  total_investigations: number;
  classification_breakdown: Record<string, number>;
  risk_distribution: RiskBucket[];
  timeline: TimelineEntry[];
  top_registrars: TopEntry[];
  top_hosting_providers: TopEntry[];
  recent_malicious: RecentMalicious[];
}

// --- Watchlist ---

export type WatchlistStatus = "active" | "paused" | "removed";

export interface WatchlistEntry {
  id: string;
  domain: string;
  notes?: string;
  added_by?: string;
  status: WatchlistStatus;
  created_at: string;
  last_checked_at?: string;
  alert_count: number;
}

export interface WatchlistAlert {
  id: string;
  alert_type: string;
  details_json: Record<string, any>;
  created_at: string;
  acknowledged: boolean;
}

// --- Client Management ---

export type ClientStatus = "active" | "paused";
export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type AlertType =
  | "brand_impersonation"
  | "typosquatting"
  | "phishing_detected"
  | "infrastructure_overlap";

export interface Client {
  id: string;
  name: string;
  domain: string;
  aliases: string[];
  brand_keywords: string[];
  contact_email?: string;
  notes?: string;
  status: ClientStatus;
  created_at: string;
  alert_count: number;
  last_alert_at?: string;
  // Cortex-like per-org config
  default_collectors: string[];
}

export interface ClientAlert {
  id: string;
  client_id: string;
  investigation_id?: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  title: string;
  details_json: Record<string, any>;
  created_at: string;
  acknowledged: boolean;
  resolved: boolean;
}

export interface ClientListResponse {
  items: Client[];
  total: number;
}

export interface ClientAlertListResponse {
  items: ClientAlert[];
  total: number;
}

// --- WHOIS History ---

export interface WHOISHistorySnapshot {
  id: string;
  domain: string;
  whois_json: Record<string, any>;
  captured_at: string;
  investigation_id?: string;
  changes_from_previous?: Record<string, { old: any; new: any }>;
}

// --- Geolocation ---

export interface GeoPoint {
  lat: number;
  lon: number;
  label: string;
  type: "hosting" | "mx" | "redirect" | "subdomain";
  country?: string;
  city?: string;
  ip: string;
}



