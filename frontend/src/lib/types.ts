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

/**
 * Input modes offered on the New Investigation form. "alert_body" is not a
 * backend observable type — a pasted alert is parsed into many indicators and
 * runs through /api/alert-investigations instead.
 */
export type InvestigationInputType = ObservableType | "alert_body";

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

export interface SensitiveFormControl {
  form_index: number;
  tag: string;
  type: string;
  category: string;
  label?: string;
  placeholder?: string;
  autocomplete?: string;
  name?: string;
  required?: boolean;
  has_submit_control?: boolean;
  bounds?: { x: number; y: number; width: number; height: number };
}

export interface SensitiveFormDetection {
  detected: boolean;
  confidence: "none" | "medium" | "high" | string;
  interaction_required: boolean;
  form_count: number;
  visible_control_count: number;
  categories: string[];
  indicators: string[];
  controls: SensitiveFormControl[];
  sources: string[];
  screenshot_artifact_id?: string;
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
  error?: string;
  har_artifact_id?: string;
  sensitive_form_detection?: SensitiveFormDetection;
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

export interface URLLexicalMLEvidence {
  model_source?: string;
  score?: number;
  label?: "low" | "medium" | "high" | string;
  top_features?: string[];
  feature_contributions?: Record<string, number>;
  features?: Record<string, number>;
  thresholds?: Record<string, number>;
  weights?: Record<string, number>;
  raw_score?: number;
  calibration_applied?: boolean;
  rule_floor_applied?: boolean;
  error?: string;
}

export interface URLMLFeatureImpact {
  name: string;
  impact: number;
}

export interface URLMLScoreEvidence {
  url?: string;
  phishing_probability: number;
  risk_level: string;
  model_version: string;
  top_features: URLMLFeatureImpact[];
  raw?: Record<string, any>;
}

export interface URLBehaviorEvidence {
  checked: boolean;
  redirect_count: number;
  ua_cloaking_detected: boolean;
  credential_form_present: boolean;
  suspicious_post_endpoints: string[];
  multiple_domain_hops: boolean;
  unique_domains_in_chain: string[];
  final_url?: string;
  behavior_score: number;
  chains: any[];
  error?: string;
}

export interface ContentMLEvidence {
  social_engineering_probability: number;
  urgency_probability: number;
  impersonation_probability: number;
  bec_probability: number;
  top_content_terms: string[];
  model_source?: string;
  feature_hash?: string;
}

export interface AttachmentAnalysisItem {
  hash?: string;
  filename?: string;
  file_type: string;
  macro_detected: boolean;
  embedded_objects: boolean;
  entropy: number;
  suspicious_import_count: number;
  static_risk_score: number;
  risk_level: string;
}

export interface AttachmentAnalysisEvidence {
  checked: boolean;
  items: AttachmentAnalysisItem[];
  summary: Record<string, number>;
}

export interface HybridAnalysisItem {
  checked: boolean;
  indicator_type?: string;
  verdict: string;
  provider_verdict?: string;
  verdict_context?: Record<string, any>;
  analysis_id?: string;
  threat_score?: number;
  error?: string;
  cache_hit?: boolean;
  dynamic_io_summary?: Record<string, any>;
  raw_summary?: Record<string, any>;
  sandbox_intelligence?: Record<string, any>;
}

export interface HybridAnalysisEvidence {
  items: HybridAnalysisItem[];
}

// --- OpenCTI ---

export interface OpenCTIIndicator {
  id: string;
  name: string;
  pattern: string;
  valid_from?: string;
  valid_until?: string;
  confidence: number;
  revoked: boolean;
}

export interface OpenCTIReport {
  id: string;
  name: string;
  description: string;
  published?: string;
  author?: string;
  creators: string[];
  labels: string[];
  report_types: string[];
  created?: string;
  modified?: string;
}

export interface OpenCTIThreatActor {
  id: string;
  name: string;
  entity_type: string;
  sophistication?: string;
  resource_level?: string;
}

export interface OpenCTIMalware {
  id: string;
  name: string;
  malware_types: string[];
  first_seen?: string;
}

export interface OpenCTIAttackPattern {
  id: string;
  name: string;
  mitre_id?: string;
}

export interface OpenCTIEvidence {
  meta?: any;
  found: boolean;
  observable_id?: string;
  standard_id?: string;
  observable_entity_type?: string;
  observable_value?: string;
  score: number;
  author?: string;
  creators: string[];
  markings: string[];
  created_at?: string;
  updated_at?: string;
  labels: string[];
  indicators: OpenCTIIndicator[];
  reports: OpenCTIReport[];
  threat_actors: OpenCTIThreatActor[];
  malware_families: OpenCTIMalware[];
  attack_patterns: OpenCTIAttackPattern[];
  campaigns: string[];
  intrusion_sets: string[];
  notes: string[];
}

export interface FinalRiskEvidence {
  risk_score: number;
  risk_level: string;
  confidence: string;
  components: Record<string, number>;
  weights: Record<string, number>;
  rationale: string[];
}

export interface RedirectDestinationWhoisEvidence {
  status?: string;
  error?: string;
  registrar?: string;
  domain_age_days?: number;
  created_date?: string;
  expiry_date?: string;
  name_servers?: string[];
  registrant_org?: string;
  registrant_country?: string;
}

export interface RedirectDestinationVTEvidence {
  status?: string;
  error?: string;
  found?: boolean;
  malicious_count?: number;
  suspicious_count?: number;
  total_vendors?: number;
  reputation_score?: number;
  categories?: Record<string, string>;
}

export interface RedirectDestinationDNSEvidence {
  status?: string;
  error?: string;
  a?: string[];
  aaaa?: string[];
  mx?: string[];
  ns?: string[];
}

export interface RedirectDestinationHostingEvidence {
  status?: string;
  error?: string;
  ip?: string;
  asn?: number;
  asn_org?: string;
  country?: string;
  is_cdn?: boolean;
  is_cloud?: boolean;
}

export interface RedirectDestinationComparisonEvidence {
  source_age_days?: number;
  destination_age_days?: number;
  source_vs_destination_root?: string;
}

export interface RedirectDestinationIntelEvidence {
  final_url?: string;
  investigated_host?: string;
  investigated_root?: string;
  destination_host?: string;
  destination_root?: string;
  whois?: RedirectDestinationWhoisEvidence;
  vt?: RedirectDestinationVTEvidence;
  dns?: RedirectDestinationDNSEvidence;
  hosting?: RedirectDestinationHostingEvidence;
  comparison?: RedirectDestinationComparisonEvidence;
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

export interface GoogleSafeBrowsingResult {
  checked: boolean;
  listed: boolean;
  matches_count: number;
  threat_types: string[];
  platform_types?: string[];
  cache_durations?: string[];
  error?: string;
}

export interface OTXPulseResult {
  id?: string;
  name: string;
  description?: string;
  author_name?: string;
  created?: string;
  modified?: string;
  tlp?: string;
  subscriber_count?: number;
  indicator_count?: number;
  related_indicator_is_active?: boolean;
  tags: string[];
  malware_families: string[];
  adversary?: string;
  references: string[];
}

export interface OTXPassiveDNSRecord {
  hostname?: string;
  address?: string;
  record_type?: string;
  first?: string;
  last?: string;
  asn?: string;
  country?: string;
  asset_type?: string;
}

export interface OTXResult {
  checked: boolean;
  found: boolean;
  indicator?: string;
  indicator_type?: string;
  type_title?: string;
  pulse_count: number;
  pulses: OTXPulseResult[];
  sections: string[];
  validation: string[];
  indicator_facts: string[];
  tags: string[];
  malware_families: string[];
  adversaries: string[];
  references: string[];
  external_resources: Record<string, string>;
  geo: Record<string, string | number>;
  passive_dns_count: number;
  passive_dns: OTXPassiveDNSRecord[];
  nameservers: string[];
  subdomains: string[];
  ip_addresses: string[];
  url_count: number;
  urls: string[];
  malware_count: number;
  http_scans_count: number;
  reputation?: number;
  error?: string;
}

export interface ThreatFeedEvidence {
  meta: CollectorMeta;
  abuseipdb?: AbuseIPDBResult;
  phishtank?: PhishTankResult;
  threatfox_matches: ThreatFoxResult[];
  openphish_listed: boolean;
  google_safe_browsing?: GoogleSafeBrowsingResult;
  otx?: OTXResult;
  feeds_checked: string[];
  feeds_skipped: string[];
}

export interface BraveOSINTResult {
  title: string;
  url: string;
  description: string;
  source: string;
  matched_keywords: string[];
  score: number;
}

export interface BraveOSINTEvidence {
  meta: CollectorMeta;
  checked: boolean;
  queries: string[];
  top_hits: BraveOSINTResult[];
  observed_results: BraveOSINTResult[];
  all_results: BraveOSINTResult[];
  source_counts: Record<string, number>;
  score: number;
  risk_level: string;
  summary: string;
  notes: string[];
  error?: string;
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
  url_lexical_ml?: URLLexicalMLEvidence;
  ml_url_score?: URLMLScoreEvidence;
  url_behavior?: URLBehaviorEvidence;
  content_ml?: ContentMLEvidence;
  attachment_analysis?: AttachmentAnalysisEvidence;
  hybrid_analysis?: HybridAnalysisEvidence;
  opencti?: OpenCTIEvidence;
  final_risk?: FinalRiskEvidence;
  redirect_destination_intel?: RedirectDestinationIntelEvidence;
  threat_feeds?: ThreatFeedEvidence;
  brave_osint?: BraveOSINTEvidence;
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
  ai_model?: string;
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
  duration_ms?: number;
  total_elapsed_ms?: number;
  report_recomputed?: boolean;
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

// --- Settings / API Health ---

export type APIHealthStatus =
  | "healthy"
  | "low_quota"
  | "rate_limited"
  | "unavailable"
  | "not_configured"
  | "configured";

export interface APIProviderHealth {
  provider: string;
  display_name: string;
  configured: boolean;
  status: APIHealthStatus;
  remaining?: number | null;
  limit?: number | null;
  unit?: string | null;
  reset_at?: string | null;
  low_quota_threshold?: number | null;
  last_checked_at?: string | null;
  source?: string | null;
  requests_today?: number;
  requests_this_month?: number;
  limit_period?: string | null;
  error?: string | null;
  // "shared_team" means remaining/limit describe a pool this key shares with
  // others, so the same figure appearing on several cards is one balance —
  // not several that coincide.
  quota_scope?: "shared_team" | "per_key" | null;
  quota_shared_with?: number;
  per_key_month_limit?: number | null;
  details?: APIProviderHealth[];
}

export interface APIHealthResponse {
  providers: APIProviderHealth[];
  generated_at: string;
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

// --- Email Investigation ---

export interface EmailInvestigationOutcome {
  indicator_type: string;
  value: string;
  observable_type: ObservableType;
  investigation_id: string;
  state: string;
  classification?: Classification;
  confidence?: Confidence;
  risk_score?: number;
}

export interface EmailInvestigationResolution {
  email_subject?: string;
  overall_verdict?: "clean" | "suspicious" | "malicious" | "inconclusive";
  confidence?: "low" | "medium" | "high";
  primary_signals?: string[];
  formatted_resolution: string;
  template_resolution?: string;
  url_assessments?: Array<{
    url?: string;
    where_it_points?: string;
    legitimacy?: "legitimate" | "suspicious" | "malicious" | "unknown" | string;
    reasoning?: string;
  }>;
  conclusion?: {
    classification: Classification | "inconclusive";
    confidence: Confidence;
    justification: string;
  };
  sections?: Record<string, any>;
  sender_domain_analysis?: {
    classification?: string;
    primary_reasoning?: string;
    findings?: Array<{
      title?: string;
      severity?: string;
      description?: string;
    }>;
  };
}

export interface EmailInvestigationResponse {
  run_id?: string;
  history_id?: string;
  status?: "queued" | "processing" | "completed" | "failed" | "cancelled";
  error?: string | null;
  created_at?: string;
  completed_at?: string;
  filename: string;
  email_subject?: string;
  sender_email?: string;
  sender_domain?: string;
  sender_ip?: string;
  authentication?: Record<string, any>;
  urls_count: number;
  urls: string[];
  url_domains: string[];
  attachments_count: number;
  attachments: Array<Record<string, any>>;
  indicator_checks: {
    sender_domain?: Record<string, any>;
    sender_ip: Record<string, any>;
    urls: Array<Record<string, any>>;
    attachments: Record<string, any>;
    content_ml?: Record<string, any>;
    attachment_analysis?: Record<string, any>;
    hybrid_analysis?: Record<string, any>;
    email_anyrun?: Record<string, any>;
    email_security?: Record<string, any>;
    final_risk?: Record<string, any>;
  };
  resolution_source: string;
  resolution: EmailInvestigationResolution;
}

export interface EmailInvestigationHistoryItem {
  id: string;
  created_at?: string;
  completed_at?: string;
  status?: "queued" | "processing" | "completed" | "failed" | "cancelled";
  filename: string;
  email_subject?: string;
  sender_email?: string;
  sender_domain?: string;
  sender_ip?: string;
  resolution_source: string;
  classification?: string;
  error?: string | null;
  urls_count: number;
  attachments_count: number;
}

export interface EmailInvestigationSubmitResponse {
  run_id: string;
  history_id?: string;
  status: "queued" | "processing" | "completed" | "failed" | "cancelled";
  message: string;
}

export type AssistantMode = "alert_analysis" | "incident_correlation";
export type AssistantSessionStatus = "draft" | "processing" | "completed" | "failed";

export interface AssistantEntry {
  id: string;
  session_id: string;
  entry_index: number;
  entry_label?: string;
  raw_text: string;
  sanitized_text: string;
  token_map_json: Record<string, string>;
  created_at: string;
}

export interface AssistantSessionListItem {
  id: string;
  title: string;
  mode: AssistantMode;
  status: AssistantSessionStatus;
  source_type: string;
  linked_investigation_id?: string | null;
  sanitization_summary_json: Record<string, any>;
  result_json: Record<string, any>;
  report_markdown?: string | null;
  error?: string | null;
  created_at: string;
  updated_at?: string | null;
  completed_at?: string | null;
}

export interface AssistantSessionDetail extends AssistantSessionListItem {
  entries: AssistantEntry[];
}

export interface AssistantDailyMetrics {
  date: string;
  timezone_offset_minutes: number;
  total: number;
  previous_total: number;
  change_percent: number | null;
  peak_hour: string | null;
  hourly: Array<{
    hour: string;
    count: number;
  }>;
}

// ─── Alert body investigations ───────────────────────────────────────────────

export type AlertIndicatorType = "url" | "domain" | "ip" | "hash" | "email" | "cve";

export type AlertRunStatus = "queued" | "processing" | "completed" | "failed" | "cancelled";

/** An earlier investigation of the exact same indicator value. */
export interface AlertPriorInvestigation {
  investigation_id: string;
  value?: string;
  observable_type?: string;
  state?: string;
  classification?: string | null;
  confidence?: string | null;
  risk_score?: number | null;
  recommended_action?: string | null;
  created_at?: string | null;
  concluded_at?: string | null;
  age_days?: number | null;
  /** How many investigations exist for this value, newest described above. */
  total_investigations?: number;
  /** Recent + concluded → the alert run reuses it instead of re-collecting. */
  reusable?: boolean;
}

/** A full investigation started for an indicator extracted from an alert body. */
export interface AlertSpawnedInvestigation {
  investigation_id: string;
  /** Ready-to-link path to the investigation detail page. */
  url: string;
  state: string;
  value?: string | null;
  classification?: string | null;
  confidence?: string | null;
  risk_score?: number | null;
  recommended_action?: string | null;
  created_at?: string | null;
  concluded_at?: string | null;
  executive_summary?: string | null;
  spawned_by_alert?: boolean;
}

export interface AlertExtractedIndicator {
  type: AlertIndicatorType;
  value: string;
  matched_text?: string;
  occurrences: number;
  investigable: boolean;
  skip_reason?: string | null;
  defanged_in_source?: boolean;
  host?: string;
  /** FQDNs that collapsed into this registered domain (domain indicators only). */
  hostnames?: string[];
  hash_type?: string;
  /** Other digests of the same file (md5/sha1/imphash) — not separate lookups. */
  other_digests?: Record<string, string>;
  ip_version?: number;
  derived_from?: string;
  prior_investigation?: AlertPriorInvestigation;
}

/** The same indicators as a flat map of values, for consumers that want only those. */
export interface AlertIndicatorsByType {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: { md5: string[]; sha1: string[]; sha256: string[] };
  emails: string[];
  cves: string[];
}

export interface AlertExtractionResult {
  schema_version?: string;
  indicators: AlertExtractedIndicator[];
  by_type?: AlertIndicatorsByType;
  counts: Partial<Record<AlertIndicatorType, number>>;
  total: number;
  investigable_total: number;
  /** Indicators answered by the exclusion list instead of by collectors. */
  excluded_total?: number;
  truncated: boolean;
  dropped: number;
  characters: number;
  max_indicators?: number;
}

/** One detection rule's measured quality — see /api/detections/quality. */
export interface DetectionQualityRule {
  rule_id: string;
  rule_name: string | null;
  alerts: number;
  verdicts: { malicious: number; suspicious: number; benign: number; inconclusive: number };
  highest_risk_score: number;
  fully_excluded_alerts: number;
  attack_claims: number;
  attack_confirmed: number;
  attack_uncorroborated: number;
  attack_additional: number;
  /** null below the scoring threshold — a rate from two alerts is not a rate. */
  noise_rate: number | null;
  actionable_rate: number | null;
  attack_confirm_rate: number | null;
  analyst_feedback: {
    true_positive: number;
    false_positive: number;
    unclear: number;
    false_positive_rate: number | null;
  };
  scored: boolean;
  assessment: string;
  last_seen: string | null;
}

export interface DetectionQualityResponse {
  window_days: number;
  rules_seen: number;
  alerts_total: number;
  min_alerts_to_score: number;
  rules: DetectionQualityRule[];
  /** Alerts with no rule id — so the totals visibly do not cover everything. */
  unattributed_alerts: number;
}

export interface AttackCoverageTechnique {
  id: string;
  name: string | null;
  /** Primary tactic — the first of `tactics`, for wherever one label is needed. */
  tactic: string;
  /** Every tactic ATT&CK lists the technique under; `["Unmapped"]` if it knows none. */
  tactics: string[];
  url: string | null;
  /** False when this platform could never corroborate the technique, only name it. */
  evidenceable: boolean;
  /** ATT&CK has retired the technique; a rule still claims it. */
  deprecated: boolean;
  claimed: number;
  confirmed: number;
  uncorroborated: number;
  observed: number;
  ai_suggested: number;
  confirm_rate: number | null;
}

export interface AttackCoverageResponse {
  window_days: number;
  runs_assessed: number;
  techniques_seen: number;
  techniques: AttackCoverageTechnique[];
  tactics: Array<{
    tactic: string;
    techniques: number;
    claimed: number;
    confirmed: number;
    observed: number;
    uncorroborated: number;
    ai_suggested: number;
    /** Distinct techniques under this tactic with at least one confirmation. */
    confirmed_techniques: number;
    /** Distinct techniques the AI proposed that no rule claimed. */
    ai_suggested_techniques: number;
  }>;
  /** Evidence independently bore out what a rule claimed. */
  confirmed_techniques: AttackCoverageTechnique[];
  /** Proposed by the AI, claimed by no rule. */
  ai_suggested_techniques: AttackCoverageTechnique[];
  /** Claimed by a rule, never once corroborated by evidence. */
  unvalidated_mappings: AttackCoverageTechnique[];
  /** Seen in evidence, never claimed by any detection. */
  undetected_behaviour: AttackCoverageTechnique[];
  blind_spots: Array<{ tactic: string; techniques_we_could_evidence: number }>;
  /**
   * What a rule claimed against what the evidence found on the same alert.
   * Only runs carrying both a claim and evidence — a run with a claim and
   * nothing found is not a mismatch, it is an alert that carried no evidence.
   */
  mapping_mismatches: Array<{
    rule_id: string | null;
    rule_name: string;
    runs: number;
    claimed: Array<{ id: string; name: string | null; runs: number }>;
    evidenced_instead: Array<{
      id: string;
      name: string | null;
      runs: number;
      /** Only ever proposed by AI here — a lead, not a deterministic signal. */
      ai_only: boolean;
    }>;
  }>;
}

/** One alert run that touched a tactic, with the techniques of that tactic it carried. */
export interface TacticAlert {
  run_id: string;
  title: string;
  created_at: string | null;
  overall_verdict: string | null;
  highest_risk_score: number | null;
  detection_rule_id: string | null;
  detection_rule_name: string | null;
  techniques: Array<{
    id: string;
    name: string | null;
    url: string | null;
    /** confirmed | not_corroborated | refuted | observed | ai_suggested */
    status: string;
    /** False when the platform could never corroborate it — only name it. */
    evidenceable: boolean;
    explanation: string | null;
  }>;
  confirmed: number;
}

export interface TacticAlertsResponse {
  tactic: string;
  window_days: number;
  total: number;
  returned: number;
  alerts: TacticAlert[];
}

export interface AnalystFeedback {
  id: string;
  subject_type: "investigation" | "alert_run";
  subject_id: string;
  verdict: "true_positive" | "false_positive" | "unclear";
  platform_classification: string | null;
  platform_risk_score: number | null;
  detection_rule_id: string | null;
  note: string | null;
  analyst: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface FeedbackAccuracy {
  window_days: number;
  feedback_total: number;
  judged: number;
  unclear: number;
  agreed: number;
  disagreed: number;
  agreement_rate: number | null;
  missed_by_platform: AnalystFeedback[];
  over_flagged_by_platform: AnalystFeedback[];
  note: string;
}

export interface CostDashboard {
  window_days: number;
  providers: Array<{
    key: string;
    provider: string;
    requests_today: number;
    requests_this_month: number;
    daily_limit: number | null;
    monthly_limit: number | null;
    percent_used: number | null;
    remaining_today: number | null;
  }>;
  providers_idle: string[];
  ai_requests_today: number;
  at_risk: CostDashboard["providers"];
  savings: {
    alert_runs: number;
    indicator_lookups_performed: number;
    indicator_lookups_avoided: number;
    avoided_by_exclusion_list: number;
    avoided_by_prior_investigation_reuse: number;
    duplicate_alert_deliveries_absorbed: number;
    ai_analyses_skipped: number;
    exclusion_hits_all_time: number;
    avoidance_rate: number | null;
  };
  note: string;
}

/** An indicator the platform treats as benign without collecting — see /exclusions. */
export interface Exclusion {
  id: string;
  indicator_type: "domain" | "ip" | "url" | "hash";
  value: string;
  normalized_value: string;
  reason: string;
  added_by: string | null;
  /** Domain entries cover subdomains unless this is off. */
  match_subdomains: boolean;
  active: boolean;
  /** True once expires_at has passed — the row stops matching but is kept. */
  expired: boolean;
  expires_at: string | null;
  /** How many indicators this entry has kept out of the collectors. */
  hit_count: number;
  last_hit_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface AlertIndicatorVerdict {
  classification: "malicious" | "suspicious" | "benign" | "inconclusive" | "not_investigated";
  risk_score: number;
  confidence: number;
  reasons: string[];
  sources: string[];
}

/** One thing a source actually found for an indicator. */
export interface AlertFinding {
  source: string;
  collector: string;
  type:
    | "reputation"
    | "file_profile"
    | "sandbox_behaviour"
    | "infrastructure"
    | "registration"
    | "web"
    | "threat_intel"
    | "blocklist"
    | "certificate";
  severity: "high" | "medium" | "low" | "info";
  summary: string;
  data: Record<string, any>;
}

/** One JSON report per analysed indicator — the reusable integration payload. */
export interface AlertIndicatorReport {
  schema_version: string;
  report_type?: "indicator";
  indicator: {
    value: string;
    type: AlertIndicatorType;
    observable_type?: string | null;
    occurrences: number;
    defanged_in_source?: boolean;
    matched_text?: string;
    host?: string;
    hostnames?: string[];
    hash_type?: string;
    ip_version?: number;
    derived_from?: string;
    prior_investigation?: AlertPriorInvestigation;
  };
  /**
   * "reused"        — answered from an earlier investigation, no collector was run
   * "investigating" — a full investigation was started and is still running; the
   *                   verdict fills in the next time the run is read or exported
   */
  status: "completed" | "failed" | "skipped" | "reused" | "investigating";
  skip_reason?: string;
  prior_investigation?: AlertPriorInvestigation;
  /** The full investigation this indicator was answered by (domains and URLs). */
  investigation?: AlertSpawnedInvestigation;
  verdict: AlertIndicatorVerdict;
  findings: AlertFinding[];
  sources_checked: string[];
  collector_runs: Array<{
    collector: string;
    status: string;
    duration_ms?: number;
    error?: string | null;
  }>;
  /** Only present when the run was created with include_raw_evidence. */
  evidence?: Record<string, any>;
  ip_lookup?: Record<string, any> | null;
  errors: string[];
  started_at: string;
  completed_at: string;
  duration_ms: number;
}

/** The AI assistant's reading of the whole alert body — first entry in `reports`. */
export interface AlertAIReport {
  schema_version?: string;
  report_type: "ai_assistant";
  status: "completed" | "failed" | "skipped";
  error?: string | null;
  assistant_session_id?: string;
  assistant_session_url?: string;
  mode?: string;
  title?: string;
  generated_at?: string | null;
  report_markdown?: string;
  incident_graph?: Record<string, any>;
  sanitization_summary?: Record<string, number>;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
}

/** What the collectors actually found, one line per indicator. */
export interface AlertIndicatorSummaryEntry {
  value: string;
  type: string;
  classification?: string;
  risk_score?: number | null;
  status?: string;
  line: string;
  vt_malicious?: number;
  vt_total?: number;
  vt_detections?: string[] | null;
  vt_flagged_by?: string[] | null;
  file_name?: string | null;
  other_names?: string[] | null;
  file_type?: string | null;
  size_bytes?: number | null;
  signed?: boolean;
  signature?: Record<string, any> | null;
  threat_label?: string | null;
  imphash?: string | null;
  times_submitted?: number | null;
  sandbox?: string | null;
  feeds?: string[] | null;
  investigation_id?: string;
}

export interface AlertIndicatorSummary {
  headline: string;
  highlights: string[];
  indicators: AlertIndicatorSummaryEntry[];
}

/** A Sysmon/EDR event parsed out of the alert body, scored on its behaviour. */
export interface AlertEndpointEventReport {
  schema_version?: string;
  report_type: "endpoint_event";
  event: {
    type?: string;
    header?: string;
    utc_time?: string;
    host_user?: string;
    image?: string;
    command_line?: string;
    parent_image?: string;
    parent_command_line?: string;
    current_directory?: string;
    integrity_level?: string;
    process_id?: string;
    parent_process_id?: string;
    process_guid?: string;
    logon_id?: string;
    hashes?: Record<string, string>;
    fields?: Record<string, string>;
  };
  verdict: AlertIndicatorVerdict;
  findings: AlertFinding[];
  sources_checked?: string[];
  errors?: string[];
  started_at?: string;
  completed_at?: string;
}

export type AlertReport = AlertAIReport | AlertIndicatorReport | AlertEndpointEventReport;

/* ── The `format=report` export: what a reporting platform receives ────────── */

export interface SocReportKeyValue {
  label: string;
  value: string | number | boolean | null;
  mono?: boolean;
}

export interface SocReportTable {
  headers: string[];
  rows: (string | number | null)[][];
}

export interface SocReportSection {
  title: string;
  rows?: SocReportKeyValue[];
  table?: SocReportTable | null;
}

export interface SocReportFinding {
  id?: string;
  title: string;
  severity: string;
  description?: string;
  evidence_refs?: string[];
  evidence_arguments?: Array<{
    ref: string;
    argument: string;
    supports_classification?: boolean;
    contradicts_classification?: boolean;
  }>;
  ttp?: string | null;
  ttp_name?: string | null;
}

/** The SOC report as data — the same dict our PDF template renders. */
export interface SocReport {
  title: string;
  subtitle?: string;
  generated_at?: string;
  classification: string;
  classification_color?: string;
  verdict: {
    classification: string;
    confidence?: string;
    risk_score?: number | null;
    recommended_action?: string;
    risk_level?: string;
    risk_rationale?: string;
  };
  case_metadata: SocReportKeyValue[];
  summary?: string;
  assessment_points?: string[];
  key_evidence?: Array<{ source: string; ref: string; value: string; relevance?: string }>;
  findings?: SocReportFinding[];
  iocs?: Array<{ type: string; value: string; context?: string; confidence?: string }>;
  recommendations?: string[];
  derived_intelligence?: {
    confidence_engine?: {
      verdict?: string;
      score?: number;
      confidence?: string;
      confidence_percent?: number;
      components?: unknown[];
      reasons?: string[];
    };
    ioc_quality?: {
      summary?: Record<string, number>;
      items?: Array<{
        type: string;
        value: string;
        quality_score?: number;
        labels?: string[];
        recommended_action?: string;
      }>;
      total_items?: number;
    };
  };
  signals?: Array<{ severity: string; description: string }>;
  evidence_sections?: SocReportSection[];
  collector_status?: SocReportKeyValue[];
  contradicting_evidence?: unknown[];
  data_gaps?: unknown[];
  technical_narrative?: string;
  methodology?: string[];
}

/** Element 0 of the report export. */
export interface AlertExecutiveSummaryDocument {
  report_type: "executive_summary";
  schema_version?: string;
  run_id?: string;
  title?: string;
  status?: string;
  overall_verdict?: string;
  highest_risk_score?: number;
  started_at?: string | null;
  completed_at?: string | null;
  summary?: AlertInvestigationSummary;
  extraction?: Record<string, any>;
  prior_investigations?: Record<string, any>;
  spawned_investigations?: Record<string, any>;
  investigations?: Array<{
    investigation_id: string;
    url: string;
    indicator?: string;
    observable_type?: string;
    state?: string;
    classification?: string | null;
    risk_score?: number | null;
    reused?: boolean;
  }>;
  alert_body?: string;
  context?: string | null;
  error?: string | null;
  indicator_summary?: AlertIndicatorSummary;
  ai_analysis?: {
    status?: string;
    report_markdown?: string;
    incident_graph?: Record<string, any>;
    assistant_session_id?: string;
    error?: string | null;
  };
}

/** Every other element: one indicator, with its SOC report when it has one. */
export interface AlertReportIndicatorDocument {
  report_type: "indicator";
  schema_version?: string;
  indicator: AlertIndicatorReport["indicator"];
  status: AlertIndicatorReport["status"];
  skip_reason?: string;
  verdict: AlertIndicatorVerdict;
  investigation?: AlertSpawnedInvestigation;
  prior_investigation?: AlertPriorInvestigation & { url?: string };
  soc_report?: SocReport;
  findings?: AlertFinding[];
  sources_checked?: string[];
  errors?: string[];
  started_at?: string;
  completed_at?: string;
}

export type AlertReportDocument =
  | AlertExecutiveSummaryDocument
  | AlertReportIndicatorDocument
  | AlertEndpointEventReport;

export interface AlertInvestigationSummary {
  indicators_total: number;
  indicators_investigated: number;
  indicators_skipped: number;
  indicators_failed: number;
  /** Answered from an earlier investigation instead of fresh collector runs. */
  indicators_reused?: number;
  /** Full investigations still running when the alert run finished. */
  indicators_investigating?: number;
  /** Endpoint events parsed from the alert body, and how many were flagged. */
  events_total?: number;
  events_flagged?: number;
  /** Investigations this alert run started, in report order. */
  investigation_ids?: string[];
  classification_counts: Record<string, number>;
  highest_risk_score: number;
  overall_verdict: string;
  malicious_indicators: string[];
  suspicious_indicators: string[];
  ai_analysis?: string;
}

export interface AlertInvestigationRun {
  run_id: string;
  id: string;
  title: string;
  status: AlertRunStatus;
  indicator_count: number;
  overall_verdict?: string | null;
  highest_risk_score?: number | null;
  created_at: string | null;
  completed_at: string | null;
  error?: string | null;
  /** Investigations this run started — deleting the run deletes them too. */
  spawned_investigation_count?: number;
  alert_body?: string;
  context?: string | null;
  schema_version?: string;
  source?: string;
  extraction?: AlertExtractionResult;
  summary?: AlertInvestigationSummary;
  ai_report?: AlertAIReport | null;
  /** Endpoint events found in the alert body, scored on behaviour. */
  event_reports?: AlertEndpointEventReport[];
  /** Factual roll-up of what each source found — see IndicatorSummaryCard. */
  indicator_summary?: AlertIndicatorSummary;
  indicator_reports?: AlertIndicatorReport[];
  /** Exported contract: [AI report, ...indicator reports]. */
  reports?: AlertReport[];
  duration_ms?: number;
}
