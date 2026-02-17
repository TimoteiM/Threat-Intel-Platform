/**
 * TypeScript types — mirrors backend Pydantic schemas.
 *
 * Keep in sync with: backend/app/models/schemas.py
 * Keep in sync with: backend/app/models/enums.py
 */

// ─── Enums ───

export type InvestigationState =
  | "created"
  | "gathering"
  | "evaluating"
  | "insufficient_data"
  | "concluded"
  | "failed";

export type Classification = "benign" | "suspicious" | "malicious" | "inconclusive";
export type Confidence = "low" | "medium" | "high";
export type SOCAction = "monitor" | "investigate" | "block" | "hunt";
export type CollectorStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type IOCType = "ip" | "domain" | "url" | "hash" | "email";

// ─── Collector Evidence ───

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

// ─── Intel Evidence ───

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

// ─── VirusTotal Evidence ───

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
}

// ─── Domain Similarity ───

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

// ─── Visual Comparison ───

export interface VisualComparisonEvidence {
  investigated_domain: string;
  client_domain: string;
  investigated_screenshot_artifact_id?: string;
  client_screenshot_artifact_id?: string;
  reference_image_used: boolean;
  phash_similarity?: number;
  histogram_similarity?: number;
  overall_visual_similarity?: number;
  is_visual_clone: boolean;
  is_partial_clone: boolean;
  summary: string;
  investigated_capture_error?: string;
  client_capture_error?: string;
}

// ─── Signals & Gaps ───

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

// ─── Master Evidence ───

export interface CollectedEvidence {
  domain: string;
  investigation_id: string;
  timestamps: Record<string, string>;
  dns: DNSEvidence;
  whois: WHOISEvidence;
  http: HTTPEvidence;
  tls: TLSEvidence;
  hosting: ASNEvidence;
  intel: IntelEvidence;
  vt: VTEvidence;
  domain_similarity?: DomainSimilarityEvidence;
  visual_comparison?: VisualComparisonEvidence;
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

// ─── Analyst Report ───

export interface AnalystFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  evidence_refs: string[];
  ttp?: string;
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

// ─── API Responses ───

export interface InvestigationListItem {
  id: string;
  domain: string;
  state: InvestigationState;
  classification?: Classification;
  risk_score?: number;
  created_at: string;
}

export interface InvestigationDetail {
  id: string;
  domain: string;
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
