/**
 * API client — wraps fetch with error handling.
 *
 * All requests go through Next.js rewrites (see next.config.js)
 * so /api/* → http://localhost:8000/api/*
 */

import type {
  AlertExtractedIndicator,
  AlertExtractionResult,
  AlertInvestigationRun,
  AlertReportDocument,
  APIHealthResponse,
  AnalystFeedback,
  AttackCoverageResponse,
  CostDashboard,
  DetectionQualityResponse,
  Exclusion,
  FeedbackAccuracy,
  MismatchAlertsResponse,
  CorrelatedCase,
  CorrelatedCasesResponse,
  CaseDetail,
  CaseNarrativeDetail,
  EntityProfile,
  TuningResponse,
  SuppressionCandidate,
  TacticAlertsResponse,
} from "./types";

const BASE = "/api";
const DIRECT_BACKEND = (process.env.NEXT_PUBLIC_BACKEND_URL || "").replace(/\/$/, "");
const DEFAULT_BACKEND_PORT = process.env.NEXT_PUBLIC_BACKEND_PORT || "8000";

function resolveDirectBackendBase(): string {
  if (DIRECT_BACKEND) return DIRECT_BACKEND;
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol || "http:";
    const host = window.location.hostname || "127.0.0.1";
    return `${protocol}//${host}:${DEFAULT_BACKEND_PORT}`;
  }
  return `http://127.0.0.1:${DEFAULT_BACKEND_PORT}`;
}

function canUseDirectBackendFallback(): boolean {
  if (typeof window === "undefined") return false;
  const host = (window.location.hostname || "").toLowerCase();
  // Allow direct backend fallback for local/private hosts to mitigate
  // intermittent proxy/rewrite failures for large multipart uploads.
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const octets = host.split(".").map((x) => Number(x));
    const [a, b] = octets;
    if (
      a === 10 ||
      a === 127 ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31)
    ) {
      return true;
    }
  }
  return false;
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    // The session cookie authenticates every call. Same-origin would cover the
    // proxied path on its own, but the direct-to-backend upload fallback below
    // is cross-origin and would otherwise send no credential at all.
    credentials: "include",
    ...options,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

async function requestWithDirectFallback<T>(path: string, options?: RequestInit): Promise<T> {
  const proxiedUrl = `${BASE}${path}`;
  const directUrl = `${resolveDirectBackendBase()}${BASE}${path}`;
  const endpoints = canUseDirectBackendFallback() ? [directUrl, proxiedUrl] : [proxiedUrl];

  let lastError: unknown = null;
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint, {
        headers: { "Content-Type": "application/json", ...options?.headers },
        credentials: "include",
        ...options,
      });

      if (!res.ok) {
        const body = await res.text();
        throw new ApiError(res.status, body || res.statusText);
      }

      if (res.status === 204) return undefined as T;
      return res.json();
    } catch (error) {
      lastError = error;
      // A backend HTTP response means the request was delivered. Retrying it
      // through another endpoint can duplicate expensive/non-idempotent work.
      if (error instanceof ApiError) throw error;
      if (!canUseDirectBackendFallback()) break;
    }
  }

  throw lastError instanceof Error ? lastError : new Error("Request failed");
}

async function requestLongRunning<T>(path: string, options?: RequestInit): Promise<T> {
  // Exactly one submission: long-running AI requests must never be replayed
  // automatically because the first request may already be billable.
  const endpoint = canUseDirectBackendFallback()
    ? `${resolveDirectBackendBase()}${BASE}${path}`
    : `${BASE}${path}`;
  const res = await fetch(endpoint, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json();
}

// ─── Investigation endpoints ───

export function createInvestigation(data: {
  domain: string;
  observable_type?: string;
  context?: string;
  client_domain?: string;
  investigated_url?: string;
  client_url?: string;
  network_profile?: { use_residential_proxy?: boolean; proxy_country?: string };
  requested_collectors?: string[];
  ai_model?: string;
}) {
  return request<{
    investigation_id: string;
    domain: string;
    observable_type: string;
    state: string;
    message: string;
  }>("/investigations", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getProxyCountries() {
  return request<{ items: Array<{ country: string; label: string; configured: string }> }>(
    "/investigations/proxy-countries",
  );
}

export async function uploadFileInvestigation(
  file: File,
  context?: string,
  options?: { use_residential_proxy?: boolean; proxy_country?: string },
): Promise<{ investigation_id: string; domain: string; observable_type: string; state: string }> {
  const formData = new FormData();
  formData.append("file", file);
  if (context) formData.append("context", context);
  if (options?.use_residential_proxy !== undefined) {
    formData.append("use_residential_proxy", String(options.use_residential_proxy));
  }
  if (options?.proxy_country) {
    formData.append("proxy_country", options.proxy_country);
  }

  const res = await fetch(`${BASE}/investigations/upload-file`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || res.statusText);
  }

  return res.json();
}

export async function uploadEmailInvestigation(
  file: File,
  options?: {
    context?: string;
    max_urls?: number;
    max_attachment_hashes?: number;
    include_url_screenshots?: boolean;
    run_anyrun?: boolean;
    run_ai?: boolean;
    ml_phishing_score?: number;
  },
): Promise<any> {
  const formData = new FormData();
  formData.append("file", file);
  if (options?.context) formData.append("context", options.context);
  if (options?.max_urls !== undefined) formData.append("max_urls", String(options.max_urls));
  if (options?.max_attachment_hashes !== undefined) {
    formData.append("max_attachment_hashes", String(options.max_attachment_hashes));
  }
  if (options?.include_url_screenshots !== undefined) {
    formData.append("include_url_screenshots", String(options.include_url_screenshots));
  }
  if (options?.run_anyrun !== undefined) formData.append("run_anyrun", String(options.run_anyrun));
  if (options?.run_ai !== undefined) formData.append("run_ai", String(options.run_ai));
  if (options?.ml_phishing_score !== undefined) {
    formData.append("ml_phishing_score", String(options.ml_phishing_score));
  }

  const directBackendBase = resolveDirectBackendBase();
  const proxiedEndpoint = `${BASE}/email-investigations/upload`;
  const directEndpoint = `${directBackendBase}/api/email-investigations/upload`;

  function shouldPreferDirectBackend(): boolean {
    // Large multipart uploads can intermittently reset through Next dev rewrites on Windows.
    // Prefer direct backend in local development; keep proxy-first behavior elsewhere.
    if (typeof window === "undefined") return false;
    const host = (window.location.hostname || "").toLowerCase();
    const isLocalHost = host === "localhost" || host === "127.0.0.1";
    const direct = directEndpoint.toLowerCase();
    const isLocalBackend = direct.includes("127.0.0.1") || direct.includes("localhost");
    return isLocalHost && isLocalBackend;
  }

  async function postMultipart(endpoint: string): Promise<Response> {
    return fetch(endpoint, { method: "POST", body: formData });
  }

  const canUseDirect = canUseDirectBackendFallback();
  const endpoints = canUseDirect
    ? (
      shouldPreferDirectBackend()
        ? [directEndpoint, proxiedEndpoint]
        : [proxiedEndpoint, directEndpoint]
    )
    : [proxiedEndpoint];

  let res: Response | null = null;
  let lastNetworkError: unknown = null;
  for (const endpoint of endpoints) {
    try {
      res = await postMultipart(endpoint);
      // If endpoint exists (anything except 404/405/5xx), stop retrying.
      if (res.status < 500 && res.status !== 404 && res.status !== 405) break;
    } catch (err) {
      lastNetworkError = err;
    }
  }

  if (!res) {
    throw new Error(
      lastNetworkError instanceof Error
        ? `Upload request failed: ${lastNetworkError.message}`
        : "Upload request failed",
    );
  }

  if (canUseDirect && !res.ok && (res.status >= 500 || res.status === 404 || res.status === 405)) {
    // Final compatibility retry for mixed environments.
    const fallbackOrder = [directEndpoint, proxiedEndpoint];
    for (const endpoint of fallbackOrder) {
      if (endpoint === res.url) continue;
      try {
        const retryRes = await postMultipart(endpoint);
        if (retryRes.ok) return retryRes.json();
      } catch {
        // Try next fallback endpoint.
      }
    }
  }

  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json();
}

export async function listEmailInvestigationHistory(
  params?: { limit?: number; offset?: number; search?: string; classification?: string },
): Promise<{ items: any[]; total: number; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.search?.trim()) qs.set("search", params.search.trim());
  if (params?.classification && params.classification !== "all") qs.set("classification", params.classification);
  const query = qs.toString();
  return request<{ items: any[]; total: number; limit: number; offset: number }>(
    `/email-investigations/history${query ? `?${query}` : ""}`,
  );
}

export async function getEmailInvestigationHistoryItem(historyId: string): Promise<any> {
  return request<any>(`/email-investigations/history/${historyId}`);
}

export async function getEmailInvestigationRun(runId: string): Promise<any> {
  return request<any>(`/email-investigations/${runId}`);
}

export async function cancelEmailInvestigationRun(runId: string): Promise<any> {
  return request<any>(`/email-investigations/${runId}/cancel`, {
    method: "POST",
  });
}

// ─── Alert body investigations ───

export function extractAlertIndicators(data: { alert_body: string; max_indicators?: number }) {
  return request<AlertExtractionResult>("/alert-investigations/extract", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function createAlertInvestigation(data: {
  alert_body: string;
  title?: string;
  context?: string;
  requested_collectors?: string[];
  max_indicators?: number;
  run_ip_lookup?: boolean;
  run_ai?: boolean;
}) {
  return request<{
    run_id: string;
    status: string;
    title: string;
    indicators: AlertExtractedIndicator[];
    indicator_count: number;
    investigable_count: number;
    message: string;
    // wait=false: the UI navigates to the run page and polls it. Senders that
    // want a finished report in one call get the API default (wait=true).
  }>("/alert-investigations?wait=false", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function listAlertInvestigations(params?: {
  limit?: number;
  offset?: number;
  search?: string;
  verdict?: string;
  /** A tenant id, or "__unassigned__". Omit for every client you may see. */
  tenant?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.search?.trim()) qs.set("search", params.search.trim());
  if (params?.verdict && params.verdict !== "all") qs.set("verdict", params.verdict);
  if (params?.tenant && params.tenant !== "all") qs.set("tenant", params.tenant);
  const query = qs.toString();
  return request<
    PaginatedResponse<AlertInvestigationRun> & {
      scope?: TenantScope;
      available_tenants?: TenantOption[];
    }
  >(`/alert-investigations${query ? `?${query}` : ""}`);
}

export interface TenantOption {
  tenant_id: string;
  name: string;
  status: string;
  run_count: number;
}

export interface TenantScope {
  all_tenants: boolean;
  tenant_ids: string[];
  include_unassigned: boolean;
}

export interface AlertLogEvent {
  key: string;
  index: string;
  id: string;
  timestamp: string | null;
  agent?: { id?: string | null; name?: string | null; ip?: string | null };
  manager?: string | null;
  rule?: {
    id?: string | null;
    level?: number | null;
    description?: string | null;
    groups?: string[] | null;
    mitre_technique?: string[] | null;
  };
  event_id?: string | null;
  users?: string[];
  process?: { image?: string | null; command_line?: string | null; parent_image?: string | null };
  network?: { src_ip?: string | null; dst_ip?: string | null };
  decoder?: string | null;
  location?: string | null;
  full_log?: string | null;
  channel?: string | null;
  domain?: string | null;
  /**
   * The event's own fields, whatever they are for this event id. A list of
   * pairs rather than an object: it is stored in JSONB, which normalises key
   * order, so the server's ordering only survives as a list.
   */
  fields?: { name: string; value: string }[];
  matched_on?: string[];
  /** The ranking judged this worth an analyst's attention. Advice, not a verdict. */
  relevant?: boolean;
  /** This event actually reached the model. Only true once someone sent it. */
  sent_to_ai?: boolean;
}

export interface AlertLogPage {
  status: string;
  reason?: string | null;
  tenant_id?: string | null;
  logs: AlertLogEvent[];
  log_count: number;
  retrieved_total: number;
  filtered_total: number;
  relevant_total: number;
  sent_to_ai_total: number;
  truncated: boolean;
  offset: number;
  limit: number;
  has_more: boolean;
  alert_time?: string | null;
  window?: { start: string; end: string; covered_until: string; complete: boolean };
  selectors?: Record<string, any>;
  sources?: Record<string, any>;
  analysis_basis?: "complete" | "partial" | "unknown";
  analysis_saw_logs?: number | null;
  new_logs_since_analysis?: number | null;
  analysis_note?: string | null;
}

export function getAlertLogs(
  runId: string,
  params?: {
    limit?: number;
    offset?: number;
    q?: string;
    device?: string;
    user?: string;
    rule_id?: string;
    min_level?: number;
    side?: "before" | "after" | "all";
    only_relevant?: boolean;
  },
) {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.q?.trim()) qs.set("q", params.q.trim());
  if (params?.device?.trim()) qs.set("device", params.device.trim());
  if (params?.user?.trim()) qs.set("user", params.user.trim());
  if (params?.rule_id?.trim()) qs.set("rule_id", params.rule_id.trim());
  if (params?.min_level !== undefined) qs.set("min_level", String(params.min_level));
  if (params?.side && params.side !== "all") qs.set("side", params.side);
  if (params?.only_relevant) qs.set("only_relevant", "true");
  const query = qs.toString();
  return request<AlertLogPage>(`/alert-investigations/${runId}/logs${query ? `?${query}` : ""}`);
}

export interface AlertLogContextPage {
  status: string;
  reason?: string | null;
  tenant_id?: string | null;
  anchor: AlertLogEvent & { is_alert: true; synthetic?: boolean };
  before: AlertLogEvent[];
  after: AlertLogEvent[];
  available_before: number;
  available_after: number;
  retrieved_total: number;
  relevant_total: number;
  sent_to_ai_total: number;
  truncated: boolean;
  alert_time?: string | null;
  window?: { start: string; end: string; covered_until: string; complete: boolean };
  analysis_basis?: "complete" | "partial" | "unknown";
  new_logs_since_analysis?: number | null;
  analysis_note?: string | null;
  ai_budget_tokens?: number;
}

/** The alert with N events either side of it, the way Discover shows context. */
export function getAlertLogContext(runId: string, before = 5, after = 5) {
  const qs = new URLSearchParams({ before: String(before), after: String(after) });
  return request<AlertLogContextPage>(`/alert-investigations/${runId}/logs/context?${qs}`);
}

export interface AnalysisStatus {
  run_id: string;
  status: string;
  finished: boolean;
  completed_at?: string | null;
  overall_verdict?: string | null;
  highest_risk_score?: number | null;
  report_markdown: string;
  log_selection: {
    events_found?: number | null;
    events_selected?: number | null;
    events_represented?: number | null;
    events_omitted?: number | null;
    analyst_pinned: string[];
    analyst_pinned_dropped: string[];
    used_tokens?: number | null;
    budget_tokens?: number | null;
  };
  reanalysis: { requested_by?: string | null; requested_at?: string | null; pinned_refs: string[] };
  previous_analyses: number;
}

/** Small enough to poll while a progress bar is ticking. */
export function getAnalysisStatus(runId: string) {
  return request<AnalysisStatus>(`/alert-investigations/${runId}/analysis-status`);
}

export function reanalyseWithLogContext(runId: string, pinnedRefs: string[] = []) {
  return request<{ run_id: string; status: string; pinned_refs: string[]; note: string }>(
    `/alert-investigations/${runId}/reanalyse`,
    { method: "POST", body: JSON.stringify({ pinned_refs: pinnedRefs }) },
  );
}

export function getAlertInvestigation(runId: string) {
  return request<AlertInvestigationRun>(`/alert-investigations/${runId}`);
}

export type AlertExportFormat = "reports" | "report" | "full" | "envelope" | "ndjson";

/**
 * URL of the server-side export — the same JSON list the integration contract
 * describes. Hand this URL to another platform and it can pull the reports with
 * one GET; `download=false` serves them inline instead of as an attachment.
 *
 * `reports` and `full` are both arrays of self-describing documents; `full`
 * leads with an executive summary and carries each investigation in full.
 */
export function alertInvestigationExportUrl(
  runId: string,
  options?: {
    format?: AlertExportFormat;
    download?: boolean;
    absolute?: boolean;
    ndjson?: boolean;
    evidence?: boolean;
  },
) {
  const qs = new URLSearchParams();
  qs.set("format", options?.format || "reports");
  if (options?.download === false) qs.set("download", "false");
  if (options?.ndjson) qs.set("ndjson", "true");
  if (options?.evidence === false) qs.set("evidence", "false");
  const path = `${BASE}/alert-investigations/${runId}/export?${qs.toString()}`;
  if (options?.absolute && typeof window !== "undefined") {
    return `${window.location.origin}${path}`;
  }
  return path;
}

/**
 * Fetch the report-ready export itself — the exact array the reporting platform
 * receives. The preview page renders this, so what an analyst reviews and what
 * an integrator consumes can never differ.
 */
export function getAlertInvestigationReportList(runId: string) {
  return request<AlertReportDocument[]>(
    `/alert-investigations/${runId}/export?format=report&download=false`,
  );
}

export interface SandboxSelectionResult {
  run_id: string;
  task_id: string | null;
  queued: Array<{ investigation_id: string; indicator: string }>;
  rejected: Array<{ investigation_id: string; reason: string }>;
  estimated_seconds: number;
}

/**
 * Detonate the chosen indicators from an alert body.
 *
 * ANY.RUN is off by default on this path — one alert can carry dozens of URLs
 * and each detonation costs a licence request — so this is how an analyst
 * spends that budget on the few worth it.
 */
export function sandboxAlertIndicators(runId: string, investigationIds: string[]) {
  return request<SandboxSelectionResult>(`/alert-investigations/${runId}/sandbox`, {
    method: "POST",
    body: JSON.stringify({ investigation_ids: investigationIds }),
  });
}

export interface AISpendModel {
  provider: string;
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  usd: number;
  priced: boolean;
  /** Shown beside the cost so the arithmetic can be checked by hand. */
  input_per_mtok: number | null;
  output_per_mtok: number | null;
}

export interface AISpend {
  available: boolean;
  reason?: string;
  window_days?: number;
  window_label?: string;
  window?: {
    calls: number;
    usd: number;
    input_tokens: number;
    output_tokens: number;
    unpriced_calls: number;
  };
  /** Budget is a monthly figure, so it is always measured against the month. */
  month_to_date_usd?: number;
  window_start?: string;
  window_end?: string;
  /** Oldest day still held. Equal to window_end means one day of history. */
  first_recorded_day?: string | null;
  by_model?: AISpendModel[];
  unpriced_models?: string[];
  budget?: { monthly_usd: number; remaining_usd: number; percent_used: number } | null;
  prices_source?: string;
  scope_note?: string;
}

/** What our own AI calls cost. Not a provider balance — see the service docstring. */
export interface AuthStatus {
  mode: "monitor" | "enforce";
  authenticated: boolean;
  username?: string | null;
  role?: string | null;
  /** Which sign-in methods this deployment can actually complete. */
  providers?: { password: boolean; microsoft: boolean };
}

/**
 * Hand the browser to Entra ID.
 *
 * A full navigation, not fetch(): the flow is a chain of cross-origin
 * redirects that ends with the API setting a cookie, and XHR can neither
 * follow it nor be allowed to.
 */
export function startMicrosoftSignIn(next: string) {
  window.location.href = `/api/auth/oidc/start?next=${encodeURIComponent(next)}`;
}

/** Public: is this caller signed in, and is signing in required yet. */
export function getAuthStatus() {
  return request<AuthStatus>("/auth/status");
}

export function login(username: string, password: string) {
  return request<{ username: string; role: string; must_change_password: boolean }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

// ── CAPEv2 sandbox ───────────────────────────────────────────────────────────
//
// The browser talks only to this backend. It never holds a CAPE URL, never
// sees the CAPE token, and never calls CAPE directly — the token exists solely
// in the backend process, and none of these responses carry it.

export type SandboxStatus =
  | "queued" | "submitting" | "submitted" | "pending" | "running"
  | "processing" | "reported" | "failed" | "timed_out" | "cancelled";

export interface SandboxAnalysis {
  id: string;
  provider: string;
  status: SandboxStatus;
  /** "file" — a sample was run. "url" — CAPE fetched a URL and ran the result. */
  target_kind?: "file" | "url";
  target_url?: string | null;
  verdict?: "malicious" | "suspicious" | "likely_benign" | "unknown" | null;
  /** Null means CAPE did not report a score — never treat it as zero. */
  malscore?: number | null;
  sha256: string;
  sample_name?: string | null;
  sample_size?: number | null;
  sample_type?: string | null;
  provider_task_id?: string | null;
  reused_existing: boolean;
  error?: string | null;
  requested_by?: string | null;
  created_at?: string | null;
  submitted_at?: string | null;
  completed_at?: string | null;
  limitations: string[];
  state_history: Array<{ status: string; from?: string | null; at: string; actor?: string; note?: string }>;
  raw_summary: Record<string, unknown>;
  created?: boolean;
  note?: string;
}

export interface SandboxReport {
  task_id?: number | null;
  malscore?: number | null;
  verdict: string;
  detections: string[];
  signatures: Array<{
    name: string; description: string; severity: number; ttps: string[];
    /** What the signature matched — the substance of the finding. */
    details?: string[];
  }>;
  sha256?: string | null;
  sha1?: string | null;
  md5?: string | null;
  file_name?: string | null;
  file_type?: string | null;
  file_size?: number | null;
  ssdeep?: string | null;
  tlsh?: string | null;
  crc32?: string | null;
  clamav?: string | null;
  yara_matches?: Array<{ name: string; description?: string; author?: string | null; source?: string }>;
  started_at?: string | null;
  ended_at?: string | null;
  duration_seconds?: number | null;
  machine?: string | null;
  route?: string | null;
  package?: string | null;
  /** False when CAPE started the sample and nothing ran. */
  executed?: boolean;
  network: {
    domains: string[];
    dns_queries: string[];
    hosts: string[];
    destinations: string[];
    http_requests: Array<{ method: string; host: string; uri: string; status?: number | null }>;
    tls_sni: string[];
  };
  behaviour: {
    mutexes: string[];
    registry_keys: string[];
    files_written: string[];
    files_read: string[];
    commands: string[];
    process_tree: Array<{ name: string; pid?: number | null; command_line?: string; children?: unknown[] }>;
    process_count: number;
  };
  dropped_files: Array<{
    name?: string | null; sha256?: string | null; size?: number | null;
    file_type?: string | null; is_cape_payload: boolean; cape_type?: string | null;
  }>;
  extracted_configs: Array<Record<string, unknown>>;
  has_screenshots: boolean;
  errors: string[];
  limitations: string[];
}

export interface SandboxAnalysisResult extends SandboxAnalysis {
  available: boolean;
  result?: SandboxReport | null;
}

/** Reachability and machine availability. Administrators only. */
export function getCapeStatus() {
  return request<{
    configured: boolean;
    enabled: boolean;
    reachable: boolean;
    version?: string | null;
    machines_total?: number | null;
    machines_available?: number | null;
    detail?: string;
    error_kind?: string;
  }>("/cape/status");
}

export function listSandboxAnalyses(params: {
  investigation_id?: string;
  alert_run_id?: string;
  sha256?: string;
  status?: string;
  limit?: number;
} = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
  });
  const suffix = query.toString();
  return request<{ items: SandboxAnalysis[] }>(`/cape/analyses${suffix ? `?${suffix}` : ""}`);
}

export function submitToSandbox(body: {
  investigation_id?: string;
  alert_run_id?: string;
  artifact_id?: string;
  sha256?: string;
  force_new?: boolean;
}) {
  return request<SandboxAnalysis>("/cape/analyses", { method: "POST", body: JSON.stringify(body) });
}

export function getSandboxAnalysis(id: string) {
  return request<SandboxAnalysis>(`/cape/analyses/${id}`);
}

export function getSandboxResult(id: string) {
  return request<SandboxAnalysisResult>(`/cape/analyses/${id}/result`);
}

export function retrySandboxAnalysis(id: string) {
  return request<SandboxAnalysis>(`/cape/analyses/${id}/retry`, { method: "POST" });
}

/** Statuses that are still moving, so the panel knows when to keep polling. */
/** Roles that may manage users and keys. Mirrors ADMIN_ROLES in the backend. */
export const ADMIN_ROLES = ["owner", "admin"];

export function hasAdminRights(role?: string | null): boolean {
  return ADMIN_ROLES.includes(String(role || ""));
}

/** How a role is written for a person. */
export function roleLabel(role?: string | null): string {
  if (role === "owner") return "Owner";
  if (role === "admin") return "Administrator";
  return "Analyst";
}

export const SANDBOX_ACTIVE_STATUSES: SandboxStatus[] = [
  "queued", "submitting", "submitted", "pending", "running", "processing",
];

/** The signed-in caller, as /auth/me reports them. */
export interface Me {
  kind: "user" | "api_key";
  id: string;
  username?: string;
  role?: string;
  auth_provider?: "local" | "microsoft";
  email?: string | null;
  display_name?: string | null;
  must_change_password?: boolean;
}

export function getMe() {
  return request<Me>("/auth/me");
}

/** An account on the platform, as the administrator list shows it. */
export interface PlatformUser {
  id: string;
  username: string;
  /** "owner" carries administrator rights and cannot be deleted by anyone. */
  role: "owner" | "admin" | "analyst";
  active: boolean;
  auth_provider: "local" | "microsoft";
  email?: string | null;
  display_name?: string | null;
  must_change_password: boolean;
  created_at?: string | null;
  last_login_at?: string | null;
}

/** A password the server generated. Returned once and never stored in clear. */
export interface IssuedPassword {
  password?: string;
  note?: string;
}

export function listUsers() {
  return request<{ items: PlatformUser[] }>("/auth/users");
}

export function createUser(body: {
  username: string;
  role: string;
  password?: string;
  email?: string;
  display_name?: string;
}) {
  return request<PlatformUser & IssuedPassword>("/auth/users", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function updateUser(id: string, body: { role?: string; active?: boolean }) {
  return request<PlatformUser>(`/auth/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function resetUserPassword(id: string) {
  return request<{ username: string } & IssuedPassword>(`/auth/users/${id}/password`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function deleteUser(id: string) {
  return request<{ deleted: string }>(`/auth/users/${id}`, { method: "DELETE" });
}

export function changeOwnPassword(current_password: string, new_password: string) {
  return request<{ ok: boolean }>("/auth/password", {
    method: "POST",
    body: JSON.stringify({ current_password, new_password }),
  });
}

export function logout() {
  return request<{ ok: boolean }>("/auth/logout", { method: "POST" });
}

export function getAISpend(days = 30) {
  return request<AISpend>(`/cost/ai-spend?days=${days}`);
}

export function setAIBudget(monthlyUsd: number) {
  return request<{ monthly_usd: number }>("/cost/ai-budget", {
    method: "PUT",
    body: JSON.stringify({ monthly_usd: monthlyUsd }),
  });
}

export function cancelAlertInvestigation(runId: string) {
  return request<{ run_id: string; status: string }>(`/alert-investigations/${runId}/cancel`, {
    method: "POST",
  });
}

/**
 * Delete an alert run and the investigations it started.
 *
 * Reused investigations, and any another run still references, are kept and
 * returned in `kept_investigations`.
 */
export function deleteAlertInvestigation(runId: string) {
  return request<{
    run_id: string;
    deleted: boolean;
    deleted_investigations: string[];
    kept_investigations: string[];
  }>(`/alert-investigations/${runId}`, { method: "DELETE" });
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export function listInvestigations(params?: {
  limit?: number;
  offset?: number;
  state?: string;
  search?: string;
  observable_type?: string;
  classification?: string;
  /** Only investigations whose ANY.RUN task recorded a screencast. */
  has_video?: boolean;
  dedupe?: boolean;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.state) qs.set("state", params.state);
  if (params?.search) qs.set("search", params.search);
  if (params?.observable_type) qs.set("observable_type", params.observable_type);
  if (params?.has_video) qs.set("has_video", "true");
  if (params?.classification) qs.set("classification", params.classification);
  if (params?.dedupe) qs.set("dedupe", "true");
  const query = qs.toString();
  return request<PaginatedResponse<any>>(`/investigations${query ? `?${query}` : ""}`);
}

export function getInvestigation(id: string) {
  return request<any>(`/investigations/${id}`);
}

export function cancelInvestigation(id: string) {
  return request<any>(`/investigations/${id}/cancel`, {
    method: "POST",
  });
}

export function deleteInvestigation(id: string) {
  return request<void>(`/investigations/${id}`, {
    method: "DELETE",
  });
}

export function rerunCollector(id: string, collector: string) {
  return request<any>(`/investigations/${id}/rerun-collector`, {
    method: "POST",
    body: JSON.stringify({ collector }),
  });
}

export function getEvidence(id: string) {
  return request<any>(`/investigations/${id}/evidence`);
}

export function getReport(id: string) {
  return request<any>(`/investigations/${id}/report`);
}

export function getInvestigationIntelligence(id: string) {
  return request<any>(`/investigations/${id}/intelligence`);
}

export function generateCaseStory(id: string) {
  // Case Story generation can exceed the Next.js rewrite proxy timeout while
  // the reasoning model is still successfully working. Use the browser-to-API
  // path on local/private deployments and retain the proxy as fallback.
  return requestLongRunning<any>(`/investigations/${id}/case-story`, { method: "POST" });
}

export function askCaseStory(id: string, question: string) {
  return requestLongRunning<any>(`/investigations/${id}/case-story/ask`, {
    method: "POST",
    body: JSON.stringify({ question }),
  });
}

export function getCaseStoryChat(id: string) {
  return request<any>(`/investigations/${id}/case-story/chat`);
}

export function clearCaseStoryChat(id: string) {
  return request<void>(`/investigations/${id}/case-story/chat`, { method: "DELETE" });
}

export function enrichInvestigation(id: string, data: any) {
  return request<any>(`/investigations/${id}/enrich`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

// ─── IOC export ───

export function getIOCExportUrl(investigationId: string, format: "csv" | "stix"): string {
  return `${BASE}/investigations/${investigationId}/iocs/export?format=${format}`;
}

// ─── Artifact helpers ───

export function getArtifactUrl(artifactId: string): string {
  return `${BASE}/artifacts/${artifactId}`;
}

export async function uploadReferenceImage(domain: string, file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE}/reference-images/${encodeURIComponent(domain)}`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }

  return res.json();
}

export async function checkReferenceImage(domain: string): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/reference-images/${encodeURIComponent(domain)}`, {
      method: "HEAD",
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ─── MITRE ATT&CK ───

export function getAttackTechniques() {
  return request<any[]>("/attack/techniques");
}

// ─── Infrastructure Pivot ───

export function getPivots(investigationId: string) {
  return request<any>(`/investigations/${investigationId}/pivots`);
}

// ─── Batch Investigation ───

export async function uploadBatch(
  file: File,
  metadata: { name?: string; context?: string; client_domain?: string },
) {
  const formData = new FormData();
  formData.append("file", file);
  if (metadata.name) formData.append("name", metadata.name);
  if (metadata.context) formData.append("context", metadata.context);
  if (metadata.client_domain) formData.append("client_domain", metadata.client_domain);

  const res = await fetch(`${BASE}/batches`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }

  return res.json();
}

export function listBatches(params?: { limit?: number; offset?: number }) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return request<any[]>(`/batches${query ? `?${query}` : ""}`);
}

export function getBatch(id: string) {
  return request<any>(`/batches/${id}`);
}

export function getBatchCampaigns(id: string) {
  return request<any>(`/batches/${id}/campaigns`);
}

// ─── Dashboard ───

export function getDashboardStats() {
  return request<any>("/dashboard/stats");
}

export function getAPIHealth() {
  return request<APIHealthResponse>("/admin/api-health");
}

// ─── Watchlist ───

export function createWatchlistEntry(data: { domain: string; notes?: string; added_by?: string; schedule_interval?: string }) {
  return request<any>("/watchlist", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function listWatchlist(params?: { limit?: number; offset?: number; status?: string; search?: string }) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.status) qs.set("status", params.status);
  if (params?.search) qs.set("search", params.search);
  const query = qs.toString();
  return request<PaginatedResponse<any>>(`/watchlist${query ? `?${query}` : ""}`);
}

export function updateWatchlistEntry(id: string, data: { status?: string; notes?: string; schedule_interval?: string | null }) {
  return request<any>(`/watchlist/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function deleteWatchlistEntry(id: string) {
  return request<any>(`/watchlist/${id}`, { method: "DELETE" });
}

export function investigateWatchlistDomain(id: string) {
  return request<any>(`/watchlist/${id}/investigate`, { method: "POST" });
}

export function getWatchlistAlerts(id: string) {
  return request<any[]>(`/watchlist/${id}/alerts`);
}

// ─── Exclusions ───

export function listExclusions(params?: {
  limit?: number;
  offset?: number;
  indicator_type?: string;
  search?: string;
  active?: boolean;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.indicator_type) qs.set("indicator_type", params.indicator_type);
  if (params?.search) qs.set("search", params.search);
  if (params?.active !== undefined) qs.set("active", String(params.active));
  const query = qs.toString();
  return request<PaginatedResponse<Exclusion>>(`/exclusions${query ? `?${query}` : ""}`);
}

export function createExclusion(data: {
  indicator_type: string;
  value: string;
  reason: string;
  added_by?: string;
  match_subdomains?: boolean;
  expires_at?: string | null;
}) {
  return request<Exclusion & { already_listed: boolean }>("/exclusions", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateExclusion(
  id: string,
  data: {
    reason?: string;
    active?: boolean;
    match_subdomains?: boolean;
    expires_at?: string | null;
    clear_expiry?: boolean;
  },
) {
  return request<Exclusion>(`/exclusions/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function deleteExclusion(id: string) {
  return request<{ deleted: boolean; id: string }>(`/exclusions/${id}`, { method: "DELETE" });
}

export function checkExclusions(indicators: Array<{ indicator_type: string; value: string }>) {
  return request<{
    results: Array<{
      indicator_type: string;
      value: string;
      excluded: boolean;
      exclusion: Record<string, unknown> | null;
    }>;
    excluded_count: number;
  }>("/exclusions/check", {
    method: "POST",
    body: JSON.stringify({ indicators }),
  });
}

// ─── Detection quality, ATT&CK coverage, analyst feedback ───

export function getDetectionQuality(params?: { days?: number; limit?: number }) {
  const qs = new URLSearchParams();
  if (params?.days) qs.set("days", String(params.days));
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString();
  return request<DetectionQualityResponse>(`/detections/quality${query ? `?${query}` : ""}`);
}

export function getAttackCoverage(params?: { days?: number }) {
  const qs = new URLSearchParams();
  if (params?.days) qs.set("days", String(params.days));
  const query = qs.toString();
  return request<AttackCoverageResponse>(`/detections/attack-coverage${query ? `?${query}` : ""}`);
}

/** The alerts behind one ATT&CK tactic row, newest first. */
export function getTacticAlerts(params: { tactic: string; days?: number; limit?: number }) {
  const qs = new URLSearchParams({ tactic: params.tactic });
  if (params.days) qs.set("days", String(params.days));
  if (params.limit) qs.set("limit", String(params.limit));
  return request<TacticAlertsResponse>(`/detections/attack-coverage/tactic-alerts?${qs.toString()}`);
}

export function getMismatchAlerts(params: {
  rule_name: string;
  technique: string;
  rule_id?: string | null;
  days?: number;
  limit?: number;
}) {
  const qs = new URLSearchParams({ rule_name: params.rule_name, technique: params.technique });
  if (params.rule_id) qs.set("rule_id", params.rule_id);
  if (params.days) qs.set("days", String(params.days));
  if (params.limit) qs.set("limit", String(params.limit));
  return request<MismatchAlertsResponse>(
    `/detections/attack-coverage/mismatch-alerts?${qs.toString()}`,
  );
}

export function getRunCase(runId: string, hours = 48) {
  return request<{ case: CorrelatedCase | null }>(
    `/alert-investigations/${runId}/case?hours=${hours}`,
  );
}

export function getCorrelatedCases(params?: {
  hours?: number;
  min_rules?: number;
  min_score?: number;
}) {
  const qs = new URLSearchParams();
  if (params?.hours) qs.set("hours", String(params.hours));
  if (params?.min_rules) qs.set("min_rules", String(params.min_rules));
  if (params?.min_score) qs.set("min_score", String(params.min_score));
  const query = qs.toString();
  return request<CorrelatedCasesResponse>(
    `/detections/correlated-cases${query ? `?${query}` : ""}`,
  );
}

export function getCase(caseKey: string, hours?: number) {
  const query = hours ? `?hours=${hours}` : "";
  return request<CaseDetail>(
    `/detections/case/${encodeURIComponent(caseKey)}${query}`,
  );
}

export function getCaseNarrative(caseKey: string) {
  return request<CaseNarrativeDetail>(
    `/detections/case/${encodeURIComponent(caseKey)}/narrative`,
  );
}

export function getEntityProfile(host: string, days?: number) {
  const query = days ? `?days=${days}` : "";
  return request<EntityProfile>(
    `/detections/entity/${encodeURIComponent(host)}${query}`,
  );
}

export function getTuningRecommendations(params?: { days?: number; min_alerts?: number }) {
  const qs = new URLSearchParams();
  if (params?.days) qs.set("days", String(params.days));
  if (params?.min_alerts) qs.set("min_alerts", String(params.min_alerts));
  const query = qs.toString();
  return request<TuningResponse>(
    `/detections/tuning-recommendations${query ? `?${query}` : ""}`,
  );
}

export function getSuppressionCandidate(runId: string) {
  return request<SuppressionCandidate>(`/alert-investigations/${runId}/suppression-candidate`);
}

export function createAlertExclusion(data: {
  match_fields: Record<string, string>;
  reason: string;
  added_by?: string;
  expires_at?: string | null;
}) {
  return request<{ id: string; match_fields: Record<string, string>; already_listed: boolean }>(
    "/exclusions/alert",
    { method: "POST", body: JSON.stringify(data) },
  );
}

export function submitAnalystFeedback(data: {
  subject_type: "investigation" | "alert_run";
  subject_id: string;
  verdict: "true_positive" | "false_positive" | "unclear";
  note?: string;
  analyst?: string;
}) {
  return request<AnalystFeedback & { replaced_previous: boolean }>("/detections/feedback", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getAnalystFeedbackFor(subjectType: string, subjectId: string) {
  return request<{ feedback: AnalystFeedback | null }>(
    `/detections/feedback/${subjectType}/${subjectId}`,
  );
}

export function getFeedbackAccuracy(params?: { days?: number }) {
  const qs = new URLSearchParams();
  if (params?.days) qs.set("days", String(params.days));
  const query = qs.toString();
  return request<FeedbackAccuracy>(`/detections/feedback/accuracy${query ? `?${query}` : ""}`);
}

// ─── Cost and quota ───

export function getCostDashboard(params?: { days?: number }) {
  const qs = new URLSearchParams();
  if (params?.days) qs.set("days", String(params.days));
  const query = qs.toString();
  return request<CostDashboard>(`/cost/dashboard${query ? `?${query}` : ""}`);
}

// ─── WHOIS History ───

export function getWhoisHistory(domain: string) {
  return request<any[]>(`/whois-history/${encodeURIComponent(domain)}`);
}

// ─── Geolocation ───

export function getGeoPoints(investigationId: string) {
  return request<any[]>(`/investigations/${investigationId}/geo-points`);
}

// ─── IP Lookup ───

export function lookupIP(ip: string) {
  return request<any>("/tools/ip-lookup", {
    method: "POST",
    body: JSON.stringify({ ip }),
  });
}

export function getIPLookupHistory(limit = 50, offset = 0) {
  return request<any[]>(`/tools/ip-lookup/history?limit=${limit}&offset=${offset}`);
}

export function getIPLookup(id: string) {
  return request<any>(`/tools/ip-lookup/history/${id}`);
}

export function deleteIPLookup(id: string) {
  return request<void>(`/tools/ip-lookup/history/${id}`, { method: "DELETE" });
}

// ─── Client Management ───

export function createClient(data: {
  name: string;
  domain: string;
  aliases?: string[];
  brand_keywords?: string[];
  contact_email?: string;
  notes?: string;
  default_collectors?: string[];
}) {
  return request<any>("/clients", { method: "POST", body: JSON.stringify(data) });
}

export function listClients(params?: {
  limit?: number;
  offset?: number;
  search?: string;
  status?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.search) qs.set("search", params.search);
  if (params?.status) qs.set("status", params.status);
  const query = qs.toString();
  return request<any>(`/clients${query ? `?${query}` : ""}`);
}

export function getClient(id: string) {
  return request<any>(`/clients/${id}`);
}

export function updateClient(
  id: string,
  data: {
    name?: string;
    domain?: string;
    aliases?: string[];
    brand_keywords?: string[];
    contact_email?: string;
    notes?: string;
    status?: string;
    default_collectors?: string[];
  },
) {
  return request<any>(`/clients/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}

export function deleteClient(id: string) {
  return request<any>(`/clients/${id}`, { method: "DELETE" });
}

export function listClientAlerts(
  clientId: string,
  params?: { limit?: number; offset?: number; resolved?: boolean; severity?: string },
) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.resolved !== undefined) qs.set("resolved", String(params.resolved));
  if (params?.severity) qs.set("severity", params.severity);
  const query = qs.toString();
  return request<any>(`/clients/${clientId}/alerts${query ? `?${query}` : ""}`);
}

export function listAllAlerts(params?: {
  limit?: number;
  offset?: number;
  severity?: string;
  resolved?: boolean;
  acknowledged?: boolean;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.resolved !== undefined) qs.set("resolved", String(params.resolved));
  if (params?.acknowledged !== undefined) qs.set("acknowledged", String(params.acknowledged));
  const query = qs.toString();
  return request<any>(`/client-alerts${query ? `?${query}` : ""}`);
}

export function acknowledgeAlert(alertId: string) {
  return request<any>(`/client-alerts/${alertId}/acknowledge`, { method: "POST" });
}

export function resolveAlert(alertId: string) {
  return request<any>(`/client-alerts/${alertId}/resolve`, { method: "POST" });
}

// ─── SSE helper ───

export function listAssistantSessions(params?: {
  limit?: number;
  offset?: number;
  search?: string;
  /**
   * Also match the pasted log text. Opt-in: titles answer in ~40ms, log
   * content is 201 MB and a common word is in 83% of it.
   */
  searchContent?: boolean;
}) {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.search?.trim()) qs.set("search", params.search.trim());
  if (params?.searchContent) qs.set("search_content", "true");
  const query = qs.toString();
  return requestWithDirectFallback<PaginatedResponse<any>>(
    `/assistant/sessions${query ? `?${query}` : ""}`,
  );
}

export function getAssistantDailyMetrics(date: string, timezoneOffsetMinutes: number) {
  const qs = new URLSearchParams({
    date,
    timezone_offset_minutes: String(timezoneOffsetMinutes),
  });
  return requestWithDirectFallback<import("@/lib/types").AssistantDailyMetrics>(
    `/assistant/metrics/daily?${qs.toString()}`,
  );
}

export function getAssistantSession(sessionId: string) {
  return requestWithDirectFallback<any>(`/assistant/sessions/${sessionId}`);
}

export function createAssistantSession(data: {
  title?: string;
  mode: "alert_analysis" | "incident_correlation";
  source_type?: string;
  linked_investigation_id?: string | null;
}) {
  return requestWithDirectFallback<any>("/assistant/sessions", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function addAssistantEntry(
  sessionId: string,
  data: { text: string; entry_label?: string; entry_index?: number },
) {
  return requestWithDirectFallback<any>(`/assistant/sessions/${sessionId}/entries`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function runAssistantSession(sessionId: string, data?: { model?: string }) {
  return requestWithDirectFallback<any>(`/assistant/sessions/${sessionId}/run`, {
    method: "POST",
    body: JSON.stringify(data || {}),
  });
}

export function createAssistantSessionFromInvestigation(investigationId: string) {
  return requestWithDirectFallback<any>(`/assistant/sessions/from-investigation/${investigationId}`, {
    method: "POST",
  });
}

export function getAssistantExportUrl(sessionId: string): string {
  return `${BASE}/assistant/sessions/${sessionId}/export`;
}
export function subscribeToProgress(
  investigationId: string,
  onEvent: (data: any) => void,
  onError?: (err: Event) => void,
): EventSource {
  const es = new EventSource(`${BASE}/investigations/${investigationId}/status`);
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      onEvent(data);
      if (data.done) es.close();
    } catch {
      // Ignore parse errors (keepalives, etc.)
    }
  };
  es.onerror = (e) => {
    onError?.(e);
    es.close();
  };
  return es;
}
