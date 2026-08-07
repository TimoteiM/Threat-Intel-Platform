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
}) {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.search?.trim()) qs.set("search", params.search.trim());
  if (params?.verdict && params.verdict !== "all") qs.set("verdict", params.verdict);
  const query = qs.toString();
  return request<PaginatedResponse<AlertInvestigationRun>>(
    `/alert-investigations${query ? `?${query}` : ""}`,
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
  dedupe?: boolean;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.state) qs.set("state", params.state);
  if (params?.search) qs.set("search", params.search);
  if (params?.observable_type) qs.set("observable_type", params.observable_type);
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

export function getSOCIndicatorGraph(params?: { search?: string; severity?: string; limit?: number }) {
  const qs = new URLSearchParams();
  if (params?.search) qs.set("search", params.search);
  if (params?.severity && params.severity !== "all") qs.set("severity", params.severity);
  if (params?.limit) qs.set("limit", String(params.limit));
  const query = qs.toString();
  return request<any>(`/soc-indicators/graph${query ? `?${query}` : ""}`);
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

export function listAssistantSessions(params?: { limit?: number; offset?: number; search?: string }) {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  if (params?.search?.trim()) qs.set("search", params.search.trim());
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
