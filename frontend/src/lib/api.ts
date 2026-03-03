/**
 * API client — wraps fetch with error handling.
 *
 * All requests go through Next.js rewrites (see next.config.js)
 * so /api/* → http://localhost:8000/api/*
 */

const BASE = "/api";
const DIRECT_BACKEND =
  (process.env.NEXT_PUBLIC_BACKEND_URL ||
    "http://127.0.0.1:8000").replace(/\/$/, "");

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const method = (options?.method || "GET").toUpperCase();
  const canRetry = method === "GET" || method === "HEAD";
  const doFetch = () =>
    fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json", ...options?.headers },
      ...options,
    });

  let res = await doFetch();
  if (canRetry && !res.ok && [502, 503, 504].includes(res.status)) {
    // Retry once for transient proxy/backend restarts.
    await new Promise((resolve) => setTimeout(resolve, 350));
    res = await doFetch();
  }

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
  requested_collectors?: string[];
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

export async function uploadFileInvestigation(
  file: File,
  context?: string,
): Promise<{ investigation_id: string; domain: string; observable_type: string; state: string }> {
  const formData = new FormData();
  formData.append("file", file);
  if (context) formData.append("context", context);

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
  if (options?.run_ai !== undefined) formData.append("run_ai", String(options.run_ai));
  if (options?.ml_phishing_score !== undefined) {
    formData.append("ml_phishing_score", String(options.ml_phishing_score));
  }

  const proxiedEndpoint = `${BASE}/email-investigations/upload`;

  function getDirectEndpointFromBrowser(): string | null {
    if (typeof window === "undefined") return null;
    const configured = `${DIRECT_BACKEND}/api/email-investigations/upload`;
    try {
      const configuredUrl = new URL(configured);
      const pageHost = (window.location.hostname || "").toLowerCase();
      const configuredHost = configuredUrl.hostname.toLowerCase();
      const pageIsLocal = pageHost === "localhost" || pageHost === "127.0.0.1";
      const configuredIsLocal = configuredHost === "localhost" || configuredHost === "127.0.0.1";

      // Remote browser + localhost backend URL will never work; use same host on :8000.
      if (!pageIsLocal && configuredIsLocal) {
        return `${window.location.protocol}//${window.location.hostname}:8000/api/email-investigations/upload`;
      }
      return configured;
    } catch {
      return null;
    }
  }

  const browserDirectEndpoint = getDirectEndpointFromBrowser();

  function shouldTryDirectBackendFromBrowser(): boolean {
    return !!browserDirectEndpoint;
  }

  async function postMultipart(endpoint: string): Promise<Response> {
    return fetch(endpoint, { method: "POST", body: formData });
  }

  const endpoints: string[] = [proxiedEndpoint];
  if (
    shouldTryDirectBackendFromBrowser() &&
    browserDirectEndpoint &&
    browserDirectEndpoint !== proxiedEndpoint
  ) {
    endpoints.push(browserDirectEndpoint);
  }

  let res: Response | null = null;
  let lastNetworkError: unknown = null;
  for (const endpoint of endpoints) {
    try {
      res = await postMultipart(endpoint);
      // Stop on first HTTP response to avoid duplicate POST submits.
      break;
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

  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json();
}

export async function getEmailInvestigationRun(runId: string): Promise<any> {
  return request<any>(`/email-investigations/${runId}`);
}

export async function listEmailInvestigationHistory(
  params?: { limit?: number; offset?: number },
): Promise<{ items: any[]; limit: number; offset: number }> {
  const qs = new URLSearchParams();
  if (params?.limit !== undefined) qs.set("limit", String(params.limit));
  if (params?.offset !== undefined) qs.set("offset", String(params.offset));
  const query = qs.toString();
  return request<{ items: any[]; limit: number; offset: number }>(
    `/email-investigations/history${query ? `?${query}` : ""}`,
  );
}

export async function getEmailInvestigationHistoryItem(historyId: string): Promise<any> {
  return request<any>(`/email-investigations/history/${historyId}`);
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export function listInvestigations(params?: {
  limit?: number; offset?: number; state?: string; search?: string; observable_type?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.state) qs.set("state", params.state);
  if (params?.search) qs.set("search", params.search);
  if (params?.observable_type) qs.set("observable_type", params.observable_type);
  const query = qs.toString();
  return request<PaginatedResponse<any>>(`/investigations${query ? `?${query}` : ""}`);
}

export function getInvestigation(id: string) {
  return request<any>(`/investigations/${id}`);
}

export function getEvidence(id: string) {
  return request<any>(`/investigations/${id}/evidence`);
}

export function getReport(id: string) {
  return request<any>(`/investigations/${id}/report`);
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
