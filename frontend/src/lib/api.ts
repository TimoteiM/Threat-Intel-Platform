/**
 * API client — wraps fetch with error handling.
 *
 * All requests go through Next.js rewrites (see next.config.js)
 * so /api/* → http://localhost:8000/api/*
 */

import type { DoctorStatus } from "@/lib/types";

const BASE = "/api";

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
  deepScan?: boolean,
): Promise<{ investigation_id: string; domain: string; observable_type: string; state: string }> {
  const formData = new FormData();
  formData.append("file", file);
  if (context) formData.append("context", context);
  if (deepScan !== undefined) formData.append("deep_scan", String(deepScan));

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

export function getDoctorStatus() {
  return request<DoctorStatus>("/doctor");
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
