/**
 * API client — wraps fetch with error handling.
 *
 * All requests go through Next.js rewrites (see next.config.js)
 * so /api/* → http://localhost:8000/api/*
 */

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
  context?: string;
  requested_collectors?: string[];
}) {
  return request<{
    investigation_id: string;
    domain: string;
    state: string;
    message: string;
  }>("/investigations", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function listInvestigations(params?: { limit?: number; offset?: number; state?: string }) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.state) qs.set("state", params.state);
  const query = qs.toString();
  return request<any[]>(`/investigations${query ? `?${query}` : ""}`);
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
