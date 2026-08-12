"use client";

/**
 * Open client alerts, worst first.
 *
 * The page exists to answer one question — what needs acknowledging or
 * resolving — so severity filtering and the two actions are the whole surface.
 * Everything else about an alert lives on the investigation it came from.
 */

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listAllAlerts, acknowledgeAlert, resolveAlert, listClients } from "@/lib/api";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  Page,
  PageHeader,
} from "@/components/ui/Primitives";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeAgo(dateStr?: string): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--status-critical)",
  high:     "var(--orange)",
  medium:   "var(--status-warning)",
  low:      "var(--status-info)",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

const ALERT_TYPE_LABELS: Record<string, string> = {
  brand_impersonation:    "Brand Impersonation",
  typosquatting:          "Typosquatting",
  phishing_detected:      "Phishing Detected",
  infrastructure_overlap: "Infrastructure Overlap",
};

const PAGE_LIMIT = 30;

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AlertsPage() {
  const router = useRouter();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<"open" | "resolved" | "all">("open");

  // Client map for names
  const [clientMap, setClientMap] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const resolved = statusFilter === "all" ? undefined : statusFilter === "resolved";
      const data = await listAllAlerts({
        limit: PAGE_LIMIT,
        offset: page * PAGE_LIMIT,
        severity: severityFilter || undefined,
        resolved,
      });
      setAlerts(data.items || []);
      setTotal(data.total || 0);
    } catch {
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, [page, severityFilter, statusFilter]);

  useEffect(() => {
    listClients({ limit: 100 })
      .then((data: any) => {
        const map: Record<string, string> = {};
        for (const c of data.items || []) map[c.id] = c.name;
        setClientMap(map);
      })
      .catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  const [actionError, setActionError] = useState<string | null>(null);

  const handleAcknowledge = async (alertId: string) => {
    setActionError(null);
    try {
      await acknowledgeAlert(alertId);
      load();
    } catch (e: any) {
      // A browser alert() interrupts triage and loses the message. The failure
      // belongs on the page, next to the list it failed on.
      setActionError(`Could not acknowledge that alert: ${e?.message || "unknown error"}`);
    }
  };

  const handleResolve = async (alertId: string) => {
    setActionError(null);
    try {
      await resolveAlert(alertId);
      load();
    } catch (e: any) {
      setActionError(`Could not resolve that alert: ${e?.message || "unknown error"}`);
    }
  };

  const totalPages = Math.ceil(total / PAGE_LIMIT);

  return (
    <Page>
      <PageHeader
        title="Alerts"
        subtitle="Client threat alerts raised by concluded investigations."
        meta={
          <span>
            {total} {statusFilter === "all" ? "total" : statusFilter}
            {severityFilter ? ` · ${severityFilter} only` : ""}
          </span>
        }
        actions={
          <div className="ds-toolbar" role="group" aria-label="Filter alerts">
            {(["open", "resolved", "all"] as const).map((f) => (
              <Button
                key={f}
                variant={statusFilter === f ? "primary" : "secondary"}
                aria-pressed={statusFilter === f}
                onClick={() => { setStatusFilter(f); setPage(0); }}
                style={{ textTransform: "capitalize" }}
              >
                {f}
              </Button>
            ))}
          </div>
        }
      />

      <div className="ds-toolbar" role="group" aria-label="Filter by severity">
        {SEVERITY_ORDER.map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={severityFilter === s}
            onClick={() => { setSeverityFilter(severityFilter === s ? "" : s); setPage(0); }}
            className="ds-btn"
            style={{
              textTransform: "capitalize",
              color: severityFilter === s ? SEVERITY_COLORS[s] : "var(--text-dim)",
              borderColor: severityFilter === s ? SEVERITY_COLORS[s] : "var(--panel-divider-strong)",
            }}
          >
            <span
              aria-hidden="true"
              style={{ width: 6, height: 6, borderRadius: 999, background: SEVERITY_COLORS[s], display: "inline-block" }}
            />
            {s}
          </button>
        ))}
        {severityFilter && (
          <Button variant="quiet" onClick={() => { setSeverityFilter(""); setPage(0); }}>
            Clear severity filter
          </Button>
        )}
      </div>

      {actionError && <ErrorState title="Action failed" detail={actionError} />}

      <div>
        {loading ? (
          <LoadingState label="Loading alerts…" />
        ) : alerts.length === 0 ? (
          <EmptyState
            title={statusFilter === "open" ? "No open alerts" : "No alerts match this filter"}
            hint={
              statusFilter === "open"
                ? "Nothing is waiting on an analyst for the registered clients."
                : "Try a different status or severity."
            }
          />
        ) : (
          alerts.map((a, idx) => {
            const clientName = clientMap[a.client_id];
            return (
              <div
                key={a.id}
                className="row-hover"
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "var(--space-3)",
                  padding: "var(--space-3) 0",
                  borderBottom: idx < alerts.length - 1 ? "1px solid var(--panel-divider-soft)" : "none",
                  opacity: a.resolved ? 0.62 : 1,
                }}
              >
                {/* Severity as a rule down the row — the one place colour alone
                    is used, and the word is repeated below it. */}
                <div style={{
                  width: 3,
                  alignSelf: "stretch",
                  borderRadius: 2,
                  background: SEVERITY_COLORS[a.severity] || "var(--status-neutral)",
                  flexShrink: 0,
                }} aria-hidden="true" />

                {/* Content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", flexWrap: "wrap", marginBottom: 2 }}>
                    <span style={{
                      fontSize: "var(--font-body)", fontWeight: 600,
                      color: a.resolved ? "var(--text-muted)" : "var(--text)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {a.title}
                    </span>

                    {/* Severity carries the row's colour already; the chip says
                        it in words for anyone who cannot use the colour. */}
                    <span style={{
                      fontSize: "var(--font-micro)", fontWeight: 700,
                      color: SEVERITY_COLORS[a.severity] || "var(--text-muted)",
                      textTransform: "capitalize",
                    }}>
                      {a.severity}
                    </span>

                    <span style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>
                      {ALERT_TYPE_LABELS[a.alert_type] || a.alert_type}
                    </span>

                    {a.resolved && (
                      <span style={{ fontSize: "var(--font-micro)", color: "var(--status-success)" }}>Resolved</span>
                    )}
                    {!a.resolved && a.acknowledged && (
                      <span style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>Acknowledged</span>
                    )}
                  </div>

                  <div style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)", display: "flex", gap: "var(--space-3)", flexWrap: "wrap" }}>
                    <span>{timeAgo(a.created_at)}</span>
                    {clientName && (
                      <button
                        type="button"
                        className="ds-btn ds-btn--quiet"
                        style={{ padding: 0, color: "var(--accent)", fontSize: "var(--font-micro)" }}
                        onClick={() => router.push(`/clients/${a.client_id}?tab=alerts`)}
                      >
                        {clientName}
                      </button>
                    )}
                    {a.investigation_id && (
                      <button
                        type="button"
                        className="ds-btn ds-btn--quiet"
                        style={{ padding: 0, color: "var(--accent)", fontSize: "var(--font-micro)" }}
                        onClick={() => router.push(`/investigations/${a.investigation_id}`)}
                      >
                        View investigation
                      </button>
                    )}
                  </div>
                </div>

                {/* Resolve is the action that finishes the job, so it leads. */}
                {!a.resolved && (
                  <div className="ds-toolbar" style={{ flexShrink: 0 }}>
                    {!a.acknowledged && (
                      <Button variant="quiet" onClick={() => handleAcknowledge(a.id)}>
                        Acknowledge
                      </Button>
                    )}
                    <Button variant="secondary" onClick={() => handleResolve(a.id)}>
                      Resolve
                    </Button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Paging by prev/next: one button per page becomes a wall at 40 pages. */}
      {totalPages > 1 && (
        <div className="ds-toolbar" style={{ justifyContent: "center" }}>
          <Button variant="secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
            Previous
          </Button>
          <span style={{ fontSize: "var(--font-meta)", color: "var(--text-muted)" }}>
            Page {page + 1} of {totalPages}
          </span>
          <Button
            variant="secondary"
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
          >
            Next
          </Button>
        </div>
      )}
    </Page>
  );
}
