"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listAllAlerts, acknowledgeAlert, resolveAlert, listClients } from "@/lib/api";

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
  critical: "#f87171",
  high:     "#fb923c",
  medium:   "#fbbf24",
  low:      "#60a5fa",
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

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAlert(alertId);
      load();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      await resolveAlert(alertId);
      load();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const card: React.CSSProperties = {
    background: "var(--bg-card)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-lg)",
    overflow: "hidden",
  };

  const totalPages = Math.ceil(total / PAGE_LIMIT);

  // Severity summary counts
  const counts = SEVERITY_ORDER.reduce((acc, s) => {
    acc[s] = alerts.filter((a) => a.severity === s).length;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "32px 24px", paddingBottom: 60 }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--font-sans)", color: "var(--text)", margin: 0 }}>
          Alert Feed
        </h1>
        <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 3 }}>
          Client threat alerts — triggered by concluded investigations
        </div>
      </div>

      {/* Severity summary pills */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        {SEVERITY_ORDER.map((s) => (
          <div
            key={s}
            onClick={() => { setSeverityFilter(severityFilter === s ? "" : s); setPage(0); }}
            style={{
              padding: "8px 16px",
              background: severityFilter === s ? `${SEVERITY_COLORS[s]}22` : "var(--bg-card)",
              border: `1px solid ${severityFilter === s ? SEVERITY_COLORS[s] : "var(--border)"}`,
              borderRadius: "var(--radius)",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: SEVERITY_COLORS[s], display: "inline-block", flexShrink: 0 }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: severityFilter === s ? SEVERITY_COLORS[s] : "var(--text-dim)", fontFamily: "var(--font-sans)", textTransform: "capitalize" }}>
              {s}
            </span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["open", "resolved", "all"] as const).map((f) => (
          <button
            key={f}
            onClick={() => { setStatusFilter(f); setPage(0); }}
            style={{
              padding: "7px 16px",
              background: statusFilter === f ? "var(--accent)" : "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: statusFilter === f ? "#fff" : "var(--text-dim)",
              fontSize: 12,
              fontFamily: "var(--font-sans)",
              fontWeight: 600,
              cursor: "pointer",
              textTransform: "capitalize",
            }}
          >
            {f}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {severityFilter && (
          <button
            onClick={() => { setSeverityFilter(""); setPage(0); }}
            style={{
              padding: "7px 14px",
              background: "none",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text-muted)",
              fontSize: 11,
              fontFamily: "var(--font-sans)",
              cursor: "pointer",
            }}
          >
            Clear filter ×
          </button>
        )}
      </div>

      {/* Alert list */}
      <div style={card}>
        {loading ? (
          <div style={{ textAlign: "center", padding: 48, color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-sans)" }}>
            Loading...
          </div>
        ) : alerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: 60 }}>
            <div style={{ fontSize: 36, marginBottom: 14 }}>✓</div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#34d399", fontFamily: "var(--font-sans)" }}>
              No alerts
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 6 }}>
              {statusFilter === "open" ? "All clear — no open alerts for registered clients" : "No alerts match the current filter"}
            </div>
          </div>
        ) : (
          alerts.map((a, idx) => {
            const clientName = clientMap[a.client_id];
            return (
              <div
                key={a.id}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 14,
                  padding: "16px 20px",
                  borderBottom: idx < alerts.length - 1 ? "1px solid var(--border)" : "none",
                  background: a.resolved ? "rgba(52,211,153,0.03)" : "transparent",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { if (!a.resolved) e.currentTarget.style.background = "var(--bg-elevated)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = a.resolved ? "rgba(52,211,153,0.03)" : "transparent"; }}
              >
                {/* Severity bar */}
                <div style={{
                  width: 3,
                  alignSelf: "stretch",
                  borderRadius: 2,
                  background: SEVERITY_COLORS[a.severity] || "#94a3b8",
                  flexShrink: 0,
                }} />

                {/* Content */}
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 4 }}>
                    <span style={{
                      fontSize: 13, fontWeight: 600,
                      color: a.resolved ? "var(--text-muted)" : "var(--text)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {a.title}
                    </span>

                    {/* Severity chip */}
                    <span style={{
                      fontSize: 9, fontWeight: 700,
                      padding: "2px 7px", borderRadius: 999,
                      background: `${SEVERITY_COLORS[a.severity]}22`,
                      color: SEVERITY_COLORS[a.severity] || "#94a3b8",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {a.severity.toUpperCase()}
                    </span>

                    {/* Alert type chip */}
                    <span style={{
                      fontSize: 9, padding: "2px 7px", borderRadius: 999,
                      background: "var(--bg-elevated)",
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {ALERT_TYPE_LABELS[a.alert_type] || a.alert_type}
                    </span>

                    {a.resolved && (
                      <span style={{ fontSize: 9, color: "#34d399", fontFamily: "var(--font-sans)" }}>✓ Resolved</span>
                    )}
                    {!a.resolved && a.acknowledged && (
                      <span style={{ fontSize: 9, color: "#94a3b8", fontFamily: "var(--font-sans)" }}>Acked</span>
                    )}
                  </div>

                  <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "flex", gap: 12, flexWrap: "wrap" }}>
                    <span>{timeAgo(a.created_at)}</span>
                    {clientName && (
                      <span
                        style={{ color: "var(--accent)", cursor: "pointer" }}
                        onClick={() => router.push(`/clients/${a.client_id}?tab=alerts`)}
                      >
                        Client: {clientName}
                      </span>
                    )}
                    {a.investigation_id && (
                      <span
                        style={{ color: "var(--accent)", cursor: "pointer" }}
                        onClick={() => router.push(`/investigations/${a.investigation_id}`)}
                      >
                        View investigation →
                      </span>
                    )}
                  </div>
                </div>

                {/* Actions */}
                {!a.resolved && (
                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                    {!a.acknowledged && (
                      <button onClick={() => handleAcknowledge(a.id)} style={actionBtn("#94a3b8")}>
                        Ack
                      </button>
                    )}
                    <button onClick={() => handleResolve(a.id)} style={actionBtn("#34d399")}>
                      Resolve
                    </button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "center", marginTop: 20 }}>
          {Array.from({ length: totalPages }, (_, i) => (
            <button
              key={i}
              onClick={() => setPage(i)}
              style={{
                padding: "6px 14px",
                background: i === page ? "var(--accent)" : "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: i === page ? "#fff" : "var(--text-dim)",
                fontSize: 12,
                fontFamily: "var(--font-sans)",
                cursor: "pointer",
              }}
            >
              {i + 1}
            </button>
          ))}
        </div>
      )}

      <div style={{ textAlign: "right", fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 10 }}>
        {total} alert{total !== 1 ? "s" : ""} total
      </div>
    </div>
  );
}

function actionBtn(color: string): React.CSSProperties {
  return {
    padding: "5px 12px",
    background: "transparent",
    border: `1px solid ${color}44`,
    borderRadius: "var(--radius-sm)",
    color,
    fontSize: 11,
    fontFamily: "var(--font-sans)",
    fontWeight: 600,
    cursor: "pointer",
  };
}
