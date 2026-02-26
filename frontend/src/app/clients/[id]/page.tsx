"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter, useParams, useSearchParams } from "next/navigation";
import { getClient, listClientAlerts, acknowledgeAlert, resolveAlert, updateClient, listInvestigations } from "@/lib/api";

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

const ALERT_TYPE_LABELS: Record<string, string> = {
  brand_impersonation: "Brand Impersonation",
  typosquatting:       "Typosquatting",
  phishing_detected:   "Phishing Detected",
  infrastructure_overlap: "Infrastructure Overlap",
};

const CLASSIFICATION_COLORS: Record<string, string> = {
  malicious:    "#f87171",
  suspicious:   "#fbbf24",
  benign:       "#34d399",
  inconclusive: "#94a3b8",
};

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ClientDetailPage() {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const clientId = params.id as string;
  const initialTab = searchParams.get("tab") ?? "overview";

  const [client, setClient] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"overview" | "alerts" | "investigations">(
    initialTab as "overview" | "alerts" | "investigations",
  );

  // Alerts tab
  const [alerts, setAlerts] = useState<any[]>([]);
  const [alertTotal, setAlertTotal] = useState(0);
  const [alertPage, setAlertPage] = useState(0);
  const [alertFilter, setAlertFilter] = useState<"all" | "open" | "resolved">("open");
  const [alertsLoading, setAlertsLoading] = useState(false);

  // Investigations tab
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [invLoading, setInvLoading] = useState(false);

  const ALERT_PAGE_LIMIT = 20;

  const loadClient = useCallback(async () => {
    try {
      const data = await getClient(clientId);
      setClient(data);
    } catch {
      router.push("/clients");
    } finally {
      setLoading(false);
    }
  }, [clientId, router]);

  const loadAlerts = useCallback(async () => {
    setAlertsLoading(true);
    try {
      const resolved = alertFilter === "all" ? undefined : alertFilter === "resolved";
      const data = await listClientAlerts(clientId, {
        limit: ALERT_PAGE_LIMIT,
        offset: alertPage * ALERT_PAGE_LIMIT,
        resolved,
      });
      setAlerts(data.items || []);
      setAlertTotal(data.total || 0);
    } catch {
      setAlerts([]);
    } finally {
      setAlertsLoading(false);
    }
  }, [clientId, alertPage, alertFilter]);

  const loadInvestigations = useCallback(async () => {
    if (!client) return;
    setInvLoading(true);
    try {
      const data = await listInvestigations({ search: client.domain, limit: 50 });
      setInvestigations(data.items || []);
    } catch {
      setInvestigations([]);
    } finally {
      setInvLoading(false);
    }
  }, [client]);

  useEffect(() => { loadClient(); }, [loadClient]);
  useEffect(() => { if (tab === "alerts") loadAlerts(); }, [tab, loadAlerts]);
  useEffect(() => { if (tab === "investigations") loadInvestigations(); }, [tab, loadInvestigations]);

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAlert(alertId);
      loadAlerts();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      await resolveAlert(alertId);
      loadAlerts();
      loadClient();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const card: React.CSSProperties = {
    background: "var(--bg-card)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-lg)",
    padding: 20,
    marginBottom: 16,
  };

  if (loading) {
    return (
      <div style={{ maxWidth: 1000, margin: "0 auto", padding: "48px 24px", textAlign: "center" }}>
        <div style={{ color: "var(--text-muted)", fontFamily: "var(--font-sans)", fontSize: 13 }}>Loading...</div>
      </div>
    );
  }

  if (!client) return null;

  const tabs: { id: typeof tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "alerts", label: `Alerts${client.alert_count > 0 ? ` (${client.alert_count})` : ""}` },
    { id: "investigations", label: "Investigations" },
  ];

  return (
    <div style={{ maxWidth: 1000, margin: "0 auto", padding: "32px 24px", paddingBottom: 60 }}>

      {/* Back link */}
      <button
        onClick={() => router.push("/clients")}
        style={{
          background: "none", border: "none",
          color: "var(--text-muted)", cursor: "pointer",
          fontSize: 12, fontFamily: "var(--font-sans)",
          padding: 0, marginBottom: 20,
          display: "flex", alignItems: "center", gap: 6,
        }}
      >
        ← All Clients
      </button>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--font-sans)", color: "var(--text)", margin: 0 }}>
            {client.name}
          </h1>
          <span style={{
            fontSize: 10,
            fontWeight: 700,
            padding: "3px 9px",
            borderRadius: 999,
            background: client.status === "active" ? "rgba(52,211,153,0.15)" : "rgba(148,163,184,0.15)",
            color: client.status === "active" ? "#34d399" : "#94a3b8",
            fontFamily: "var(--font-sans)",
          }}>
            {client.status.toUpperCase()}
          </span>
        </div>
        <div style={{ fontSize: 13, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
          {client.domain}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24, borderBottom: "1px solid var(--border)", paddingBottom: 0 }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: "9px 18px",
              background: "none",
              border: "none",
              borderBottom: tab === t.id ? "2px solid var(--accent)" : "2px solid transparent",
              color: tab === t.id ? "var(--accent)" : "var(--text-dim)",
              fontSize: 13,
              fontWeight: 600,
              fontFamily: "var(--font-sans)",
              cursor: "pointer",
              marginBottom: -1,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Overview tab */}
      {tab === "overview" && (
        <div>
          <div style={card}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <Field label="Primary Domain" value={client.domain} mono />
              <Field label="Contact Email" value={client.contact_email || "—"} />
              <Field
                label="Aliases"
                value={client.aliases?.length > 0 ? client.aliases.join(", ") : "None"}
                mono
              />
              <Field
                label="Brand Keywords"
                value={client.brand_keywords?.length > 0 ? client.brand_keywords.join(", ") : "None"}
                mono
              />
              <Field label="Status" value={client.status} />
              <Field label="Registered" value={timeAgo(client.created_at)} />
              <Field label="Total Alerts" value={String(client.alert_count)} accent={client.alert_count > 0 ? "#f87171" : undefined} />
              <Field label="Last Alert" value={timeAgo(client.last_alert_at)} />
              <Field
                label="Default Analyzers"
                value={client.default_collectors?.length > 0 ? client.default_collectors.join(", ") : "All (no restriction)"}
                mono
              />
            </div>
            {client.notes && (
              <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginBottom: 6, fontWeight: 600 }}>NOTES</div>
                <div style={{ fontSize: 13, color: "var(--text-dim)", fontFamily: "var(--font-sans)", lineHeight: 1.6 }}>{client.notes}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Alerts tab */}
      {tab === "alerts" && (
        <div>
          <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
            {(["all", "open", "resolved"] as const).map((f) => (
              <button
                key={f}
                onClick={() => { setAlertFilter(f); setAlertPage(0); }}
                style={{
                  padding: "6px 14px",
                  background: alertFilter === f ? "var(--accent)" : "var(--bg-elevated)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  color: alertFilter === f ? "#fff" : "var(--text-dim)",
                  fontSize: 12,
                  fontFamily: "var(--font-sans)",
                  cursor: "pointer",
                  textTransform: "capitalize",
                }}
              >
                {f}
              </button>
            ))}
          </div>

          <div style={card}>
            {alertsLoading ? (
              <div style={{ textAlign: "center", padding: 32, color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-sans)" }}>Loading...</div>
            ) : alerts.length === 0 ? (
              <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-sans)" }}>No alerts found</div>
            ) : (
              alerts.map((a) => (
                <div
                  key={a.id}
                  style={{
                    padding: "14px 0",
                    borderBottom: "1px solid var(--border)",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 14,
                  }}
                >
                  {/* Severity dot */}
                  <div style={{
                    width: 8, height: 8,
                    borderRadius: "50%",
                    background: SEVERITY_COLORS[a.severity] || "#94a3b8",
                    marginTop: 5,
                    flexShrink: 0,
                  }} />

                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", fontFamily: "var(--font-sans)" }}>
                        {a.title}
                      </span>
                      <span style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: "2px 7px",
                        borderRadius: 999,
                        background: `${SEVERITY_COLORS[a.severity]}22`,
                        color: SEVERITY_COLORS[a.severity] || "#94a3b8",
                        fontFamily: "var(--font-sans)",
                      }}>
                        {a.severity.toUpperCase()}
                      </span>
                      <span style={{
                        fontSize: 9,
                        padding: "2px 7px",
                        borderRadius: 999,
                        background: "var(--bg-elevated)",
                        color: "var(--text-muted)",
                        fontFamily: "var(--font-sans)",
                      }}>
                        {ALERT_TYPE_LABELS[a.alert_type] || a.alert_type}
                      </span>
                      {a.resolved && <span style={{ fontSize: 9, color: "#34d399", fontFamily: "var(--font-sans)" }}>✓ Resolved</span>}
                      {!a.resolved && a.acknowledged && <span style={{ fontSize: 9, color: "#94a3b8", fontFamily: "var(--font-sans)" }}>Acknowledged</span>}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                      {timeAgo(a.created_at)}
                      {a.investigation_id && (
                        <span
                          style={{ marginLeft: 10, color: "var(--accent)", cursor: "pointer", textDecoration: "underline" }}
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
                        <button
                          onClick={() => handleAcknowledge(a.id)}
                          style={smallBtn("#94a3b8")}
                        >
                          Ack
                        </button>
                      )}
                      <button
                        onClick={() => handleResolve(a.id)}
                        style={smallBtn("#34d399")}
                      >
                        Resolve
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {alertTotal > ALERT_PAGE_LIMIT && (
            <div style={{ display: "flex", gap: 8, justifyContent: "center", marginTop: 16 }}>
              {Array.from({ length: Math.ceil(alertTotal / ALERT_PAGE_LIMIT) }, (_, i) => (
                <button
                  key={i}
                  onClick={() => setAlertPage(i)}
                  style={{
                    padding: "5px 12px",
                    background: i === alertPage ? "var(--accent)" : "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    color: i === alertPage ? "#fff" : "var(--text-dim)",
                    fontSize: 11,
                    fontFamily: "var(--font-sans)",
                    cursor: "pointer",
                  }}
                >
                  {i + 1}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Investigations tab */}
      {tab === "investigations" && (
        <div style={card}>
          {invLoading ? (
            <div style={{ textAlign: "center", padding: 32, color: "var(--text-muted)", fontSize: 13 }}>Loading...</div>
          ) : investigations.length === 0 ? (
            <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-sans)" }}>
              No investigations found for {client.domain}
            </div>
          ) : (
            investigations.map((inv) => (
              <div
                key={inv.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "12px 0",
                  borderBottom: "1px solid var(--border)",
                  cursor: "pointer",
                }}
                onClick={() => router.push(`/investigations/${inv.id}`)}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-elevated)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                    {inv.domain}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 2 }}>
                    {timeAgo(inv.created_at)} · {inv.state}
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  {inv.classification && (
                    <span style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: CLASSIFICATION_COLORS[inv.classification] || "#94a3b8",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {inv.classification.toUpperCase()}
                    </span>
                  )}
                  {inv.risk_score != null && (
                    <span style={{
                      fontSize: 12,
                      fontFamily: "var(--font-mono)",
                      color: inv.risk_score >= 70 ? "#f87171" : inv.risk_score >= 40 ? "#fbbf24" : "#60a5fa",
                    }}>
                      {inv.risk_score}
                    </span>
                  )}
                  <span style={{ fontSize: 12, color: "var(--accent)" }}>→</span>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function Field({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: string }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: accent || "var(--text)", fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)", fontWeight: mono ? 400 : 500 }}>
        {value}
      </div>
    </div>
  );
}

function smallBtn(color: string): React.CSSProperties {
  return {
    padding: "4px 10px",
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
