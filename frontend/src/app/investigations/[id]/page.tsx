"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";

import ProgressTimeline from "@/components/investigation/ProgressTimeline";
import EnrichmentPanel from "@/components/investigation/EnrichmentPanel";
import Spinner from "@/components/shared/Spinner";
import TabBar from "@/components/shared/TabBar";

import ExecutiveSummaryTab from "@/components/report/ExecutiveSummaryTab";
import TechnicalEvidenceTab from "@/components/report/TechnicalEvidenceTab";
import FindingsTab from "@/components/report/FindingsTab";
import IndicatorsTab from "@/components/report/IndicatorsTab";
import SignalsTab from "@/components/report/SignalsTab";
import InfrastructureTab from "@/components/report/InfrastructureTab";

import * as api from "@/lib/api";

// Full tab set for domain / URL investigations (Claude analysis available)
const DOMAIN_TABS = [
  { id: "summary", label: "Executive Summary" },
  { id: "evidence", label: "Technical Evidence" },
  { id: "findings", label: "Findings" },
  { id: "indicators", label: "Indicators & Pivots" },
  { id: "signals", label: "Signals & Gaps" },
  { id: "infrastructure", label: "Infrastructure" },
  { id: "raw", label: "Raw JSON" },
] as const;

// Minimal tab set for fast-path types (hash / ip / file)
// No AI-generated narrative — just technical evidence and IOCs.
const FAST_PATH_TABS = [
  { id: "evidence", label: "Technical Evidence" },
  { id: "indicators", label: "Indicators & Pivots" },
] as const;

const FAST_PATH_TYPES = new Set(["hash", "ip", "file"]);

type TabId = "summary" | "evidence" | "findings" | "indicators" | "signals" | "infrastructure" | "raw";

export default function InvestigationPage() {
  const params = useParams();
  const router = useRouter();
  const investigationId = params?.id as string;

  const [detail, setDetail] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const observableType = detail?.observable_type || "domain";
  const isFastPath = FAST_PATH_TYPES.has(observableType);
  const tabs = isFastPath ? FAST_PATH_TABS : DOMAIN_TABS;
  const defaultTab: TabId = isFastPath ? "evidence" : "summary";
  const [activeTab, setActiveTab] = useState<TabId>(defaultTab);
  const [tabError, setTabError] = useState<string | null>(null);

  // Fetch all data
  const fetchData = useCallback(async () => {
    if (!investigationId) return;
    setLoading(true);
    setError(null);

    try {
      const det = await api.getInvestigation(investigationId).catch(() => null);
      setDetail(det);

      const ev = await api.getEvidence(investigationId).catch(() => null);
      setEvidence(ev);

      const rep = await api.getReport(investigationId).catch(() => null);
      setReport(rep);

      setLoading(false);
    } catch (e: any) {
      setError(e?.message || "Failed to load");
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchData();
    // Poll every 5s if not concluded
    const interval = setInterval(() => {
      if (detail?.state === "concluded" || detail?.state === "failed") return;
      fetchData();
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchData, detail?.state]);

  // Reset activeTab when observable type loads and the current tab isn't in the tab set
  useEffect(() => {
    const validIds = tabs.map((t) => t.id);
    if (!validIds.includes(activeTab as any)) {
      setActiveTab(tabs[0].id as TabId);
    }
  }, [isFastPath]); // eslint-disable-line react-hooks/exhaustive-deps

  // Clear tab error when switching tabs
  useEffect(() => {
    setTabError(null);
  }, [activeTab]);

  const handleEnrich = useCallback(async (text: string) => {
    try {
      const data = JSON.parse(text);
      await api.enrichInvestigation(investigationId, data);
    } catch {
      await api.enrichInvestigation(investigationId, { soc_ticket_notes: text }).catch(() => {});
    }
  }, [investigationId]);

  // ─── Loading state ───
  if (loading && !evidence && !report) {
    return <Spinner message="Loading investigation..." />;
  }

  // ─── Waiting for results ───
  if (!report && detail?.state !== "concluded" && detail?.state !== "failed") {
    return (
      <div style={{ paddingTop: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 20, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
            {detail?.domain || investigationId}
          </span>
          {detail?.observable_type && detail.observable_type !== "domain" && (
            <span style={{
              fontSize: 10, fontWeight: 700,
              padding: "3px 8px",
              background: "rgba(129,140,248,0.12)",
              color: "#818cf8",
              border: "1px solid rgba(129,140,248,0.25)",
              borderRadius: 4,
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.05em",
              textTransform: "uppercase" as const,
            }}>
              {detail.observable_type}
            </span>
          )}
        </div>
        <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 20, fontFamily: "var(--font-sans)" }}>
          State: {detail?.state || "loading..."}
        </div>
        <Spinner message={`Investigation in progress — ${detail?.state || "gathering"}...`} />
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button
            onClick={fetchData}
            style={{
              padding: "8px 20px", background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
              fontSize: 12, cursor: "pointer", fontFamily: "var(--font-sans)",
              fontWeight: 500,
            }}
          >
            Refresh
          </button>
        </div>
      </div>
    );
  }

  // ─── Render active tab with error catching ───
  function renderTab() {
    try {
      switch (activeTab) {
        case "summary":
          return report ? <ExecutiveSummaryTab report={report} /> : <NoData label="report" />;
        case "evidence":
          return evidence ? <TechnicalEvidenceTab evidence={evidence} domain={detail?.domain} observableType={detail?.observable_type} /> : <NoData label="evidence" />;
        case "findings":
          return report ? <FindingsTab report={report} /> : <NoData label="report" />;
        case "indicators":
          return report ? <IndicatorsTab report={report} investigationId={investigationId} /> : <NoData label="report" />;
        case "signals":
          return evidence ? <SignalsTab evidence={evidence} /> : <NoData label="evidence" />;
        case "infrastructure":
          return <InfrastructureTab investigationId={investigationId} evidence={evidence} />;
        case "raw":
          return <RawJsonView evidence={evidence} report={report} detail={detail} />;
        default:
          return null;
      }
    } catch (e: any) {
      return (
        <div style={{
          padding: 24, background: "rgba(239,68,68,0.08)",
          border: "1px solid rgba(239,68,68,0.2)", borderRadius: "var(--radius)",
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "var(--red)", marginBottom: 8 }}>
            Error rendering {activeTab} tab
          </div>
          <pre style={{
            fontSize: 11, color: "var(--text-secondary)", whiteSpace: "pre-wrap",
            wordBreak: "break-all", fontFamily: "var(--font-mono)",
          }}>
            {e?.message || String(e)}
            {"\n\n"}
            {e?.stack || ""}
          </pre>
          <div style={{ marginTop: 16 }}>
            <button
              onClick={() => setActiveTab("raw")}
              style={{
                padding: "6px 16px", background: "var(--bg-elevated)", border: "none",
                borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 11,
                cursor: "pointer", fontFamily: "var(--font-mono)",
              }}
            >
              VIEW RAW JSON →
            </button>
          </div>
        </div>
      );
    }
  }

  // ─── Main report view ───
  return (
    <div style={{ paddingTop: 24, paddingBottom: 80 }}>
      {/* Domain header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8,
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span style={{
              fontSize: 24, fontWeight: 700, color: "var(--text)",
              letterSpacing: "-0.01em", fontFamily: "var(--font-sans)",
            }}>
              {detail?.domain || evidence?.domain || investigationId}
            </span>
            {detail?.observable_type && detail.observable_type !== "domain" && (
              <span style={{
                fontSize: 10, fontWeight: 700,
                padding: "3px 8px",
                background: "rgba(129,140,248,0.12)",
                color: "#818cf8",
                border: "1px solid rgba(129,140,248,0.25)",
                borderRadius: 4,
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.05em",
                textTransform: "uppercase" as const,
              }}>
                {detail.observable_type}
              </span>
            )}
          </div>
          <div style={{
            fontSize: 12, color: "var(--text-muted)", marginTop: 4,
            fontFamily: "var(--font-sans)",
          }}>
            Investigation {String(investigationId).slice(0, 8)}...
            {detail?.concluded_at && ` · Completed ${new Date(detail.concluded_at).toLocaleString()}`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <HeaderButton onClick={() => router.push("/")}>New Investigation</HeaderButton>
          <HeaderButton onClick={() => {
            window.open(`/api/investigations/${investigationId}/export/pdf`, "_blank");
          }}>
            Export PDF
          </HeaderButton>
          <HeaderButton onClick={() => {
            window.open(`/api/investigations/${investigationId}/export/markdown`, "_blank");
          }}>
            Export MD
          </HeaderButton>
          <HeaderButton onClick={() => {
            const blob = new Blob(
              [JSON.stringify({ evidence, report, detail }, null, 2)],
              { type: "application/json" }
            );
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${detail?.domain || "investigation"}-full.json`;
            a.click();
            URL.revokeObjectURL(url);
          }}>
            Export JSON
          </HeaderButton>
          <HeaderButton onClick={fetchData}>Refresh</HeaderButton>
        </div>
      </div>

      {/* Collector progress */}
      {evidence && (
        <ProgressTimeline
          collectors={Object.fromEntries(
            ["dns", "tls", "http", "whois", "asn", "intel", "vt"]
              .map((c) => {
                // Backend stores ASN evidence under "hosting" key
                const evidenceKey = c === "asn" ? "hosting" : c;
                const collectorData = evidence?.[evidenceKey];
                const status = collectorData?.meta?.status || (collectorData ? "completed" : "pending");
                return [c, status];
              })
          )}
          analystDone={!!report}
        />
      )}

      {/* Enrichment */}
      <EnrichmentPanel onSubmit={handleEnrich} />

      {/* Tabs */}
      <TabBar tabs={tabs} active={activeTab} onChange={(id) => setActiveTab(id as TabId)} />

      {/* Tab content wrapped in ErrorBoundary */}
      <ErrorBoundary key={activeTab} fallback={activeTab} onRaw={() => setActiveTab("raw")}>
        {renderTab()}
      </ErrorBoundary>
    </div>
  );
}

// ─── Helper Components ───

function HeaderButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "7px 14px", background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
        fontSize: 12, fontWeight: 500, cursor: "pointer",
        fontFamily: "var(--font-sans)",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "var(--accent-glow)";
        e.currentTarget.style.borderColor = "var(--accent)";
        e.currentTarget.style.color = "var(--accent)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "var(--bg-elevated)";
        e.currentTarget.style.borderColor = "var(--border)";
        e.currentTarget.style.color = "var(--text-secondary)";
      }}
    >
      {children}
    </button>
  );
}

function NoData({ label }: { label: string }) {
  return (
    <div style={{ padding: 40, textAlign: "center" }}>
      <div style={{ fontSize: 13, color: "var(--text-dim)" }}>
        No {label} data available yet.
      </div>
    </div>
  );
}

function RawJsonView({ evidence, report, detail }: { evidence: any; report: any; detail: any }) {
  const [view, setView] = useState<"evidence" | "report" | "detail">("evidence");

  const data = view === "evidence" ? evidence : view === "report" ? report : detail;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["evidence", "report", "detail"] as const).map((v) => (
          <button
            key={v}
            onClick={() => setView(v)}
            style={{
              padding: "6px 14px",
              background: view === v ? "var(--accent)" : "var(--bg-elevated)",
              border: view === v ? "1px solid var(--accent)" : "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: view === v ? "#fff" : "var(--text-dim)",
              fontSize: 11, fontWeight: 500, cursor: "pointer",
              fontFamily: "var(--font-sans)",
              textTransform: "capitalize",
            }}
          >
            {v}
          </button>
        ))}
      </div>
      <pre
        style={{
          background: "var(--bg-input)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: 20,
          fontSize: 11,
          color: "var(--text-secondary)",
          overflow: "auto",
          maxHeight: "70vh",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          fontFamily: "var(--font-mono)",
        }}
      >
        {data ? JSON.stringify(data, null, 2) : "No data available"}
      </pre>
    </div>
  );
}

// ─── Error Boundary ───

class ErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback: string; onRaw: () => void },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: 24, background: "rgba(239,68,68,0.08)",
          border: "1px solid rgba(239,68,68,0.2)", borderRadius: 8,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#ef4444", marginBottom: 8 }}>
            Error rendering &quot;{this.props.fallback}&quot; tab
          </div>
          <pre style={{
            fontSize: 11, color: "#94a3b8", whiteSpace: "pre-wrap",
            wordBreak: "break-all", marginBottom: 16,
          }}>
            {this.state.error?.message}
            {"\n"}
            {this.state.error?.stack}
          </pre>
          <button
            onClick={this.props.onRaw}
            style={{
              padding: "6px 16px", background: "#1e293b", border: "none",
              borderRadius: 4, color: "#e2e8f0", fontSize: 11,
              cursor: "pointer",
            }}
          >
            VIEW RAW JSON →
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
