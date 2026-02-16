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

import * as api from "@/lib/api";

const TABS = [
  { id: "summary", label: "EXECUTIVE SUMMARY" },
  { id: "evidence", label: "TECHNICAL EVIDENCE" },
  { id: "findings", label: "FINDINGS" },
  { id: "indicators", label: "INDICATORS & PIVOTS" },
  { id: "signals", label: "SIGNALS & GAPS" },
  { id: "raw", label: "RAW JSON" },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function InvestigationPage() {
  const params = useParams();
  const router = useRouter();
  const investigationId = params?.id as string;

  const [detail, setDetail] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("summary");
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
        <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text)", marginBottom: 8 }}>
          {detail?.domain || investigationId}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 20 }}>
          State: {detail?.state || "loading..."}
        </div>
        <Spinner message={`Investigation in progress — ${detail?.state || "gathering"}...`} />
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button
            onClick={fetchData}
            style={{
              padding: "8px 20px", background: "var(--bg-elevated)", border: "none",
              borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
              fontSize: 11, cursor: "pointer", fontFamily: "var(--font-mono)",
            }}
          >
            REFRESH
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
          return evidence ? <TechnicalEvidenceTab evidence={evidence} /> : <NoData label="evidence" />;
        case "findings":
          return report ? <FindingsTab report={report} /> : <NoData label="report" />;
        case "indicators":
          return report ? <IndicatorsTab report={report} /> : <NoData label="report" />;
        case "signals":
          return evidence ? <SignalsTab evidence={evidence} /> : <NoData label="evidence" />;
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
          <div style={{
            fontSize: 22, fontWeight: 800, color: "var(--text)",
            letterSpacing: "0.02em", fontFamily: "var(--font-mono)",
          }}>
            {detail?.domain || evidence?.domain || investigationId}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
            Investigation {String(investigationId).slice(0, 8)}...
            {detail?.concluded_at && ` · Completed ${new Date(detail.concluded_at).toLocaleString()}`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <HeaderButton onClick={() => router.push("/")}>NEW INVESTIGATION</HeaderButton>
          <HeaderButton onClick={() => {
            window.open(`/api/investigations/${investigationId}/export/pdf`, "_blank");
          }}>
            EXPORT PDF
          </HeaderButton>
          <HeaderButton onClick={() => {
            window.open(`/api/investigations/${investigationId}/export/markdown`, "_blank");
          }}>
            EXPORT MD
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
            EXPORT JSON
          </HeaderButton>
          <HeaderButton onClick={fetchData}>REFRESH</HeaderButton>
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
      <TabBar tabs={TABS} active={activeTab} onChange={(id) => setActiveTab(id as TabId)} />

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
        padding: "8px 16px", background: "var(--bg-elevated)", border: "none",
        borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
        fontSize: 10, fontWeight: 600, cursor: "pointer",
        fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
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
              border: "none", borderRadius: "var(--radius-sm)",
              color: view === v ? "#fff" : "var(--text-dim)",
              fontSize: 10, fontWeight: 600, cursor: "pointer",
              fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
              textTransform: "uppercase",
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
