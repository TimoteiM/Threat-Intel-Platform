"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";

import ProgressTimeline from "@/components/investigation/ProgressTimeline";
import CollectorTimingTable from "@/components/investigation/CollectorTimingTable";
import Spinner from "@/components/shared/Spinner";
import TabBar from "@/components/shared/TabBar";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid, { type MetadataItem } from "@/components/ui/MetadataGrid";
import PageHero from "@/components/ui/PageHero";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

import TechnicalEvidenceTab from "@/components/report/TechnicalEvidenceTab";
import FindingsTab from "@/components/report/FindingsTab";
import IndicatorsTab from "@/components/report/IndicatorsTab";
import SignalsTab from "@/components/report/SignalsTab";
import InfrastructureTab from "@/components/report/InfrastructureTab";
import AnyRunProcessGraphTab from "@/components/report/AnyRunProcessGraphTab";
import SocIntelligenceTab from "@/components/report/SocIntelligenceTab";
import AICaseStoryTab from "@/components/report/AICaseStoryTab";

import * as api from "@/lib/api";
import { useSSE } from "@/hooks/useSSE";
import { CollectorStatus } from "@/lib/types";
import completionRefresh from "./completionRefresh";
import { useSettingsPreferences } from "@/components/settings/SettingsPreferencesProvider";

const { shouldTriggerDomainCompletionRefresh } = completionRefresh;

// Full tab set for domain / URL investigations (Claude analysis available)
const DOMAIN_TABS = [
  { id: "case_story", label: "AI Case Story" },
  { id: "intelligence", label: "SOC Intelligence" },
  { id: "evidence", label: "Technical Evidence" },
  { id: "findings", label: "Findings" },
  { id: "indicators", label: "Indicators & Pivots" },
  { id: "signals", label: "Signals & Gaps" },
  { id: "infrastructure", label: "Infrastructure" },
  { id: "anyrun", label: "AnyRun" },
  { id: "raw", label: "Raw JSON" },
] as const;

// Minimal tab set for fast-path types (hash / ip / file)
// No AI-generated narrative - just technical evidence and IOCs.
const FAST_PATH_TABS = [
  { id: "case_story", label: "AI Case Story" },
  { id: "intelligence", label: "SOC Intelligence" },
  { id: "evidence", label: "Technical Evidence" },
  { id: "indicators", label: "Indicators & Pivots" },
] as const;

const FAST_PATH_TYPES = new Set(["hash", "ip", "file"]);
const DEFAULT_COLLECTOR_ORDER = [
  "dns",
  "tls",
  "http",
  "whois",
  "asn",
  "intel",
  "vt",
  "brave_osint",
  "threat_feeds",
  "hybrid_analysis",
  "urlscan",
  "screenshot",
  "js_analysis",
  "opencti",
] as const;

type TabId = "case_story" | "intelligence" | "evidence" | "findings" | "indicators" | "signals" | "infrastructure" | "anyrun" | "raw";

const pageShellStyle: React.CSSProperties = {
  paddingTop: 24,
  paddingBottom: 80,
  display: "grid",
  gap: 18,
};

const progressTrackStyle: React.CSSProperties = {
  height: 12,
  background: "var(--bg-elevated)",
  borderRadius: 999,
  overflow: "hidden",
  border: "1px solid var(--panel-divider-strong)",
};

function shortId(value: string) {
  if (!value) return "-";
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}

function humanizeState(state: string) {
  return String(state || "unknown")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function resolveStateTone(state: string, report: any): "neutral" | "info" | "success" | "warning" | "danger" {
  const normalized = String(state || "").toLowerCase();
  if (normalized === "failed" || normalized === "error") return "danger";
  if (normalized === "cancelled" || normalized === "canceled") return "neutral";
  if (normalized === "concluded") return report ? "success" : "info";
  if (normalized === "evaluating") return "warning";
  if (normalized === "gathering") return "info";
  return "neutral";
}

function stateAccent(state: string) {
  const normalized = String(state || "").toLowerCase();
  if (normalized === "failed" || normalized === "error") return "#fb7185";
  if (normalized === "concluded") return "#38d9a9";
  if (normalized === "evaluating") return "#fbbf24";
  if (normalized === "gathering") return "#66a8ff";
  return "#7891b2";
}

function getInvestigationProgressPct(state: string, ssePercent: number, reportReady: boolean) {
  if (reportReady || state === "concluded") return 100;
  const fallbackPercent =
    state === "created" ? 2 :
    state === "gathering" ? 25 :
    state === "evaluating" ? 75 :
    state === "failed" ? 100 :
    0;
  return Math.max(ssePercent || 0, fallbackPercent);
}

function actionButtonPalette(tone: "neutral" | "info" | "success" | "warning" | "danger") {
  switch (tone) {
    case "danger":
      return {
        foreground: "#fda4af",
        background: "rgba(251, 113, 133, 0.12)",
        border: "rgba(251, 113, 133, 0.28)",
        hoverBackground: "rgba(251, 113, 133, 0.18)",
        hoverBorder: "rgba(251, 113, 133, 0.42)",
      };
    case "success":
      return {
        foreground: "#9bf0d8",
        background: "rgba(56, 217, 169, 0.10)",
        border: "rgba(56, 217, 169, 0.26)",
        hoverBackground: "rgba(56, 217, 169, 0.16)",
        hoverBorder: "rgba(56, 217, 169, 0.40)",
      };
    case "warning":
      return {
        foreground: "#fde68a",
        background: "rgba(251, 191, 36, 0.10)",
        border: "rgba(251, 191, 36, 0.26)",
        hoverBackground: "rgba(251, 191, 36, 0.16)",
        hoverBorder: "rgba(251, 191, 36, 0.40)",
      };
    case "info":
      return {
        foreground: "#bfdbfe",
        background: "rgba(102, 168, 255, 0.10)",
        border: "rgba(102, 168, 255, 0.26)",
        hoverBackground: "rgba(102, 168, 255, 0.16)",
        hoverBorder: "rgba(102, 168, 255, 0.40)",
      };
    case "neutral":
    default:
      return {
        foreground: "var(--text-secondary)",
        background: "rgba(120, 145, 178, 0.08)",
        border: "rgba(120, 145, 178, 0.22)",
        hoverBackground: "rgba(120, 145, 178, 0.12)",
        hoverBorder: "rgba(120, 145, 178, 0.34)",
      };
  }
}

export default function InvestigationPage() {
  const params = useParams();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { settings } = useSettingsPreferences();
  const investigationId = params?.id as string;

  const [detail, setDetail] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [intelligence, setIntelligence] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const observableType = detail?.observable_type || "domain";
  const isFastPath = FAST_PATH_TYPES.has(observableType);
  const tabs = isFastPath ? FAST_PATH_TABS : DOMAIN_TABS;
  const defaultTab: TabId = "case_story";
  const [activeTab, setActiveTab] = useState<TabId>(defaultTab);
  const [tabError, setTabError] = useState<string | null>(null);
  const [canceling, setCanceling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [nowTs, setNowTs] = useState(Date.now());
  const completionRefreshInFlight = React.useRef(false);
  const sse = useSSE(investigationId || null);
  const collectorKeys = React.useMemo(() => {
    const keys = new Set<string>(DEFAULT_COLLECTOR_ORDER as unknown as string[]);
    Object.keys((detail?.collector_statuses || {}) as Record<string, string>).forEach((k) => keys.add(k));
    Object.keys((sse?.collectors || {}) as Record<string, string>).forEach((k) => keys.add(k));
    if (evidence && typeof evidence === "object") {
      if (evidence.dns?.meta) keys.add("dns");
      if (evidence.tls?.meta) keys.add("tls");
      if (evidence.http?.meta) keys.add("http");
      if (evidence.whois?.meta) keys.add("whois");
      if (evidence.hosting?.meta) keys.add("asn");
      if (evidence.intel?.meta) keys.add("intel");
      if (evidence.vt?.meta) keys.add("vt");
      if (evidence.brave_osint?.meta) keys.add("brave_osint");
      if (evidence.threat_feeds?.meta) keys.add("threat_feeds");
      if (evidence.hybrid_analysis?.meta) keys.add("hybrid_analysis");
      if (evidence.urlscan?.meta) keys.add("urlscan");
      if (evidence.opencti?.meta) keys.add("opencti");
    }
    const known = [...DEFAULT_COLLECTOR_ORDER].filter((k) => keys.has(k));
    const extra = Array.from(keys).filter((k) => !DEFAULT_COLLECTOR_ORDER.includes(k as any)).sort();
    return [...known, ...extra];
  }, [detail?.collector_statuses, sse?.collectors, evidence]);

  const collectorRows = collectorKeys.map((c) => {
    const evidenceKey = c === "asn" ? "hosting" : c;
    const evidenceMeta = evidence?.[evidenceKey]?.meta || {};
    const status = (
      sse.collectors[c]
      || detail?.collector_statuses?.[c]
      || evidenceMeta.status
      || "pending"
    ) as CollectorStatus;
    const durationMs = sse.collectorDurations[c] ?? evidenceMeta.duration_ms;
    return { collector: c, status, durationMs };
  });
  const isCancellable = ["created", "gathering", "evaluating"].includes(String(detail?.state || "").toLowerCase());
  const investigationTitle = detail?.domain || evidence?.domain || investigationId;
  const investigationState = String(sse.state || detail?.state || "created");
  const investigationStatusTone = resolveStateTone(investigationState, report);
  const reportReady = Boolean(report);
  const reportFreshness = report?.report_freshness || null;
  const reportWasRecomputed = Boolean(reportFreshness?.recomputed || sse.reportRecomputed);
  const collectorCompleteCount = collectorRows.filter((row) => String(row.status) === "completed").length;
  const collectorFailedCount = collectorRows.filter((row) => String(row.status) === "failed").length;
  const collectorPendingCount = Math.max(0, collectorRows.length - collectorCompleteCount - collectorFailedCount);
  const collectorCoverage = collectorRows.length
    ? Math.round((collectorCompleteCount / collectorRows.length) * 100)
    : 0;
  const currentProgressPct = getInvestigationProgressPct(investigationState, sse.percent || 0, reportReady);
  const stageSummary = sse.message || `Investigation in progress (${investigationState})`;
  const elapsedSec = detail?.created_at
    ? Math.max(0, Math.floor((nowTs - new Date(detail.created_at).getTime()) / 1000))
    : 0;
  const createdLabel = detail?.created_at ? new Date(detail.created_at).toLocaleString() : "-";
  const concludedLabel = detail?.concluded_at ? new Date(detail.concluded_at).toLocaleString() : "-";
  const investigationMetaItems: MetadataItem[] = [
    { label: "Investigation ID", value: shortId(investigationId), hint: "Stable reference for exports and links", mono: true },
    { label: "Observable", value: investigationTitle, hint: "Primary indicator under analysis", mono: true, span: 2 },
    { label: "Observable Type", value: detail?.observable_type || "domain" },
    { label: "State", value: humanizeState(investigationState) },
    { label: "Created", value: createdLabel, hint: elapsedSec ? `${elapsedSec}s elapsed` : "Awaiting start" },
    { label: "Completed", value: concludedLabel, hint: reportReady ? "Report ready" : "Still collecting" },
    { label: "Collector Coverage", value: `${collectorCoverage}%`, hint: `${collectorCompleteCount} completed / ${collectorPendingCount} pending`, tone: reportReady ? "success" : "info" },
    { label: "SSE", value: sse.connected ? "Live" : "Polling", hint: sse.connected ? "Streaming updates" : "Fallback refresh mode", tone: sse.connected ? "success" : "warning" },
    { label: "Report Freshness", value: reportWasRecomputed ? "Recomputed" : reportReady ? "Fresh" : "Pending", hint: reportFreshness?.reason || "Current report state", tone: reportWasRecomputed ? "info" : reportReady ? "success" : "warning" },
  ];

  // Fetch all data
  const fetchData = useCallback(async (options?: { silent?: boolean }) => {
    if (!investigationId) return;
    const silent = Boolean(options?.silent);
    if (!silent) {
      setLoading(true);
    }
    setError(null);

    try {
      const det = await api.getInvestigation(investigationId).catch(() => null);
      setDetail(det);

      const ev = await api.getEvidence(investigationId).catch(() => null);
      setEvidence(ev);

      const rep = await api.getReport(investigationId).catch(() => null);
      setReport(rep);

      const intel = await api.getInvestigationIntelligence(investigationId).catch(() => null);
      setIntelligence(intel);

      if (!silent) {
        setLoading(false);
      }
      return { detail: det, evidence: ev, report: rep, intelligence: intel };
    } catch (e: any) {
      setError(e?.message || "Failed to load");
      if (!silent) {
        setLoading(false);
      }
      return null;
    }
  }, [investigationId]);

  useEffect(() => {
    fetchData();
    if (!settings.investigationAutoRefresh) {
      return;
    }
    // Poll every 5s only when SSE is disconnected (fallback mode).
    const interval = setInterval(() => {
      if (sse.connected) return;
      if (detail?.state === "concluded" || detail?.state === "failed") return;
      fetchData();
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchData, detail?.state, settings.investigationAutoRefresh, sse.connected]);

  useEffect(() => {
    if (!settings.investigationAutoRefresh) {
      return;
    }
    if (!shouldTriggerDomainCompletionRefresh({
      observableType: detail?.observable_type,
      reportReady,
      liveState: sse.state || detail?.state,
      ssePercent: sse.percent || 0,
      sseDone: sse.done,
      refreshInFlight: completionRefreshInFlight.current,
    })) {
      return;
    }

    let cancelled = false;
    completionRefreshInFlight.current = true;

    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    (async () => {
      try {
        for (let attempt = 0; attempt < 5; attempt += 1) {
          const refreshed = await fetchData({ silent: true });
          if (cancelled || refreshed?.report) {
            break;
          }
          await sleep(1000);
        }
      } finally {
        completionRefreshInFlight.current = false;
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    detail?.observable_type,
    detail?.state,
    fetchData,
    reportReady,
    settings.investigationAutoRefresh,
    sse.done,
    sse.percent,
    sse.state,
  ]);

  useEffect(() => {
    if (!sse.evidenceUpdateSeq) return;
    void fetchData({ silent: true });
  }, [fetchData, sse.evidenceUpdateSeq]);

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

  useEffect(() => {
    const timer = setInterval(() => setNowTs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const qTab = String(searchParams?.get("tab") || "").trim();
    if (!qTab) return;
    const validIds = tabs.map((t) => t.id);
    if (validIds.includes(qTab as any)) {
      setActiveTab(qTab as TabId);
    }
  }, [searchParams, tabs]);

  const handleRefresh = useCallback(() => {
    void fetchData();
  }, [fetchData]);

  const handleCancel = useCallback(async () => {
    if (!investigationId || canceling || !isCancellable) return;
    setCancelError(null);
    setCanceling(true);
    try {
      await api.cancelInvestigation(investigationId);
      await fetchData();
    } catch (e: any) {
      setCancelError(e?.message || "Failed to cancel investigation");
    } finally {
      setCanceling(false);
    }
  }, [investigationId, canceling, isCancellable, fetchData]);

  const handleDelete = useCallback(async () => {
    if (!investigationId || deleting) return;
    const label = detail?.domain || investigationId;
    if (!window.confirm(`Delete ${label}? This removes the investigation, evidence, reports, and related artifacts.`)) {
      return;
    }
    setCancelError(null);
    setDeleting(true);
    try {
      await api.deleteInvestigation(investigationId);
      router.push("/investigations");
    } catch (e: any) {
      setCancelError(e?.message || "Failed to delete investigation");
      setDeleting(false);
    }
  }, [investigationId, deleting, detail?.domain, router]);

  const handleOpenAssistant = useCallback(async () => {
    if (!investigationId) return;
    try {
      const linked = await api.createAssistantSessionFromInvestigation(investigationId);
      router.push(`/assistant?session=${linked.id}`);
    } catch (e: any) {
      setCancelError(e?.message || "Failed to open AI Assistant");
    }
  }, [investigationId, router]);

  // ─── Loading state ───
  if (loading && !evidence && !report) {
    return (
      <div style={pageShellStyle}>
        <PageHero
          eyebrow="Investigation Detail"
          title={investigationTitle}
          description="Loading the console shell, collector state, and report workspace."
          status={<StatusPill tone="neutral" mono>Loading</StatusPill>}
          badges={(
            <>
              <StatusPill tone="info" size="sm" outline mono>{humanizeState(investigationState)}</StatusPill>
              <StatusPill tone={sse.connected ? "success" : "warning"} size="sm" outline mono>
                {sse.connected ? "SSE LIVE" : "POLLING"}
              </StatusPill>
            </>
          )}
          stats={(
            <>
              <SignalCard label="Progress" value={`${currentProgressPct}%`} caption="Preparing the investigation view" tone="info" compact />
              <SignalCard label="Collectors" value={collectorRows.length} caption="Configured collector channels" tone="neutral" compact />
              <SignalCard label="Report" value={reportReady ? "Ready" : "Pending"} caption="Narrative layer and exports" tone={reportReady ? "success" : "warning"} compact />
              <SignalCard label="Elapsed" value={`${elapsedSec}s`} caption="Time since submission" tone="neutral" compact />
            </>
          )}
        />
        <div style={{ marginTop: 22 }}>
          <ConsoleModule eyebrow="Console" title="Investigative workspace" description="The detail shell is assembling the shared analyst view.">
            <div style={{ display: "grid", gap: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
                <Spinner message="Loading investigation..." />
                <div style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.7 }}>
                  Establishing live state, collector coverage, and report context.
                </div>
              </div>
              <MetadataGrid items={investigationMetaItems} compact />
            </div>
          </ConsoleModule>
        </div>
      </div>
    );
  }

  // ─── Waiting for results ───
  if (!report && detail?.state !== "concluded" && detail?.state !== "failed" && detail?.state !== "cancelled") {
    const liveState = sse.state || detail?.state || "created";
    const fallbackPercent =
      liveState === "created" ? 2 :
      liveState === "gathering" ? 25 :
      liveState === "evaluating" ? 75 :
      liveState === "concluded" ? 100 :
      liveState === "failed" ? 100 : 0;
    const progressPct = Math.max(sse.percent || 0, fallbackPercent);
    const stageText = sse.message || `Investigation in progress (${liveState})`;
    const elapsedSec = detail?.created_at
      ? Math.max(0, Math.floor((nowTs - new Date(detail.created_at).getTime()) / 1000))
      : 0;
    const steps = [
      { key: "queued", label: "Queued", done: true, active: liveState === "created" },
      { key: "collectors", label: "Collectors Running", done: ["evaluating", "concluded", "failed"].includes(liveState), active: liveState === "gathering" },
      { key: "correlation", label: "Evidence Correlation", done: ["concluded", "failed"].includes(liveState), active: liveState === "evaluating" },
      { key: "analyst", label: "Analyst Decision", done: ["concluded", "failed"].includes(liveState), active: liveState === "evaluating" && /analyst/i.test(stageText) },
      { key: "complete", label: "Completed", done: ["concluded", "failed"].includes(liveState), active: ["concluded", "failed"].includes(liveState) },
    ];

    return (
      <div style={pageShellStyle}>
        <PageHero
          eyebrow="Investigation Detail"
          title={investigationTitle}
          description={(
            <>
              <span>Live collection is still in flight.</span>
              <span style={{ marginLeft: 8, color: "var(--text-dim)" }}>
                {investigationState === "created" ? "Queued" : humanizeState(investigationState)} | SSE {sse.connected ? "live" : "reconnecting"} | {elapsedSec}s elapsed
              </span>
            </>
          )}
          status={<StatusPill tone={investigationStatusTone} mono>{humanizeState(investigationState)}</StatusPill>}
          badges={(
            <>
              <StatusPill tone={sse.connected ? "success" : "warning"} size="sm" outline mono>
                {sse.connected ? "SSE LIVE" : "POLLING"}
              </StatusPill>
              <StatusPill tone={reportReady ? "success" : "warning"} size="sm" outline mono>
                {reportReady ? "REPORT READY" : "COLLECTING"}
              </StatusPill>
            </>
          )}
          actions={(
            <>
              <ConsoleActionButton onClick={handleRefresh}>Refresh</ConsoleActionButton>
              {isCancellable ? (
                <ConsoleActionButton onClick={handleCancel} tone="danger" disabled={canceling}>
                  {canceling ? "Cancelling..." : "Cancel Investigation"}
                </ConsoleActionButton>
              ) : null}
            </>
          )}
          stats={(
            <>
              <SignalCard label="Progress" value={String(currentProgressPct) + "%"} caption={stageSummary} tone={investigationStatusTone} accent={stateAccent(investigationState)} compact />
              <SignalCard label="Stage" value={humanizeState(investigationState)} caption="Current orchestration state" tone={investigationStatusTone} compact />
              <SignalCard label="Collectors" value={collectorRows.length} caption={String(collectorCompleteCount) + " complete / " + String(collectorPendingCount) + " pending"} tone="info" compact />
              <SignalCard label="Coverage" value={String(collectorCoverage) + "%"} caption="Collector completion ratio" tone={collectorCoverage >= 75 ? "success" : "warning"} compact />
            </>
          )}
        />
        <MetadataGrid items={investigationMetaItems} title="Investigation Snapshot" eyebrow="Structured metadata" description="The shared console surface summarizes the active investigation before you enter the detailed tabs." />
        <div style={consoleSectionSpacing}>
          <div style={consoleGridStyle}>
            <ConsoleModule
              eyebrow="Pipeline"
              title="Investigation progress"
              description="Collectors are still running and the narrative layer has not finalized yet."
              tone={investigationStatusTone}
              variant="glass"
            >
              <div style={{ display: "grid", gap: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={consoleLabelStyle}>Progress</span>
                  <StatusPill tone={investigationStatusTone} mono>{progressPct}%</StatusPill>
                </div>
                <div style={progressTrackStyle}>
                  <div
                    style={{
                      ...progressBarStyle,
                      width: `${progressPct}%`,
                      background: liveState === "failed"
                        ? "linear-gradient(90deg, #ef4444, #f87171)"
                        : "linear-gradient(90deg, var(--accent), #34d399)",
                    }}
                  />
                </div>
                <div style={consoleBodyStyle}>{stageText}</div>
              </div>
            </ConsoleModule>
            <ConsoleModule
              eyebrow="Stages"
              title="Execution path"
              description="A quick read on where the orchestration currently sits."
              tone="info"
              variant="dense"
            >
              <div style={{ display: "grid", gap: 10 }}>
                {steps.map((step) => (
                  <div key={step.key} style={stageRowStyle(step.active, step.done)}>
                    <span style={stageIconStyle(step.active, step.done)}>{step.done ? "Done" : step.active ? "Live" : "Pending"}</span>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>{step.label}</span>
                  </div>
                ))}
              </div>
            </ConsoleModule>
          </div>
          <ConsoleModule
            eyebrow="Telemetry"
            title="Collector timings"
            description="Live collector timing stays visible while the investigation is still in progress."
            variant="solid"
            tone="info"
          >
            <CollectorTimingTable
              rows={collectorRows}
              totalDurationMs={sse.totalElapsedMs ?? (elapsedSec * 1000)}
              live={true}
              title="Collector Timings"
            />
          </ConsoleModule>
          {cancelError ? <div style={inlineErrorStyle}>{cancelError}</div> : null}
        </div>
        {false && <div style={{ paddingTop: 24 }}>
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
          State: {liveState} | Elapsed: {elapsedSec}s | SSE: {sse.connected ? "live" : "reconnecting"}
        </div>
        <div style={{
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: "var(--bg-card)",
          padding: 16,
          marginBottom: 14,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>Progress</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{progressPct}%</span>
          </div>
          <div style={{ height: 10, background: "var(--bg-input)", borderRadius: 999, overflow: "hidden", border: "1px solid var(--border)" }}>
            <div style={{
              height: "100%",
              width: `${progressPct}%`,
              background: liveState === "failed"
                ? "linear-gradient(90deg, #ef4444, #f87171)"
                : "linear-gradient(90deg, var(--accent), #34d399)",
              transition: "width 400ms ease",
            }} />
          </div>
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text)" }}>{stageText}</div>
        </div>
        <div style={{
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: "var(--bg-card)",
          padding: 12,
          marginBottom: 14,
        }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600, marginBottom: 8 }}>
            Investigation Stages
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            {steps.map((step) => (
              <div key={step.key} style={{ fontSize: 12, color: step.active ? "var(--accent)" : step.done ? "var(--green)" : "var(--text-muted)" }}>
                {step.done ? "✓" : step.active ? "●" : "○"} {step.label}
              </div>
            ))}
          </div>
        </div>
        <CollectorTimingTable
          rows={collectorRows}
          totalDurationMs={sse.totalElapsedMs ?? (elapsedSec * 1000)}
          live={true}
          title="Collector Timings"
        />
        <div style={{ textAlign: "center", marginTop: 16 }}>
          {cancelError && (
            <div style={{ color: "#f87171", fontSize: 12, marginBottom: 8 }}>{cancelError}</div>
          )}
          <button
            onClick={handleRefresh}
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
          {isCancellable && (
            <button
              onClick={handleCancel}
              disabled={canceling}
              style={{
                marginLeft: 10,
                padding: "8px 20px",
                background: "rgba(239,68,68,0.12)",
                border: "1px solid rgba(239,68,68,0.35)",
                borderRadius: "var(--radius-sm)",
                color: "#fca5a5",
                fontSize: 12,
                cursor: canceling ? "not-allowed" : "pointer",
                fontFamily: "var(--font-sans)",
                fontWeight: 600,
              }}
            >
              {canceling ? "Cancelling..." : "Cancel Investigation"}
            </button>
          )}
        </div>
        </div>}
      </div>
    );
  }

  // ─── Render active tab with error catching ───
  function renderTab() {
    try {
      switch (activeTab) {
        case "case_story":
          return report ? <AICaseStoryTab investigationId={investigationId} initialStory={report?.ai_case_story} /> : <NoData label="completed report" />;
        case "intelligence":
          return <SocIntelligenceTab intelligence={intelligence} report={report} evidence={evidence} detail={detail} loading={!intelligence && !evidence && !report} />;
        case "evidence":
          return evidence ? <TechnicalEvidenceTab evidence={evidence} domain={detail?.domain} observableType={detail?.observable_type} investigationId={investigationId} onRefresh={() => fetchData({ silent: true })} /> : <NoData label="evidence" />;
        case "findings":
          return report ? <FindingsTab report={report} evidence={evidence} /> : <NoData label="report" />;
        case "indicators":
          return report ? <IndicatorsTab report={report} investigationId={investigationId} /> : <NoData label="report" />;
        case "signals":
          return evidence ? <SignalsTab evidence={evidence} /> : <NoData label="evidence" />;
        case "infrastructure":
          return <InfrastructureTab investigationId={investigationId} evidence={evidence} />;
        case "anyrun":
          return <AnyRunProcessGraphTab evidence={evidence || {}} />;
        case "raw":
          return <RawJsonView evidence={evidence} report={report} detail={detail} intelligence={intelligence} />;
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
    <div style={pageShellStyle}>
      <PageHero
        eyebrow="Investigation Detail"
        title={investigationTitle}
        description={(
          <>
            <span>Threat Analyst Console view for the active investigation.</span>
            <span style={{ marginLeft: 8, color: "var(--text-dim)" }}>
              {shortId(investigationId)} | {createdLabel}{detail?.concluded_at ? " | Completed " + concludedLabel : ""}
            </span>
          </>
        )}
        status={<StatusPill tone={investigationStatusTone} mono>{humanizeState(investigationState)}</StatusPill>}
        badges={(
          <>
            {detail?.observable_type && detail.observable_type !== "domain" ? (
              <StatusPill tone="info" size="sm" outline mono>{detail.observable_type}</StatusPill>
            ) : null}
            {report?.ai_model ? (
              <StatusPill
                tone={String(report.ai_model).startsWith("claude-") ? "warning" : "info"}
                size="sm" outline mono
              >
                {String(report.ai_model).startsWith("claude-sonnet") ? "Sonnet 4.6"
                  : String(report.ai_model).startsWith("claude-haiku") ? "Haiku 4.5"
                  : report.ai_model === "gpt-5.6-luna" ? "GPT-5.6 Luna"
                  : String(report.ai_model).startsWith("claude-opus") ? "Opus 4.6"
                  : String(report.ai_model).replace(" (default)", "")}
              </StatusPill>
            ) : null}
            <StatusPill tone={sse.connected ? "success" : "warning"} size="sm" outline mono>
              {sse.connected ? "SSE LIVE" : "POLLING"}
            </StatusPill>
            <StatusPill tone={reportReady ? "success" : "warning"} size="sm" outline mono>
              {reportReady ? "REPORT READY" : "COLLECTING"}
            </StatusPill>
            {reportWasRecomputed ? (
              <StatusPill tone="info" size="sm" outline mono>RECOMPUTED</StatusPill>
            ) : null}
          </>
        )}
        actions={(
          <>
            <ConsoleActionButton onClick={() => router.push("/")}>New Investigation</ConsoleActionButton>
            <ConsoleActionButton onClick={() => { void handleOpenAssistant(); }}>Open in AI Assistant</ConsoleActionButton>
            {isCancellable ? (
              <ConsoleActionButton onClick={handleCancel} tone="danger" disabled={canceling}>
                {canceling ? "Cancelling..." : "Cancel"}
              </ConsoleActionButton>
            ) : null}
            <ConsoleActionButton onClick={handleDelete} tone="danger" disabled={deleting}>
              {deleting ? "Deleting..." : "Delete"}
            </ConsoleActionButton>
            <ConsoleActionButton onClick={() => { window.open("/api/investigations/" + investigationId + "/export/pdf", "_blank"); }}>Export PDF</ConsoleActionButton>
            <ConsoleActionButton onClick={() => { window.open("/api/investigations/" + investigationId + "/export/markdown", "_blank"); }}>Export MD</ConsoleActionButton>
            <ConsoleActionButton onClick={() => {
              const blob = new Blob([JSON.stringify({ evidence, report, detail }, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = (detail?.domain || "investigation") + "-full.json";
              a.click();
              URL.revokeObjectURL(url);
            }}>
              Export JSON
            </ConsoleActionButton>
            <ConsoleActionButton onClick={handleRefresh}>Refresh</ConsoleActionButton>
          </>
        )}
        stats={(
          <>
            <SignalCard label="Progress" value={reportReady ? "100%" : String(currentProgressPct) + "%"} caption={reportReady ? "Investigation complete" : stageSummary} tone={investigationStatusTone} accent={stateAccent(investigationState)} compact />
            <SignalCard label="Collectors" value={collectorRows.length} caption={String(collectorCompleteCount) + " complete / " + String(collectorPendingCount) + " pending"} tone="info" compact />
            <SignalCard label="Coverage" value={String(collectorCoverage) + "%"} caption="Collector completion ratio" tone={collectorCoverage >= 75 ? "success" : "warning"} compact />
            <SignalCard label="Workspace" value={tabs.length} caption="Available report sections" tone="neutral" compact />
          </>
        )}
      />
      <MetadataGrid items={investigationMetaItems} title="Investigation Snapshot" eyebrow="Structured metadata" description="The shared console surface summarizes the active investigation before you enter the detailed tabs." />
      <div style={consoleSectionSpacing}>
        {cancelError ? <div style={inlineErrorStyle}>{cancelError}</div> : null}

        {evidence ? (
          <div style={consoleGridStyle}>
            <ConsoleModule
              eyebrow="Pipeline"
              title="Collector progress"
              description="A compact execution view before you enter the detailed report sections."
              tone="info"
              variant="glass"
            >
              <ProgressTimeline
                collectors={Object.fromEntries(
                  collectorKeys.map((c) => {
                    const evidenceKey = c === "asn" ? "hosting" : c;
                    const collectorData = evidence?.[evidenceKey];
                    const status = collectorData?.meta?.status || (collectorData ? "completed" : "pending");
                    return [c, status];
                  })
                )}
                analystDone={!!report}
              />
            </ConsoleModule>
            <ConsoleModule
              eyebrow="Timing"
              title="Collector timings"
              description="Wall-clock timing for each collection stage."
              tone="neutral"
              variant="solid"
            >
              <CollectorTimingTable
                rows={collectorRows}
                totalDurationMs={
                  detail?.created_at && detail?.concluded_at
                    ? Math.max(0, new Date(detail.concluded_at).getTime() - new Date(detail.created_at).getTime())
                    : undefined
                }
                title="Collector Timings"
              />
            </ConsoleModule>
          </div>
        ) : null}

        <ConsoleModule
          eyebrow="Report Workspace"
          title="Analysis tabs"
          description="Navigate the executive summary, evidence, findings, pivots, and raw data from a single investigation shell."
          tone="info"
          variant="glass"
        >
          <TabBar tabs={tabs} active={activeTab} onChange={(id) => setActiveTab(id as TabId)} />
          <ErrorBoundary key={activeTab} fallback={activeTab} onRaw={() => setActiveTab("raw")}>
            {renderTab()}
          </ErrorBoundary>
        </ConsoleModule>
      </div>
      {false && <div style={{ paddingTop: 24, paddingBottom: 80 }}>
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
            {detail?.concluded_at && ` | Completed ${new Date(detail.concluded_at).toLocaleString()}`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <HeaderButton onClick={() => router.push("/")}>New Investigation</HeaderButton>
          <HeaderButton onClick={() => { void handleOpenAssistant(); }}>
            Open in AI Assistant
          </HeaderButton>
          {isCancellable && (
            <HeaderButton onClick={handleCancel}>
              {canceling ? "Cancelling..." : "Cancel"}
            </HeaderButton>
          )}
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
          <HeaderButton onClick={handleRefresh}>Refresh</HeaderButton>
        </div>
      </div>
      {cancelError && (
        <div style={{ color: "#f87171", fontSize: 12, marginBottom: 10 }}>{cancelError}</div>
      )}

      {/* Collector progress */}
      {evidence && (
        <>
          <ProgressTimeline
            collectors={Object.fromEntries(
              collectorKeys
                .map((c) => {
                  const evidenceKey = c === "asn" ? "hosting" : c;
                  const collectorData = evidence?.[evidenceKey];
                  const status = collectorData?.meta?.status || (collectorData ? "completed" : "pending");
                  return [c, status];
                })
            )}
            analystDone={!!report}
          />
          <CollectorTimingTable
            rows={collectorRows}
            totalDurationMs={
              detail?.created_at && detail?.concluded_at
                ? Math.max(0, new Date(detail.concluded_at).getTime() - new Date(detail.created_at).getTime())
                : undefined
            }
            title="Collector Timings"
          />
        </>
      )}

      {/* Tabs */}
      <TabBar tabs={tabs} active={activeTab} onChange={(id) => setActiveTab(id as TabId)} />

      {/* Tab content wrapped in ErrorBoundary */}
      <ErrorBoundary key={activeTab} fallback={activeTab} onRaw={() => setActiveTab("raw")}>
        {renderTab()}
      </ErrorBoundary>
    </div>}
    </div>
  );
}

// ─── Helper Components ───

function ConsoleActionButton({ onClick, children, tone = "neutral", disabled = false }: { onClick: () => void; children: React.ReactNode; tone?: "neutral" | "info" | "success" | "warning" | "danger"; disabled?: boolean }) {
  const palette = actionButtonPalette(tone);

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: "8px 14px",
        background: disabled ? "rgba(120, 145, 178, 0.08)" : palette.background,
        border: `1px solid ${disabled ? "rgba(120, 145, 178, 0.12)" : palette.border}`,
        borderRadius: 12,
        color: disabled ? "var(--text-muted)" : palette.foreground,
        fontSize: 12,
        fontWeight: 700,
        cursor: disabled ? "not-allowed" : "pointer",
        fontFamily: "var(--font-sans)",
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        boxShadow: disabled ? "none" : "0 12px 24px rgba(3, 8, 20, 0.16)",
        transition: "transform 120ms ease, border-color 120ms ease, background 120ms ease, color 120ms ease",
      }}
      onMouseEnter={(e) => {
        if (disabled) return;
        e.currentTarget.style.transform = "translateY(-1px)";
        e.currentTarget.style.background = palette.hoverBackground;
        e.currentTarget.style.borderColor = palette.hoverBorder;
      }}
      onMouseLeave={(e) => {
        if (disabled) return;
        e.currentTarget.style.transform = "translateY(0)";
        e.currentTarget.style.background = palette.background;
        e.currentTarget.style.borderColor = palette.border;
      }}
    >
      {children}
    </button>
  );
}

function HeaderButton(props: { onClick: () => void; children: React.ReactNode }) {
  return <ConsoleActionButton onClick={props.onClick}>{props.children}</ConsoleActionButton>;
}

const consoleSectionSpacing: React.CSSProperties = {
  display: "grid",
  gap: 18,
};

const consoleGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
  gap: 18,
  alignItems: "start",
};

const consoleLabelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
};

const consoleBodyStyle: React.CSSProperties = {
  fontSize: 13,
  lineHeight: 1.7,
  color: "var(--text-secondary)",
};

const progressBarStyle: React.CSSProperties = {
  height: "100%",
  transition: "width 400ms ease",
};

function stageRowStyle(active: boolean, done: boolean): React.CSSProperties {
  return {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "10px 12px",
    borderRadius: 14,
    border: `1px solid ${
      active
        ? "rgba(102, 168, 255, 0.28)"
        : done
        ? "rgba(56, 217, 169, 0.24)"
        : "rgba(120, 145, 178, 0.16)"
    }`,
    background: active
      ? "rgba(102, 168, 255, 0.10)"
      : done
      ? "rgba(56, 217, 169, 0.08)"
      : "var(--panel-empty-bg)",
    color: active ? "#bfdbfe" : done ? "#9bf0d8" : "var(--text-secondary)",
  };
}

function stageIconStyle(active: boolean, done: boolean): React.CSSProperties {
  return {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    minWidth: 58,
    padding: "4px 10px",
    borderRadius: 999,
    fontSize: 10,
    fontWeight: 800,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    color: active ? "#bfdbfe" : done ? "#9bf0d8" : "var(--text-dim)",
    background: active
      ? "rgba(102, 168, 255, 0.12)"
      : done
      ? "rgba(56, 217, 169, 0.12)"
      : "rgba(120, 145, 178, 0.08)",
  };
}

const inlineErrorStyle: React.CSSProperties = {
  color: "#fda4af",
  fontSize: 12,
  fontWeight: 600,
  padding: "12px 14px",
  borderRadius: 14,
  border: "1px solid rgba(251, 113, 133, 0.24)",
  background: "rgba(251, 113, 133, 0.10)",
};

function NoData({ label }: { label: string }) {
  return (
    <div style={{ padding: 40, textAlign: "center" }}>
      <div style={{ fontSize: 13, color: "var(--text-dim)" }}>
        No {label} data available yet.
      </div>
    </div>
  );
}

function RawJsonView({ evidence, report, detail, intelligence }: { evidence: any; report: any; detail: any; intelligence?: any }) {
  const [view, setView] = useState<"evidence" | "report" | "detail" | "intelligence">("evidence");

  const data = view === "evidence" ? evidence : view === "report" ? report : view === "intelligence" ? intelligence : detail;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["evidence", "report", "intelligence", "detail"] as const).map((v) => (
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
