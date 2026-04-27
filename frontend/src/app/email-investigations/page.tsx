"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  cancelEmailInvestigationRun,
  getEmailInvestigationRun,
  getEmailInvestigationHistoryItem,
  listEmailInvestigationHistory,
  uploadEmailInvestigation,
} from "@/lib/api";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid from "@/components/ui/MetadataGrid";
import PageHero from "@/components/ui/PageHero";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";
import type {
  EmailInvestigationHistoryItem,
  EmailInvestigationResponse,
  EmailInvestigationSubmitResponse,
} from "@/lib/types";

export default function EmailInvestigationsPage() {
  const HISTORY_PAGE_SIZE = 20;
  const HISTORY_CLASSIFICATIONS = ["all", "malicious", "suspicious", "benign", "inconclusive", "unknown"] as const;
  const [file, setFile] = useState<File | null>(null);
  const [context, setContext] = useState("");
  const [mlScore, setMlScore] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [loadingHistoryItemId, setLoadingHistoryItemId] = useState<string | null>(null);
  const [cancelingRunId, setCancelingRunId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [result, setResult] = useState<EmailInvestigationResponse | null>(null);
  const [historyItems, setHistoryItems] = useState<EmailInvestigationHistoryItem[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);
  const [historySearch, setHistorySearch] = useState("");
  const [historySearchQuery, setHistorySearchQuery] = useState("");
  const [historyClassification, setHistoryClassification] = useState<string>("all");
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [includeScreenshots, setIncludeScreenshots] = useState(false);
  const [runAnyRun, setRunAnyRun] = useState(true);
  const [activeResultTab, setActiveResultTab] = useState<"summary" | "indicators" | "anyrun">("summary");
  const [runAiInterpretation, setRunAiInterpretation] = useState(true);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [loadingStartedAt, setLoadingStartedAt] = useState<number | null>(null);
  const [loadingNow, setLoadingNow] = useState<number>(Date.now());
  const historySearchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [anyrunPages, setAnyrunPages] = useState({
    domains: 1,
    hosts: 1,
    urls: 1,
    files: 1,
  });

  useEffect(() => {
    if (!loading) return;
    const timer = setInterval(() => setLoadingNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, [loading]);

  const loadingElapsedSec = useMemo(() => {
    if (!loading || !loadingStartedAt) return 0;
    return Math.max(0, Math.floor((loadingNow - loadingStartedAt) / 1000));
  }, [loading, loadingNow, loadingStartedAt]);

  const progressModel = useMemo(() => {
    const steps = [
      { key: "upload", label: "Uploading email file", weight: 1 },
      { key: "parse", label: "Parsing email and extracting indicators", weight: 2 },
      { key: "ip", label: "Checking sender IP in VT and AbuseIPDB", weight: 2 },
      { key: "url", label: "Checking URLs in VirusTotal", weight: 3 },
      { key: "attachment", label: "Checking attachment hashes in VirusTotal", weight: 3 },
      ...(runAnyRun ? [{ key: "sandbox", label: "Checking Any.Run intelligence/sandbox", weight: 4 }] : []),
      ...(includeScreenshots ? [{ key: "screenshot", label: "Capturing URL destination screenshots", weight: 5 }] : []),
      ...(runAiInterpretation ? [{ key: "ai", label: "Generating final AI interpretation", weight: 6 }] : []),
      { key: "finalize", label: "Finalizing investigation results", weight: 1 },
    ];

    const totalWeight = steps.reduce((sum, s) => sum + s.weight, 0);
    const expectedSeconds = totalWeight * 2.2;
    const progressedWeight = Math.min(totalWeight * 0.95, (loadingElapsedSec / Math.max(1, expectedSeconds)) * totalWeight);
    const percent = Math.max(2, Math.min(95, Math.round((progressedWeight / totalWeight) * 100)));

    let cursor = 0;
    let activeIndex = 0;
    for (let i = 0; i < steps.length; i += 1) {
      cursor += steps[i].weight;
      if (progressedWeight <= cursor) {
        activeIndex = i;
        break;
      }
      activeIndex = i;
    }
    return {
      steps,
      percent,
      activeIndex,
      stageText: steps[activeIndex]?.label || "Running investigation",
    };
  }, [includeScreenshots, runAnyRun, runAiInterpretation, loadingElapsedSec]);

  const domainFindings = useMemo(
    () => buildSenderDomainFindings(result),
    [result],
  );
  const urlSummary = useMemo(
    () => buildUrlSummary(result),
    [result],
  );
  const anyrunArtifacts = useMemo(
    () => buildAnyRunEmailArtifacts(result),
    [result],
  );
  const anyrunPageSize = 8;
  const selectedHistoryItem = selectedHistoryId
    ? historyItems.find((item) => item.id === selectedHistoryId) || null
    : null;
  const workflowTone = loading ? "warning" : error ? "danger" : result ? "success" : "info";
  const workflowLabel = loading ? "Processing" : error ? "Attention needed" : result ? "Results ready" : "Awaiting sample";
  const fileLabel = file?.name || "No file selected";
  const fileStateLabel = file ? "File staged" : "No sample loaded";
  const historyActiveCount = historyItems.filter((item) =>
    ["queued", "processing", "running"].includes(String(item.status || "").toLowerCase()),
  ).length;
  const progressTone = loading ? "warning" : activeRunId ? "info" : "neutral";
  const historyPages = Math.max(1, Math.ceil(historyTotal / HISTORY_PAGE_SIZE));
  const historyShowingFrom = historyTotal === 0 ? 0 : historyPage * HISTORY_PAGE_SIZE + 1;
  const historyShowingTo = Math.min((historyPage + 1) * HISTORY_PAGE_SIZE, historyTotal);

  useEffect(() => {
    setAnyrunPages({
      domains: 1,
      hosts: 1,
      urls: 1,
      files: 1,
    });
  }, [result?.run_id, result?.history_id, result?.created_at]);

  useEffect(() => {
    return () => {
      if (historySearchTimer.current) clearTimeout(historySearchTimer.current);
    };
  }, []);

  async function refreshHistory() {
    setLoadingHistory(true);
    try {
      const res = await listEmailInvestigationHistory({
        limit: HISTORY_PAGE_SIZE,
        offset: historyPage * HISTORY_PAGE_SIZE,
        search: historySearchQuery || undefined,
        classification: historyClassification !== "all" ? historyClassification : undefined,
      });
      setHistoryItems((res?.items || []) as EmailInvestigationHistoryItem[]);
      setHistoryTotal(Number(res?.total || 0));
    } catch {
      // Keep page usable even if history fetch fails.
      setHistoryTotal(0);
    } finally {
      setLoadingHistory(false);
    }
  }

  useEffect(() => {
    refreshHistory();
  }, [historyPage, historySearchQuery, historyClassification]);

  async function openHistoryItem(id: string) {
    setLoadingHistoryItemId(id);
    setSelectedHistoryId(id);
    setError("");
    try {
      const item = await getEmailInvestigationHistoryItem(id);
      setResult(item as EmailInvestigationResponse);
    } catch (err: any) {
      setError(err?.message || "Failed to load history item");
    } finally {
      setLoadingHistoryItemId(null);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setLoadingStartedAt(Date.now());
    setError("");
    setResult(null);
    try {
      const submit = (await uploadEmailInvestigation(file, {
        context: context || undefined,
        max_urls: 20,
        include_url_screenshots: includeScreenshots,
        run_anyrun: runAnyRun,
        run_ai: runAiInterpretation,
        ml_phishing_score: mlScore.trim() ? Number(mlScore) : undefined,
      })) as EmailInvestigationSubmitResponse;
      setActiveRunId(submit.run_id || null);
      setSelectedHistoryId(submit.run_id || null);

      const pollDeadline = Date.now() + 15 * 60 * 1000;
      let completedRun: EmailInvestigationResponse | null = null;
      while (Date.now() < pollDeadline) {
        const run = (await getEmailInvestigationRun(submit.run_id)) as EmailInvestigationResponse;
        if (run.status === "completed") {
          completedRun = run;
          setResult(run);
          break;
        }
        if (run.status === "failed") {
          throw new Error(run.error || "Email investigation failed");
        }
        if (run.status === "cancelled") {
          setResult(run);
          completedRun = run;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      if (!completedRun) {
        const latest = (await getEmailInvestigationRun(submit.run_id)) as EmailInvestigationResponse;
        if (latest.status === "completed" || latest.status === "cancelled") {
          setResult(latest);
        } else {
          throw new Error("Email investigation is still processing. Please refresh history shortly.");
        }
      }

      await refreshHistory();
    } catch (err: any) {
      setError(err?.message || "Upload failed");
    } finally {
      setLoading(false);
      setLoadingStartedAt(null);
      setActiveRunId(null);
    }
  }

  async function cancelRun(runId: string) {
    if (!runId || cancelingRunId) return;
    setCancelingRunId(runId);
    setError("");
    try {
      await cancelEmailInvestigationRun(runId);
      if (activeRunId === runId) {
        setLoading(false);
        setLoadingStartedAt(null);
        setActiveRunId(null);
      }
      await refreshHistory();
      if (selectedHistoryId === runId) {
        const item = await getEmailInvestigationRun(runId);
        setResult(item as EmailInvestigationResponse);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to cancel investigation");
    } finally {
      setCancelingRunId(null);
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedText(text);
      setTimeout(() => setCopiedText(null), 1800);
    }).catch(() => {});
  }

  const shellFieldStyle: React.CSSProperties = {
    display: "grid",
    gap: 10,
    padding: 14,
    borderRadius: 18,
    border: "1px solid rgba(120, 145, 178, 0.16)",
    background: "linear-gradient(180deg, rgba(16, 26, 44, 0.92), rgba(11, 17, 29, 0.98))",
  };
  const shellLabelStyle: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 800,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    color: "var(--text-dim)",
  };
  const shellInputStyle: React.CSSProperties = {
    width: "100%",
    background: "var(--bg-input)",
    border: "1px solid var(--border)",
    color: "var(--text)",
    borderRadius: 14,
    padding: "11px 12px",
    fontSize: 13,
    outline: "none",
  };
  const shellTextAreaStyle: React.CSSProperties = {
    ...shellInputStyle,
    resize: "vertical",
    minHeight: 112,
  };
  const shellCheckboxStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "flex-start",
    gap: 10,
    color: "var(--text-secondary)",
    fontSize: 13,
    lineHeight: 1.6,
    padding: "10px 12px",
    borderRadius: 14,
    border: "1px solid rgba(120, 145, 178, 0.12)",
    background: "rgba(9, 15, 26, 0.42)",
  };

  return (
    <div style={{ paddingTop: 18, paddingBottom: 44, display: "grid", gap: 18 }}>
      <PageHero
        eyebrow="Threat Analyst Console"
        title="Email Investigation"
        description="Upload an .eml or .msg sample, inspect prior runs, and follow the workflow from intake through verdict in a single console surface."
        status={<StatusPill tone={workflowTone} mono>{workflowLabel}</StatusPill>}
        badges={
          <>
            <StatusPill tone={historyActiveCount ? "warning" : "neutral"} outline mono>{`${historyItems.length} history`}</StatusPill>
            {historyClassification !== "all" ? <StatusPill tone={historyClassification === "malicious" ? "danger" : historyClassification === "suspicious" ? "warning" : historyClassification === "benign" ? "success" : "neutral"} outline mono>{historyClassification}</StatusPill> : null}
            <StatusPill tone={runAnyRun ? "success" : "neutral"} outline mono>{runAnyRun ? "AnyRun on" : "AnyRun off"}</StatusPill>
            <StatusPill tone={runAiInterpretation ? "info" : "neutral"} outline mono>{runAiInterpretation ? "AI on" : "AI off"}</StatusPill>
          </>
        }
        stats={
          <>
            <SignalCard
              label="History"
              value={historyTotal}
              caption={selectedHistoryItem ? selectedHistoryItem.email_subject || selectedHistoryItem.filename || "Selected run loaded" : "Archived investigations available"}
              tone={historyTotal ? "info" : "neutral"}
              compact
            />
            <SignalCard
              label="Upload"
              value={file ? "Ready" : "Idle"}
              caption={fileLabel}
              tone={file ? "success" : "neutral"}
              compact
            />
            <SignalCard
              label="Progress"
              value={loading ? `${progressModel.percent}%` : activeRunId ? "Polling" : "Standby"}
              caption={loading ? progressModel.stageText : activeRunId ? "Monitoring the live run" : "No active investigation"}
              tone={progressTone}
              compact
            />
            <SignalCard
              label="Results"
              value={result ? "Loaded" : error ? "Attention" : "Waiting"}
              caption={result ? result.email_subject || "Latest analysis available" : error || "Open a sample to populate the report pane"}
              tone={result ? "success" : error ? "danger" : "neutral"}
              compact
            />
          </>
        }
        actions={
          <button
            type="button"
            onClick={refreshHistory}
            style={{
              background: "rgba(96,165,250,0.12)",
              border: "1px solid rgba(96,165,250,0.28)",
              color: "var(--text-strong)",
              borderRadius: "999px",
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              padding: "8px 12px",
              cursor: "pointer",
            }}
          >
            {loadingHistory ? "Refreshing..." : "Refresh history"}
          </button>
        }
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16, alignItems: "start" }}>
        <ConsoleModule
          eyebrow="Archive"
          title="History"
          description="Recent runs and live cancel controls. Open a previous run to repopulate the result pane."
          tone="info"
          actions={<StatusPill tone={historyTotal ? "info" : "neutral"} outline mono>{`${historyTotal} records`}</StatusPill>}
        >
          <MetadataGrid
            compact
            columns={2}
            items={[
              { label: "Total", value: historyTotal, tone: "info", mono: true },
              { label: "Active", value: historyActiveCount, tone: historyActiveCount ? "warning" : "neutral", mono: true },
              { label: "Selected", value: selectedHistoryItem ? selectedHistoryItem.email_subject || selectedHistoryItem.filename || selectedHistoryItem.id : "None", tone: selectedHistoryItem ? "success" : "neutral" },
              { label: "Classification", value: historyClassification === "all" ? "All" : historyClassification, tone: historyClassification === "all" ? "neutral" : historyClassification === "malicious" ? "danger" : historyClassification === "suspicious" ? "warning" : historyClassification === "benign" ? "success" : "neutral", mono: true },
              { label: "Search", value: historySearchQuery || "All archived emails", tone: historySearchQuery ? "warning" : "neutral" },
              { label: "Page", value: `${historyPage + 1} / ${historyPages}`, tone: "neutral", mono: true },
            ]}
          />
          <div style={{ marginTop: 14 }}>
            <div style={{ display: "grid", gap: 12, marginBottom: 14 }}>
              <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto auto", gap: 10, alignItems: "end" }}>
                <div style={{ ...shellFieldStyle, padding: 12 }}>
                  <div style={shellLabelStyle}>Search history</div>
                  <input
                    type="text"
                    value={historySearch}
                    onChange={(e) => {
                      const value = e.target.value;
                      setHistorySearch(value);
                      if (historySearchTimer.current) clearTimeout(historySearchTimer.current);
                      historySearchTimer.current = setTimeout(() => {
                        setHistorySearchQuery(value.trim());
                        setHistoryPage(0);
                      }, 250);
                    }}
                    placeholder="Search by subject, filename, sender email, or sender domain"
                    style={shellInputStyle}
                  />
                </div>
                <div style={{ ...shellFieldStyle, padding: 12, minWidth: 160 }}>
                  <div style={shellLabelStyle}>Classification</div>
                  <select
                    value={historyClassification}
                    onChange={(e) => {
                      setHistoryClassification(e.target.value);
                      setHistoryPage(0);
                    }}
                    style={shellInputStyle}
                  >
                    {HISTORY_CLASSIFICATIONS.map((option) => (
                      <option key={option} value={option}>
                        {option === "all" ? "All" : option[0].toUpperCase() + option.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setHistorySearch("");
                    setHistorySearchQuery("");
                    setHistoryClassification("all");
                    setHistoryPage(0);
                  }}
                  style={{
                    background: "rgba(120,145,178,0.12)",
                    border: "1px solid rgba(120,145,178,0.24)",
                    color: "var(--text-secondary)",
                    borderRadius: 14,
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    padding: "12px 14px",
                    cursor: "pointer",
                    minHeight: 52,
                  }}
                >
                  Clear
                </button>
              </div>
            </div>
            {!historyItems.length ? (
              <div style={{ color: "var(--text-dim)", fontSize: 13, lineHeight: 1.7 }}>No previous email investigations yet.</div>
            ) : (
              <div style={{ display: "grid", gap: 10, maxHeight: 280, overflowY: "auto", paddingRight: 4 }}>
                {historyItems.map((h) => {
                  const isSelected = selectedHistoryId === h.id;
                  const status = String(h.status || "unknown").toLowerCase();
                  const statusTone = ["queued", "processing", "running"].includes(status) ? "warning" : status === "completed" ? "success" : status === "failed" ? "danger" : "neutral";
                  const classification = String(h.classification || "unknown").toLowerCase();
                  const classificationTone =
                    classification === "malicious" ? "danger" :
                    classification === "suspicious" ? "warning" :
                    classification === "benign" ? "success" : "neutral";
                  return (
                    <article
                      key={h.id}
                      style={{
                        borderRadius: 18,
                        border: `1px solid ${isSelected ? "rgba(96,165,250,0.40)" : "rgba(120,145,178,0.16)"}`,
                        background: isSelected ? "rgba(96,165,250,0.10)" : "linear-gradient(180deg, rgba(16, 26, 44, 0.92), rgba(11, 17, 29, 0.98))",
                        padding: 12,
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => openHistoryItem(h.id)}
                        disabled={!!loadingHistoryItemId}
                        style={{
                          width: "100%",
                          textAlign: "left",
                          background: "transparent",
                          border: "none",
                          cursor: "pointer",
                          padding: 0,
                          display: "grid",
                          gap: 8,
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                          <div style={{ minWidth: 0, flex: "1 1 240px" }}>
                            <div style={{ fontSize: 13, color: "var(--text-strong)", fontWeight: 700, lineHeight: 1.4, wordBreak: "break-word" }}>
                              {h.email_subject || h.filename || "No subject"}
                            </div>
                            <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4, wordBreak: "break-word" }}>
                              {h.sender_email || "Unknown sender"}
                            </div>
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
                            <StatusPill tone={classificationTone} size="sm" mono>
                              {classification}
                            </StatusPill>
                            <StatusPill tone={statusTone} size="sm" mono>
                              {h.status || "unknown"}
                            </StatusPill>
                          </div>
                        </div>
                        <MetadataGrid
                          compact
                          columns={2}
                          items={[
                            { label: "URLs", value: h.urls_count, mono: true },
                            { label: "Attachments", value: h.attachments_count, mono: true },
                            { label: "Created", value: h.created_at ? new Date(h.created_at).toLocaleString() : "Unknown time" },
                            { label: "Run id", value: h.id, mono: true },
                          ]}
                        />
                      </button>
                      {["queued", "processing", "running"].includes(status) && (
                        <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>
                          <button
                            type="button"
                            onClick={() => cancelRun(h.id)}
                            disabled={cancelingRunId === h.id}
                            style={{
                              background: "rgba(239,68,68,0.12)",
                              border: "1px solid rgba(239,68,68,0.30)",
                              color: "#fca5a5",
                              borderRadius: 999,
                              fontSize: 11,
                              fontWeight: 700,
                              letterSpacing: "0.08em",
                              textTransform: "uppercase",
                              padding: "8px 12px",
                              cursor: cancelingRunId === h.id ? "not-allowed" : "pointer",
                            }}
                          >
                            {cancelingRunId === h.id ? "Cancelling..." : "Cancel run"}
                          </button>
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
            {historyTotal > 0 ? (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap", marginTop: 14, paddingTop: 12, borderTop: "1px solid rgba(120,145,178,0.12)" }}>
                <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                  {historyShowingFrom}-{historyShowingTo} of {historyTotal}
                </div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button type="button" onClick={() => setHistoryPage(0)} disabled={historyPage === 0} style={historyPaginationButtonStyle(historyPage === 0)}>&laquo;</button>
                  <button type="button" onClick={() => setHistoryPage((prev) => Math.max(0, prev - 1))} disabled={historyPage === 0} style={historyPaginationButtonStyle(historyPage === 0)}>Prev</button>
                  <button type="button" onClick={() => setHistoryPage((prev) => Math.min(historyPages - 1, prev + 1))} disabled={historyPage >= historyPages - 1} style={historyPaginationButtonStyle(historyPage >= historyPages - 1)}>Next</button>
                  <button type="button" onClick={() => setHistoryPage(historyPages - 1)} disabled={historyPage >= historyPages - 1} style={historyPaginationButtonStyle(historyPage >= historyPages - 1)}>&raquo;</button>
                </div>
              </div>
            ) : null}
          </div>
        </ConsoleModule>

        <ConsoleModule
          eyebrow="Sample intake"
          title="Upload"
          description="Configure the email analysis before submission. The current options do not change the existing run logic."
          tone="info"
          actions={<StatusPill tone={file ? "success" : "neutral"} outline mono>{fileStateLabel}</StatusPill>}
        >
          <MetadataGrid
            compact
            columns={2}
            items={[
              { label: "Selected file", value: fileLabel, tone: file ? "success" : "neutral" },
              { label: "Context", value: context.trim() ? `${context.trim().length} chars` : "Optional", tone: context.trim() ? "info" : "neutral", mono: true },
              { label: "ML score", value: mlScore.trim() || "unset", tone: mlScore.trim() ? "warning" : "neutral", mono: true },
              { label: "Screenshots", value: includeScreenshots ? "Enabled" : "Disabled", tone: includeScreenshots ? "warning" : "neutral" },
              { label: "AnyRun", value: runAnyRun ? "Enabled" : "Disabled", tone: runAnyRun ? "success" : "neutral" },
              { label: "AI interpretation", value: runAiInterpretation ? "Enabled" : "Disabled", tone: runAiInterpretation ? "info" : "neutral" },
            ]}
          />
          <form
            onSubmit={onSubmit}
            style={{
              marginTop: 16,
              display: "grid",
              gap: 12,
            }}
          >
            <div style={shellFieldStyle}>
              <div style={shellLabelStyle}>Email file</div>
              <input
                type="file"
                accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                style={shellInputStyle}
              />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
              <div style={shellFieldStyle}>
                <div style={shellLabelStyle}>Optional investigation context</div>
                <textarea
                  placeholder="Add analyst context, suspected campaign notes, or any extra clues."
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                  rows={4}
                  style={shellTextAreaStyle}
                />
              </div>
              <div style={shellFieldStyle}>
                <div style={shellLabelStyle}>Optional ML phishing score</div>
                <input
                  type="number"
                  min="0"
                  max="1"
                  step="0.001"
                  placeholder="0.000 - 1.000"
                  value={mlScore}
                  onChange={(e) => setMlScore(e.target.value)}
                  style={shellInputStyle}
                />
                <div style={{ marginTop: 10, fontSize: 12, lineHeight: 1.6, color: "var(--text-muted)" }}>
                  Higher values bias the workflow toward suspicious outcomes when combined with other signals.
                </div>
              </div>
            </div>
            <div style={shellFieldStyle}>
              <div style={shellLabelStyle}>Analysis options</div>
              <div style={{ display: "grid", gap: 10 }}>
                <label style={shellCheckboxStyle}>
                  <input type="checkbox" checked={includeScreenshots} onChange={(e) => setIncludeScreenshots(e.target.checked)} />
                  <span>Capture screenshot for each URL destination (slower)</span>
                </label>
                <label style={shellCheckboxStyle}>
                  <input type="checkbox" checked={runAnyRun} onChange={(e) => setRunAnyRun(e.target.checked)} />
                  <span>Run Any.Run checks for URLs and attachment hashes</span>
                </label>
                <label style={shellCheckboxStyle}>
                  <input type="checkbox" checked={runAiInterpretation} onChange={(e) => setRunAiInterpretation(e.target.checked)} />
                  <span>AI-assisted interpretation (recommended)</span>
                </label>
              </div>
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
              <button
                type="submit"
                disabled={!file || loading}
                style={{
                  background: "linear-gradient(135deg,#60a5fa,#818cf8)",
                  border: "none",
                  color: "#fff",
                  borderRadius: 999,
                  fontSize: 12,
                  fontWeight: 800,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  padding: "11px 16px",
                  cursor: !file || loading ? "not-allowed" : "pointer",
                  opacity: !file || loading ? 0.65 : 1,
                }}
              >
                {loading ? "Running investigation..." : "Upload and analyze"}
              </button>
              <StatusPill tone={runAnyRun ? "success" : "neutral"} outline mono>{runAnyRun ? "AnyRun enabled" : "AnyRun disabled"}</StatusPill>
              <StatusPill tone={runAiInterpretation ? "info" : "neutral"} outline mono>{runAiInterpretation ? "AI enabled" : "AI disabled"}</StatusPill>
            </div>
          </form>
        </ConsoleModule>
      </div>

      {error && (
        <ConsoleModule
          eyebrow="Run status"
          title="Attention"
          description={error}
          tone="danger"
          variant="outline"
        >
          <StatusPill tone="danger" outline mono>Error surfaced by the workflow</StatusPill>
        </ConsoleModule>
      )}
      <ConsoleModule
        eyebrow="Orchestration"
        title="Progress"
        description="Live upload, enrichment, and verdict state. The step list updates while the backend pipeline runs."
        tone={progressTone}
        actions={activeRunId ? <StatusPill tone="warning" outline mono>Cancelable</StatusPill> : <StatusPill tone="neutral" outline mono>Idle</StatusPill>}
      >
      {loading && (
        <div
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
            marginBottom: 16,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>Investigation Progress</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {progressModel.percent}% · {loadingElapsedSec}s
            </span>
          </div>
          <div style={{ height: 10, background: "var(--bg-input)", borderRadius: 999, overflow: "hidden", border: "1px solid var(--border)" }}>
            <div
              style={{
                height: "100%",
                width: `${progressModel.percent}%`,
                background: "linear-gradient(90deg, var(--accent), #34d399)",
                transition: "width 300ms ease",
              }}
            />
          </div>
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text)" }}>{progressModel.stageText}</div>
          <div style={{ marginTop: 10, display: "grid", gap: 5 }}>
            {progressModel.steps.map((step, idx) => (
              <div
                key={step.key}
                style={{
                  fontSize: 12,
                  color: idx < progressModel.activeIndex ? "var(--green)" : idx === progressModel.activeIndex ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                {idx < progressModel.activeIndex ? "[x]" : idx === progressModel.activeIndex ? "[>]" : "[ ]"} {step.label}
              </div>
            ))}
          </div>
          {activeRunId && (
            <div style={{ marginTop: 10 }}>
              <button
                type="button"
                onClick={() => cancelRun(activeRunId)}
                disabled={cancelingRunId === activeRunId}
                style={{
                  background: "rgba(239,68,68,0.12)",
                  border: "1px solid rgba(239,68,68,0.35)",
                  color: "#fca5a5",
                  borderRadius: "var(--radius)",
                  fontSize: 12,
                  fontWeight: 600,
                  padding: "6px 10px",
                  cursor: cancelingRunId === activeRunId ? "not-allowed" : "pointer",
                }}
              >
                {cancelingRunId === activeRunId ? "Cancelling..." : "Cancel Investigation"}
              </button>
            </div>
          )}
        </div>
      )}
      </ConsoleModule>

      <ConsoleModule
        eyebrow="Investigation output"
        title="Results"
        description={result?.email_subject || "Structured resolution, indicators, and sandbox context for the current sample."}
        tone={result ? "success" : "neutral"}
        actions={result ? <StatusPill tone="success" outline mono>Report ready</StatusPill> : <StatusPill tone="neutral" outline mono>No report</StatusPill>}
      >
      {result && (
        <div style={{ display: "grid", gap: 16 }}>

          {/* ── Overall Verdict Banner ── */}
          {(() => {
            const verdict = String((result as any)?.resolution?.overall_verdict || "inconclusive").toLowerCase();
            const confidence = String((result as any)?.resolution?.confidence || "low").toLowerCase();
            const signals: string[] = (result as any)?.resolution?.primary_signals || [];
            const color = verdict === "malicious" ? "#ef4444" : verdict === "suspicious" ? "#f59e0b" : verdict === "clean" ? "#34d399" : "#94a3b8";
            const bg = verdict === "malicious" ? "rgba(239,68,68,0.08)" : verdict === "suspicious" ? "rgba(245,158,11,0.08)" : verdict === "clean" ? "rgba(52,211,153,0.08)" : "rgba(148,163,184,0.06)";
            const border = verdict === "malicious" ? "rgba(239,68,68,0.35)" : verdict === "suspicious" ? "rgba(245,158,11,0.35)" : verdict === "clean" ? "rgba(52,211,153,0.3)" : "var(--border)";
            return (
              <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: "var(--radius-lg)", padding: "14px 16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 18, fontWeight: 800, color, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                    {verdict}
                  </span>
                  <span style={{ fontSize: 11, color, fontWeight: 600, border: `1px solid ${border}`, borderRadius: 999, padding: "3px 8px" }}>
                    {confidence} confidence
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
                    {result.resolution_source === "ai" ? "AI-assisted" : "Deterministic"}
                  </span>
                </div>
                {signals.length > 0 && (
                  <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {signals.map((s, i) => (
                      <span key={i} style={{ fontSize: 11, color: "var(--text-secondary)", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6, padding: "2px 8px" }}>
                        {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}

          {/* ── Result Tab Bar ── */}
          {(() => {
            const tabs: { id: "summary" | "indicators" | "anyrun"; label: string }[] = [
              { id: "summary", label: "Summary" },
              { id: "indicators", label: "Indicators" },
              { id: "anyrun", label: "AnyRun" },
            ];
            return (
              <div
                style={{
                  display: "flex",
                  gap: 10,
                  flexWrap: "wrap",
                  borderBottom: "1px solid rgba(120, 145, 178, 0.22)",
                  paddingBottom: 8,
                  marginBottom: 10,
                }}
              >
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setActiveResultTab(t.id)}
                    style={{
                      background:
                        activeResultTab === t.id
                          ? "linear-gradient(180deg, rgba(102,168,255,0.18) 0%, rgba(102,168,255,0.08) 100%)"
                          : "rgba(15, 23, 42, 0.72)",
                      border: activeResultTab === t.id
                        ? "1px solid rgba(102,168,255,0.52)"
                        : "1px solid rgba(120,145,178,0.22)",
                      borderBottom: activeResultTab === t.id
                        ? "1px solid rgba(102,168,255,0.65)"
                        : "1px solid rgba(120,145,178,0.22)",
                      color: activeResultTab === t.id ? "#d8e9ff" : "var(--text-secondary)",
                      fontSize: 14,
                      letterSpacing: "0.04em",
                      fontWeight: activeResultTab === t.id ? 800 : 600,
                      lineHeight: 1.1,
                      padding: "10px 18px",
                      minWidth: 132,
                      borderRadius: 12,
                      boxShadow: activeResultTab === t.id
                        ? "0 10px 24px rgba(37, 99, 235, 0.18)"
                        : "none",
                      cursor: "pointer",
                      marginBottom: -1,
                      textTransform: "uppercase",
                      transition: "background 140ms ease, border-color 140ms ease, color 140ms ease, box-shadow 140ms ease",
                    }}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            );
          })()}

          {activeResultTab === "summary" && <>

          {/* ── Email Summary ── */}
          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>Email Summary</div>
            <div style={{ color: "var(--text)", fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
              {result.email_subject || "No subject"}
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {/* Sender row with copy */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", minWidth: 90 }}>Sender</span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{result.sender_email || "N/A"}</span>
                {result.sender_email && (
                  <button type="button" onClick={() => copyToClipboard(result.sender_email!)} style={copyBtnStyle(copiedText === result.sender_email)}>
                    {copiedText === result.sender_email ? "Copied" : "Copy"}
                  </button>
                )}
              </div>
              {/* Domain row */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", minWidth: 90 }}>Domain</span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{result.sender_domain || "N/A"}</span>
                {result.sender_domain && (
                  <button type="button" onClick={() => copyToClipboard(result.sender_domain!)} style={copyBtnStyle(copiedText === result.sender_domain)}>
                    {copiedText === result.sender_domain ? "Copied" : "Copy"}
                  </button>
                )}
              </div>
              {/* IP row */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", minWidth: 90 }}>Sender IP</span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                  {result.sender_ip || "N/A"}
                  {result?.indicator_checks?.sender_ip?.abuseipdb?.isp ? ` (${result.indicator_checks.sender_ip.abuseipdb.isp}` : ""}
                  {result?.indicator_checks?.sender_ip?.abuseipdb?.country_code ? `, ${result.indicator_checks.sender_ip.abuseipdb.country_code})` : result?.indicator_checks?.sender_ip?.abuseipdb?.isp ? ")" : ""}
                </span>
                {result.sender_ip && (
                  <button type="button" onClick={() => copyToClipboard(result.sender_ip!)} style={copyBtnStyle(copiedText === result.sender_ip)}>
                    {copiedText === result.sender_ip ? "Copied" : "Copy"}
                  </button>
                )}
              </div>
              {/* Auth row */}
              {result.authentication && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", minWidth: 90 }}>Auth Header</span>
                  {(["spf", "dkim", "dmarc"] as const).map((k) => {
                    const val = String((result.authentication as any)?.[k] || "none").toLowerCase();
                    const c = val === "pass" ? "#34d399" : val === "fail" || val === "permerror" ? "#ef4444" : "#f59e0b";
                    return (
                      <span key={k} style={{ fontSize: 11, fontWeight: 700, color: c, border: "1px solid var(--border)", borderRadius: 6, padding: "2px 7px", textTransform: "uppercase" }}>
                        {k.toUpperCase()}: {val}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                URLs: {result.urls_count}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                Attachments: {result.attachments_count}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                Risk: {(result as any)?.indicator_checks?.final_risk?.risk_level || "unknown"} / score {(result as any)?.indicator_checks?.final_risk?.risk_score ?? "N/A"}
              </span>
            </div>
          </div>

          {/* ── Email Authentication & Security Posture ── */}
          {(() => {
            const es = (result as any)?.indicator_checks?.email_security || {};
            const auth = result.authentication as any || {};
            const hasData = es.available !== false || auth.spf;
            if (!hasData) return null;
            const spoofability = String(es.spoofability_score || "").toLowerCase();
            const spoofColor = spoofability === "high" ? "#ef4444" : spoofability === "medium" ? "#f59e0b" : spoofability === "low" ? "#60a5fa" : "#34d399";
            return (
              <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--accent)", marginBottom: 12, paddingBottom: 8, borderBottom: "1px solid var(--border)" }}>
                  Email Authentication &amp; Security Posture
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: 10, marginBottom: 12 }}>
                  {/* Header-parsed tokens */}
                  {(["spf", "dkim", "dmarc"] as const).map((k) => {
                    const headerVal = String(auth?.[k] || "none").toLowerCase();
                    const c = headerVal === "pass" ? "#34d399" : headerVal === "fail" || headerVal === "permerror" ? "#ef4444" : "#f59e0b";
                    return (
                      <div key={k} style={{ padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                        <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>{k.toUpperCase()} (header)</div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: c }}>{headerVal.toUpperCase()}</div>
                      </div>
                    );
                  })}
                  {/* Live DNS DMARC policy */}
                  {es.dmarc_policy !== undefined && (
                    <div style={{ padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>DMARC Policy (DNS)</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: es.dmarc_policy === "reject" ? "#34d399" : es.dmarc_policy === "quarantine" ? "#60a5fa" : "#f59e0b" }}>
                        {String(es.dmarc_policy || "none").toUpperCase()}
                      </div>
                    </div>
                  )}
                  {/* SPF all qualifier */}
                  {es.spf_all_qualifier !== undefined && (
                    <div style={{ padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>SPF All Qualifier</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: es.spf_all_qualifier === "-all" ? "#34d399" : es.spf_all_qualifier === "+all" ? "#ef4444" : "#f59e0b" }}>
                        {String(es.spf_all_qualifier || "none")}
                      </div>
                    </div>
                  )}
                  {/* DKIM selectors */}
                  <div style={{ padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>DKIM Selectors</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: (es.dkim_selectors_found || []).length > 0 ? "#34d399" : "#f59e0b" }}>
                      {(es.dkim_selectors_found || []).length > 0 ? (es.dkim_selectors_found || []).join(", ") : "None found"}
                    </div>
                  </div>
                  {/* Security score */}
                  {typeof es.email_security_score === "number" && (
                    <div style={{ padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Security Score</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: es.email_security_score >= 80 ? "#34d399" : es.email_security_score >= 50 ? "#f59e0b" : "#ef4444" }}>
                        {es.email_security_score}/100
                      </div>
                    </div>
                  )}
                </div>
                {/* Spoofability */}
                {spoofability && (
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>Spoofability:</span>
                    <span style={{ fontSize: 12, fontWeight: 700, color: spoofColor, border: `1px solid ${spoofColor}40`, borderRadius: 6, padding: "2px 10px" }}>
                      {spoofability.toUpperCase()}
                    </span>
                    {(es.spoofability_reasons || []).map((r: string, i: number) => (
                      <span key={i} style={{ fontSize: 11, color: "var(--text-secondary)", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6, padding: "2px 8px" }}>{r}</span>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}

          {/* ── Investigation Summary (AI narrative) ── */}
          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--accent)", marginBottom: 12, paddingBottom: 8, borderBottom: "1px solid var(--border)" }}>
              Investigation Summary
              <span style={{ marginLeft: 8, fontSize: 10, color: "var(--text-muted)", fontWeight: 400 }}>
                {result.resolution_source === "ai" ? "AI-assisted" : result.resolution_source === "disabled" ? "AI disabled — template output" : "Template output"}
              </span>
            </div>
            <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", fontSize: 13, lineHeight: 1.7, whiteSpace: "pre-wrap", color: "var(--text-secondary)", marginBottom: 14 }}>
              {result?.resolution?.formatted_resolution || "Not present in the provided evidence."}
            </div>
            {/* Sender domain analysis */}
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 8 }}>Sender Domain Analysis</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              {(() => {
                const cls = (result?.resolution?.sender_domain_analysis?.classification || "unknown").toLowerCase();
                const c = cls === "malicious" ? "#ef4444" : cls === "suspicious" ? "#f59e0b" : cls === "benign" ? "#34d399" : "var(--text-secondary)";
                return <span style={{ fontSize: 11, color: c, border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px", fontWeight: 700, textTransform: "uppercase" }}>{cls}</span>;
              })()}
            </div>
            {result?.resolution?.sender_domain_analysis?.primary_reasoning && (
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12, padding: "10px 12px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                {result.resolution.sender_domain_analysis.primary_reasoning}
              </div>
            )}
            {!domainFindings.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No sender-domain findings returned.</div>
            ) : (
              <div style={{ display: "grid", gap: 8 }}>
                {domainFindings.map((f: any, idx: number) => (
                  <div key={idx} style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", borderLeft: `3px solid ${findingSeverityColor(f?.severity)}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, gap: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 10, fontWeight: 700, borderRadius: 999, padding: "2px 8px", color: findingSeverityColor(f?.severity), background: "rgba(96,165,250,0.10)", textTransform: "uppercase" }}>
                          {(f?.severity || "info").toUpperCase()}
                        </span>
                        <span style={{ fontSize: 13, color: "var(--text)", fontWeight: 700 }}>{f?.title || "Untitled finding"}</span>
                      </div>
                      <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>Sender Domain</span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>{f?.description || "Not present in the provided evidence."}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ── Indicator Checks ── */}
          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>Indicator Checks</div>
            <div style={{ display: "grid", gap: 8 }}>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                <b>Sender domain:</b> {result?.indicator_checks?.sender_domain?.domain || result.sender_domain || "N/A"}
                {" | "}Registrar: {result?.indicator_checks?.sender_domain?.whois?.registrar || "N/A"}
                {" | "}Age: {result?.indicator_checks?.sender_domain?.whois?.domain_age_days ?? "N/A"} days
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                <b>Sender IP:</b> {result?.indicator_checks?.sender_ip?.ip || "N/A"}
                {" | "}VT: {result?.indicator_checks?.sender_ip?.vt?.malicious_count ?? 0}m/{result?.indicator_checks?.sender_ip?.vt?.suspicious_count ?? 0}s
                {" | "}AbuseIPDB: {result?.indicator_checks?.sender_ip?.abuseipdb?.abuse_confidence_score ?? "N/A"}%
                {result?.indicator_checks?.sender_ip?.abuseipdb?.usage_type ? ` | ${result.indicator_checks.sender_ip.abuseipdb.usage_type}` : ""}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                <b>URLs checked:</b> {result?.indicator_checks?.urls?.length || 0}
                {" | "}<b>Attachments:</b> {result?.indicator_checks?.attachments?.items?.length || 0}
                {" | "}<b>Final Risk:</b> {(result as any)?.indicator_checks?.final_risk?.risk_level || "unknown"} (score {(result as any)?.indicator_checks?.final_risk?.risk_score ?? "N/A"})
              </div>
              {/* Content ML */}
              {(result as any)?.indicator_checks?.content_ml && (
                <div style={{ fontSize: 12, color: "var(--text-secondary)", padding: "8px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                  <div style={{ fontWeight: 600, marginBottom: 4, color: "var(--text)" }}>Content ML (header heuristics)</div>
                  {(["social_engineering_probability", "urgency_probability", "impersonation_probability", "bec_probability"] as const).map((k) => {
                    const val = (result as any).indicator_checks.content_ml[k];
                    if (typeof val !== "number") return null;
                    const pct = (val * 100).toFixed(0);
                    const label = k.replace("_probability", "").replace(/_/g, " ");
                    const color = val > 0.7 ? "#ef4444" : val > 0.4 ? "#f59e0b" : "var(--text-dim)";
                    return (
                      <span key={k} style={{ marginRight: 12, color }}>
                        {label}: {pct}%
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          </>}

          {activeResultTab === "anyrun" && <>
          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--accent)",
              letterSpacing: "0.01em",
              marginBottom: 14,
              paddingBottom: 8,
              borderBottom: "1px solid var(--border)",
            }}>
              AnyRun Email Analysis
            </div>
            {(
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <span style={{
                    fontSize: 11,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    borderRadius: 999,
                    padding: "4px 8px",
                    color:
                      String((result as any)?.indicator_checks?.email_anyrun?.verdict || "unknown").toLowerCase() === "malicious"
                        ? "#ef4444"
                        : String((result as any)?.indicator_checks?.email_anyrun?.verdict || "unknown").toLowerCase() === "suspicious"
                          ? "#f59e0b"
                          : String((result as any)?.indicator_checks?.email_anyrun?.verdict || "unknown").toLowerCase() === "clean"
                            ? "#34d399"
                            : "var(--text-secondary)",
                    border: "1px solid var(--border)",
                  }}>
                    {String((result as any)?.indicator_checks?.email_anyrun?.verdict || "unknown")}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                    Checked: {String((result as any)?.indicator_checks?.email_anyrun?.checked ? "yes" : "no")}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                    Threat score: {(result as any)?.indicator_checks?.email_anyrun?.threat_score ?? "N/A"}
                  </span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>
                      Sample
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 600 }}>
                      {(result as any)?.indicator_checks?.email_anyrun?.file_name || result?.filename || "Not present in the provided evidence."}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6, wordBreak: "break-all", fontFamily: "var(--font-mono)" }}>
                      Task ID: {(result as any)?.indicator_checks?.email_anyrun?.analysis_id || "Not present in the provided evidence."}
                    </div>
                    {(result as any)?.indicator_checks?.email_anyrun?.analysis_link && (
                      <a
                        href={String((result as any)?.indicator_checks?.email_anyrun?.analysis_link)}
                        target="_blank"
                        rel="noreferrer"
                        style={{ display: "inline-block", marginTop: 8, fontSize: 11, color: "var(--accent)" }}
                      >
                        Open AnyRun task
                      </a>
                    )}
                  </div>
                  <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>
                      Analyst Summary
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                      {(() => {
                        const anyrun = (result as any)?.indicator_checks?.email_anyrun || {};
                        const raw = anyrun?.raw_summary || {};
                        const ai = raw?.anyrun_ai_summary || {};
                        if (typeof ai === "string" && ai.trim()) {
                          return ai;
                        }
                        if (typeof ai?.summary === "string" && ai.summary.trim()) {
                          return ai.summary;
                        }
                        if (typeof ai?.verdict === "string" && ai.verdict.trim()) {
                          return ai.verdict;
                        }
                        if (typeof anyrun?.error === "string" && anyrun.error.trim()) {
                          return anyrun.error;
                        }
                        return "Email sample was submitted to AnyRun and the detonation result was captured for this investigation.";
                      })()}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                      Domains observed: {anyrunArtifacts.domains.length}
                      {" | "}
                      Hosts observed: {anyrunArtifacts.hosts.length}
                    </div>
                  </div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
                      Observed Domains
                    </div>
                    {anyrunArtifacts.domains.length ? (
                      <PaginatedTextList
                        items={anyrunArtifacts.domains}
                        page={anyrunPages.domains}
                        pageSize={anyrunPageSize}
                        onPageChange={(page) => setAnyrunPages((current) => ({ ...current, domains: page }))}
                        renderItem={(d, idx) => {
                          const tl = d.threatLevel ?? 0;
                          const label = tl >= 2 ? "malicious" : tl === 1 ? "suspicious" : "clean";
                          const labelColor = tl >= 2 ? "#ef4444" : tl === 1 ? "#f59e0b" : "#34d399";
                          const labelBg = tl >= 2 ? "rgba(239,68,68,0.12)" : tl === 1 ? "rgba(245,158,11,0.12)" : "rgba(52,211,153,0.1)";
                          return (
                            <div key={`${d.name}-${idx}`} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6, marginBottom: 2 }}>
                              <span style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all", flex: 1 }}>
                                {d.name}
                              </span>
                              <span style={{ fontSize: 9, color: labelColor, background: labelBg, border: `1px solid ${labelColor}40`, borderRadius: 999, padding: "1px 6px", whiteSpace: "nowrap", flexShrink: 0 }}>
                                {label}
                              </span>
                            </div>
                          );
                        }}
                      />
                    ) : (
                      <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No domains were surfaced by AnyRun.</div>
                    )}
                  </div>
                  <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
                      Observed Hosts
                    </div>
                    {anyrunArtifacts.hosts.length ? (
                      <PaginatedTextList
                        items={anyrunArtifacts.hosts}
                        page={anyrunPages.hosts}
                        pageSize={anyrunPageSize}
                        onPageChange={(page) => setAnyrunPages((current) => ({ ...current, hosts: page }))}
                        renderItem={(h, idx) => {
                          const tl = h.threatLevel ?? 0;
                          const isMalicious = tl >= 2;
                          const isSuspicious = tl === 1;
                          const ipColor = isMalicious ? "#ef4444" : isSuspicious ? "#f59e0b" : "var(--text-secondary)";
                          return (
                            <div key={`${h.display}-${idx}`} style={{ marginBottom: 4 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ fontSize: 11, color: ipColor, fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                                  {h.display}
                                </span>
                                {(isMalicious || isSuspicious) && (
                                  <span style={{ fontSize: 9, color: ipColor, background: isMalicious ? "rgba(239,68,68,0.12)" : "rgba(245,158,11,0.12)", border: `1px solid ${ipColor}40`, borderRadius: 999, padding: "1px 6px", whiteSpace: "nowrap", flexShrink: 0 }}>
                                    {isMalicious ? "malicious" : "suspicious"}
                                  </span>
                                )}
                              </div>
                              {(h.asn || h.country) && (
                                <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>
                                  {[h.asn, h.country].filter(Boolean).join(" · ")}
                                </div>
                              )}
                            </div>
                          );
                        }}
                      />
                    ) : (
                      <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No destination hosts were surfaced by AnyRun.</div>
                    )}
                  </div>
                </div>
                <div style={{ padding: "12px 14px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
                    AnyRun-Surfaced URL And File Indicators
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>
                    URLs: {anyrunArtifacts.urls.length} | File-like indicators: {anyrunArtifacts.files.length}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
                        URLs
                      </div>
                      {anyrunArtifacts.urls.length ? (
                        <div style={{ maxHeight: 260, overflowY: "auto" }}>
                          <PaginatedTextList
                            items={anyrunArtifacts.urls}
                            page={anyrunPages.urls}
                            pageSize={anyrunPageSize}
                            onPageChange={(page) => setAnyrunPages((current) => ({ ...current, urls: page }))}
                            renderItem={(url, idx) => (
                              <div key={`${url}-${idx}`} style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                                {url}
                              </div>
                            )}
                          />
                        </div>
                      ) : (
                        <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No URL IOCs surfaced by AnyRun.</div>
                      )}
                    </div>
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 6 }}>
                        Files And Hashes
                      </div>
                      {anyrunArtifacts.files.length ? (
                        <div style={{ maxHeight: 260, overflowY: "auto" }}>
                          <PaginatedTextList
                            items={anyrunArtifacts.files}
                            page={anyrunPages.files}
                            pageSize={anyrunPageSize}
                            onPageChange={(page) => setAnyrunPages((current) => ({ ...current, files: page }))}
                            renderItem={(file, idx) => (
                              <div key={`${file.name}-${file.value}-${idx}`} style={{ padding: "6px 10px", border: "1px solid var(--border)", borderRadius: 6 }}>
                                <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                                  {file.name}
                                </div>
                                <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", marginTop: 2 }}>
                                  {file.category}
                                </div>
                                <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)", wordBreak: "break-all", marginTop: 2 }}>
                                  {file.value}
                                </div>
                              </div>
                            )}
                          />
                        </div>
                      ) : (
                        <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No file-like IOCs surfaced by AnyRun.</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* AnyRun status when not checked */}
          {!(result?.indicator_checks as any)?.email_anyrun?.checked && (
            <div style={{ padding: "20px 16px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text-dim)", fontSize: 12, textAlign: "center" }}>
              {!runAnyRun
                ? "AnyRun sandbox was not requested for this investigation."
                : (() => {
                    const err = String((result?.indicator_checks as any)?.email_anyrun?.error || "");
                    return err || "AnyRun sandbox analysis did not complete.";
                  })()
              }
            </div>
          )}
          </>}

          {activeResultTab === "indicators" && <>

          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>Attachment Hash Checks</div>
            {!result?.indicator_checks?.attachments?.items?.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No attachments found.</div>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                {result.indicator_checks.attachments.items.map((a: any, idx: number) => {
                  const attVtVerdict = String(a?.vt?.verdict || "unknown").toLowerCase();
                  const anyrunVerdict = String(a?.anyrun?.verdict || "").toLowerCase();
                  const isRisky = attVtVerdict === "malicious" || attVtVerdict === "suspicious" || anyrunVerdict === "malicious" || anyrunVerdict === "suspicious";
                  const staticItems = (result as any)?.indicator_checks?.attachment_analysis?.items || [];
                  const staticFound = staticItems.find((i: any) => String(i?.hash || "").toLowerCase() === String(a?.sha256 || "").toLowerCase());
                  return (
                    <div key={idx} style={{ border: `1px solid ${isRisky ? "rgba(239,68,68,0.4)" : "var(--border)"}`, borderRadius: "var(--radius)", padding: 10 }}>
                      <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 600, marginBottom: 6 }}>
                        {a?.filename || "unnamed_attachment"}
                        <span style={{ fontSize: 11, color: "var(--text-dim)", fontWeight: 400, marginLeft: 8 }}>({a?.size_bytes ?? 0} bytes)</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>SHA256</span>
                        <span style={{ fontSize: 10, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all", flex: 1 }}>{a?.sha256 || "N/A"}</span>
                        {a?.sha256 && <button type="button" onClick={() => copyToClipboard(a.sha256)} style={copyBtnStyle(copiedText === a.sha256)}>{copiedText === a.sha256 ? "Copied" : "Copy"}</button>}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>MD5</span>
                        <span style={{ fontSize: 10, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all", flex: 1 }}>{a?.md5 || "N/A"}</span>
                        {a?.md5 && <button type="button" onClick={() => copyToClipboard(a.md5)} style={copyBtnStyle(copiedText === a.md5)}>{copiedText === a.md5 ? "Copied" : "Copy"}</button>}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 8 }}>
                        <div style={{ padding: "6px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6 }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>VirusTotal</div>
                          <div style={{ fontSize: 12, fontWeight: 700, color: attVtVerdict === "malicious" ? "#ef4444" : attVtVerdict === "suspicious" ? "#f59e0b" : attVtVerdict === "clean" ? "#34d399" : "var(--text)" }}>
                            {attVtVerdict.toUpperCase()}
                          </div>
                          <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>m={a?.vt?.malicious_count ?? 0}, s={a?.vt?.suspicious_count ?? 0}, n={a?.vt?.total_vendors ?? 0}</div>
                          {a?.vt?.verdict === "rate_limited" && <div style={{ fontSize: 10, color: "#f87171" }}>rate limited</div>}
                        </div>
                        <div style={{ padding: "6px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6 }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>AnyRun TI</div>
                          <div style={{ fontSize: 12, fontWeight: 700, color: anyrunVerdict === "malicious" ? "#ef4444" : anyrunVerdict === "suspicious" ? "#f59e0b" : anyrunVerdict === "clean" ? "#34d399" : "var(--text-dim)" }}>
                            {a?.anyrun?.checked ? anyrunVerdict.toUpperCase() || "CHECKED" : a?.anyrun?.error === "Not requested" ? "Not queried" : "Not found"}
                          </div>
                          {typeof a?.anyrun?.threat_score === "number" && <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>score: {a.anyrun.threat_score}</div>}
                        </div>
                        <div style={{ padding: "6px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6 }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>Static ML</div>
                          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-secondary)" }}>
                            {staticFound ? String(staticFound.risk_level || "unknown").toUpperCase() : "N/A"}
                          </div>
                          {staticFound && <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>score: {Number(staticFound.static_risk_score || 0).toFixed(3)}</div>}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* URL summary strip */}
          {urlSummary.caution.length > 0 && (
            <div style={{ background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: "var(--radius-lg)", padding: "10px 14px" }}>
              <div style={{ fontSize: 11, color: "#ef4444", fontWeight: 700, textTransform: "uppercase", marginBottom: 4 }}>Suspicious / Malicious URL Destinations</div>
              {urlSummary.caution.map((d, i) => (
                <div key={i} style={{ fontSize: 11, color: "#fca5a5", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{d}</div>
              ))}
            </div>
          )}

          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 16 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>URL Reputation and Destination</div>
            {!result?.indicator_checks?.urls?.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No URLs found.</div>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {result.indicator_checks.urls.map((u: any, idx: number) => {
                  const finalUrl = u?.screenshot?.final_url || u?.url_behavior?.final_url || "Not present in the provided evidence.";
                  const verdict = (u?.effective_verdict || u?.vt?.verdict || "unknown").toLowerCase();
                  const verdictColor = verdict === "malicious" ? "#ef4444" : verdict === "suspicious" ? "#f59e0b" : verdict === "clean" ? "#34d399" : "var(--text)";
                  const anyrunVerdict = String(u?.anyrun?.verdict || "").toLowerCase();
                  // Determine which source drove the effective verdict
                  const vtV = String(u?.vt?.verdict || "").toLowerCase();
                  const urlscanV = String(u?.urlscan?.verdict || "").toLowerCase();
                  const verdictSource: string = (() => {
                    if (["malicious","suspicious","clean"].includes(vtV)) return "VirusTotal";
                    if (u?.anyrun?.checked && ["malicious","suspicious","clean"].includes(anyrunVerdict)) return "AnyRun TI";
                    if (u?.urlscan?.checked && ["malicious","suspicious","clean"].includes(urlscanV)) return "URLScan";
                    return "";
                  })();
                  return (
                    <div key={idx} style={{ border: `1px solid ${verdict === "malicious" ? "rgba(239,68,68,0.4)" : verdict === "suspicious" ? "rgba(245,158,11,0.3)" : "var(--border)"}`, borderRadius: "var(--radius)", padding: 12 }}>
                      {/* URL header */}
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: verdictColor }}>{verdict.toUpperCase()}</span>
                        {verdictSource && <span style={{ fontSize: 10, color: "var(--text-muted)", border: "1px solid var(--border)", borderRadius: 999, padding: "1px 7px" }}>via {verdictSource}</span>}
                        <span style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all", flex: 1 }}>{u.url}</span>
                        <button type="button" onClick={() => copyToClipboard(String(u.url))} style={copyBtnStyle(copiedText === String(u.url))}>
                          {copiedText === String(u.url) ? "Copied" : "Copy"}
                        </button>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 8, marginBottom: 8 }}>
                        {/* Verdict details */}
                        <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 8, background: "rgba(96,165,250,0.05)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Signals</div>
                          <div style={{ fontSize: 10, color: "var(--text-secondary)", marginTop: 2 }}>
                            VT: {u?.vt?.verdict || "unknown"} (m={u?.vt?.malicious_count ?? 0}, s={u?.vt?.suspicious_count ?? 0}, n={u?.vt?.total_vendors ?? 0})
                            {u?.vt?.verdict === "rate_limited" && <span style={{ color: "#f87171" }}> [rate limited]</span>}
                          </div>
                          {u?.anyrun && u.anyrun.error !== "Not requested" && (
                            <div style={{ fontSize: 10, color: anyrunVerdict === "malicious" ? "#ef4444" : anyrunVerdict === "suspicious" ? "#f59e0b" : anyrunVerdict === "clean" ? "#34d399" : "var(--text-dim)", marginTop: 3 }}>
                              AnyRun TI: {u.anyrun.checked ? (anyrunVerdict || "unknown") + (typeof u.anyrun.threat_score === "number" ? ` (score ${u.anyrun.threat_score})` : "") : "not found in database"}
                            </div>
                          )}
                          {u?.urlscan?.checked && (
                            <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 3 }}>
                              URLScan: {u.urlscan.verdict || "unknown"}{typeof u.urlscan.score === "number" ? ` (${u.urlscan.score})` : ""}
                            </div>
                          )}
                          <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 3 }}>
                            Lexical ML: {String(u?.ml_url_score?.risk_level || u?.lexical_ml?.label || "unknown").toUpperCase()}
                            {typeof u?.lexical_ml?.score === "number" ? ` (${u.lexical_ml.score.toFixed(3)})` : ""}
                          </div>
                        </div>
                        {/* Final URL + behavior */}
                        <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 8, background: "rgba(16,185,129,0.04)" }}>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>Destination</div>
                          <div style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", fontFamily: "var(--font-mono)" }}>{finalUrl}</div>
                          {(u?.urlscan?.page_title || u?.urlscan?.page_ip) && (
                            <div style={{ marginTop: 4, fontSize: 10, color: "var(--text-dim)" }}>
                              {u.urlscan.page_title ? `title: ${u.urlscan.page_title}` : ""}
                              {u.urlscan.page_title && u.urlscan.page_ip ? " | " : ""}
                              {u.urlscan.page_ip ? `ip: ${u.urlscan.page_ip}` : ""}
                            </div>
                          )}
                          <div style={{ marginTop: 4, fontSize: 10, color: "var(--text-dim)" }}>
                            Redirects: {u?.url_behavior?.redirect_count ?? "N/A"}
                            {" | "}Cred form: <span style={{ color: u?.url_behavior?.credential_form_present ? "#ef4444" : "var(--text-dim)", fontWeight: u?.url_behavior?.credential_form_present ? 700 : 400 }}>{u?.url_behavior?.credential_form_present ? "YES" : "No"}</span>
                            {" | "}UA cloaking: {u?.url_behavior?.ua_cloaking_detected ? "Yes" : "No"}
                          </div>
                        </div>
                      </div>
                      {u?.screenshot?.image_base64 ? (
                        <img src={`data:image/png;base64,${u.screenshot.image_base64}`} alt={`URL screenshot ${idx + 1}`} style={{ maxWidth: "100%", borderRadius: 6, border: "1px solid var(--border)", marginTop: 8 }} />
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          </>}

        </div>
      )}
      </ConsoleModule>
    </div>
  );
}

function historyPaginationButtonStyle(disabled: boolean): React.CSSProperties {
  return {
    padding: "8px 12px",
    background: "rgba(10, 16, 28, 0.72)",
    border: "1px solid rgba(120, 145, 178, 0.18)",
    borderRadius: 12,
    color: disabled ? "var(--text-dim)" : "var(--text-strong)",
    fontSize: 11,
    fontWeight: 700,
    cursor: disabled ? "default" : "pointer",
    fontFamily: "var(--font-mono)",
    opacity: disabled ? 0.45 : 1,
    minWidth: 46,
  };
}

function findingSeverityColor(severity?: string): string {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "#ef4444";
  if (s === "medium") return "#f59e0b";
  if (s === "low") return "#60a5fa";
  return "#94a3b8";
}

function copyBtnStyle(active: boolean): React.CSSProperties {
  return {
    background: active ? "rgba(52,211,153,0.15)" : "var(--bg-elevated)",
    border: `1px solid ${active ? "rgba(52,211,153,0.4)" : "var(--border)"}`,
    color: active ? "#34d399" : "var(--text-muted)",
    borderRadius: 6,
    fontSize: 10,
    fontWeight: 600,
    padding: "2px 8px",
    cursor: "pointer",
    whiteSpace: "nowrap" as const,
  };
}

function buildSenderDomainFindings(
  result: EmailInvestigationResponse | null,
): Array<{ title: string; severity: string; description: string }> {
  const aiFindings = result?.resolution?.sender_domain_analysis?.findings;
  if (Array.isArray(aiFindings) && aiFindings.length > 0) {
    return aiFindings.map((f: any) => ({
      title: String(f?.title || "Untitled finding"),
      severity: String(f?.severity || "medium").toLowerCase(),
      description: String(f?.description || "Not present in the provided evidence."),
    }));
  }

  const domain = result?.sender_domain || result?.indicator_checks?.sender_domain?.domain || "Not present in the provided evidence.";
  const whois = result?.indicator_checks?.sender_domain?.whois || {};
  const registrar = whois?.registrar || "Not present in the provided evidence.";
  const ageDays = typeof whois?.domain_age_days === "number" ? String(whois.domain_age_days) : "Not present in the provided evidence.";
  const statuses = Array.isArray(whois?.statuses) && whois.statuses.length
    ? whois.statuses.join(", ")
    : "Not present in the provided evidence.";
  const suspiciousUrls = (result?.indicator_checks?.urls || []).filter(
    (u: any) => ["malicious", "suspicious"].includes(String(u?.vt?.verdict || "").toLowerCase()),
  ).length;

  const fallback: Array<{ title: string; severity: string; description: string }> = [
    {
      title: "Sender domain registration context",
      severity: "low",
      description: `Domain: ${domain}. Registrar: ${registrar}. Domain age days: ${ageDays}. WHOIS statuses: ${statuses}.`,
    },
    {
      title: "Sender domain URL risk context",
      severity: suspiciousUrls > 0 ? "medium" : "low",
      description: `URLs analyzed: ${result?.urls_count ?? 0}. Suspicious/malicious URL verdicts: ${suspiciousUrls}.`,
    },
  ];
  return fallback;
}

function buildUrlSummary(result: EmailInvestigationResponse | null): {
  overview: string;
  purpose: string[];
  destinations: string[];
  caution: string[];
} {
  const urls = result?.indicator_checks?.urls || [];
  if (!urls.length) {
    return {
      overview: "No URLs were found in this email.",
      purpose: [],
      destinations: [],
      caution: [],
    };
  }

  const risky = urls.filter((u: any) => ["malicious", "suspicious"].includes(String(u?.vt?.verdict || "").toLowerCase()));
  const clean = urls.filter((u: any) => String(u?.vt?.verdict || "").toLowerCase() === "clean");
  const enriched = urls.map((u: any) => {
    const original = String(u?.url || "").trim();
    const finalUrl = String(u?.screenshot?.final_url || original).trim();
    const verdict = String(u?.vt?.verdict || "unknown").toLowerCase();
    return {
      original,
      finalUrl,
      verdict,
      purpose: inferUrlPurpose(original, finalUrl),
    };
  });

  const purposeCounts = new Map<string, number>();
  for (const item of enriched) {
    purposeCounts.set(item.purpose, (purposeCounts.get(item.purpose) || 0) + 1);
  }

  const purposeList = Array.from(purposeCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([purpose, count]) => `${count} ${count === 1 ? "URL appears to be" : "URLs appear to be"} ${purpose}.`);

  const topPoints = enriched
    .slice(0, 3)
    .map((u) => u.finalUrl)
    .filter(Boolean);

  const riskyList = enriched
    .filter((u) => u.verdict === "malicious" || u.verdict === "suspicious")
    .slice(0, 2)
    .map((u) => u.finalUrl)
    .filter(Boolean);

  return {
    overview: `Analyzed ${urls.length} URL(s): ${clean.length} clean and ${risky.length} suspicious/malicious by VirusTotal.`,
    purpose: purposeList,
    destinations: topPoints,
    caution: riskyList,
  };
}

type AnyRunDomain = { name: string; threatLevel: number; threatName: string[] };
type AnyRunHost = { display: string; ip: string; port: string; asn: string; country: string; threatLevel: number };

function buildAnyRunEmailArtifacts(result: EmailInvestigationResponse | null): {
  domains: AnyRunDomain[];
  hosts: AnyRunHost[];
  urls: string[];
  files: Array<{ name: string; value: string; category: string }>;
} {
  const anyrun = (result?.indicator_checks as any)?.email_anyrun || {};
  const dynamic = anyrun?.dynamic_io_summary || {};
  const raw = anyrun?.raw_summary || {};
  const iocs = Array.isArray(raw?.iocs) ? raw.iocs : [];
  const behaviorDetails = raw?.behavior_details || {};

  // Build IP → {asn, country} lookup from connections (which carry ASN/country per entry)
  const connGeo: Record<string, { asn: string; country: string }> = {};
  for (const c of (Array.isArray(behaviorDetails?.connections) ? behaviorDetails.connections : [])) {
    if (!c || typeof c !== "object") continue;
    const ip = String(c?.destinationIP || c?.ip || c?.host || "").trim();
    if (!ip) continue;
    const asn = String(c?.asn || "").trim();
    const country = String(c?.country || c?.geo?.country || "").trim();
    if ((asn || country) && !connGeo[ip]) connGeo[ip] = { asn, country };
  }

  // Domains — keep full metadata for labels
  const domainMap: Record<string, AnyRunDomain> = {};
  for (const entry of (Array.isArray(dynamic?.domains) ? dynamic.domains : [])) {
    if (!entry || typeof entry !== "object") continue;
    const name = String(entry?.domainName || entry?.domain || "").trim();
    if (!name) continue;
    if (!domainMap[name]) {
      domainMap[name] = {
        name,
        threatLevel: Number(entry?.threatLevel ?? 0),
        threatName: Array.isArray(entry?.threatName) ? entry.threatName.map(String).filter(Boolean) : [],
      };
    }
  }
  const domains: AnyRunDomain[] = Object.values(domainMap);

  // Hosts — enrich with ASN/country from connections
  const hostMap: Record<string, AnyRunHost> = {};
  for (const entry of (Array.isArray(dynamic?.hosts) ? dynamic.hosts : [])) {
    if (!entry || typeof entry !== "object") continue;
    const ip = String(entry?.destinationIP || entry?.ip || entry?.host || "").trim();
    if (!ip) continue;
    const port = String(entry?.destinationPort ?? entry?.port ?? "").trim();
    const key = `${ip}:${port}`;
    if (!hostMap[key]) {
      const geo = connGeo[ip] || { asn: "", country: "" };
      hostMap[key] = {
        display: port ? `${ip}:${port}` : ip,
        ip,
        port,
        asn: geo.asn,
        country: geo.country,
        threatLevel: Number(entry?.threatLevel ?? 0),
      };
    }
  }
  const hosts: AnyRunHost[] = Object.values(hostMap);

  // URLs from IOC report (type may be "URL", "url", "uri", "http", "link")
  const _urlTypes = new Set(["url", "uri", "http", "link"]);
  const urlsFromIocs: string[] = iocs
    .filter((item: any) => _urlTypes.has(String(item?.type || "").toLowerCase()))
    .map((item: any) => String(item?.ioc || "").trim())
    .filter(Boolean);

  // URLs from sandbox HTTP traffic stored in dynamic_io_summary.urls
  const urlsFromDynamic: string[] = (Array.isArray(dynamic?.urls) ? dynamic.urls : [])
    .map((r: any) => String(r?.url || "").trim())
    .filter((u: string) => u && u.startsWith("http"));

  // URLs from sandbox HTTP traffic stored in behavior_details (fallback)
  const urlsFromHttp: string[] = (Array.isArray(behaviorDetails?.http_requests) ? behaviorDetails.http_requests : [])
    .map((r: any) => String(r?.url || r?.requestUrl || "").trim())
    .filter((u: string) => u && u !== "-" && u.startsWith("http"));

  const urls: string[] = Array.from(new Set([...urlsFromIocs, ...urlsFromDynamic, ...urlsFromHttp]));

  const fileMap: Record<string, { name: string; value: string; category: string }> = {};
  for (const item of iocs) {
    if (!["file", "sha256", "md5", "hash"].includes(String(item?.type || "").toLowerCase())) {
      continue;
    }
    const name = String(item?.name || item?.ioc || "Unknown file").trim();
    const value = String(item?.ioc || "").trim();
    const category = String(item?.category || String(item?.type || "indicator")).trim();
    fileMap[`${name}|${value}|${category}`] = { name, value, category };
  }
  const files: Array<{ name: string; value: string; category: string }> = Object.values(fileMap);

  return { domains, hosts, urls, files };
}

function PaginatedTextList<T>({
  items,
  page,
  pageSize,
  onPageChange,
  renderItem,
}: {
  items: T[];
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  renderItem: (item: T, index: number) => React.ReactNode;
}) {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(Math.max(page, 1), totalPages);
  const startIndex = (safePage - 1) * pageSize;
  const endIndex = Math.min(items.length, startIndex + pageSize);
  const visibleItems = items.slice(startIndex, endIndex);

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Showing {items.length ? startIndex + 1 : 0}-{endIndex} of {items.length}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            type="button"
            onClick={() => onPageChange(safePage - 1)}
            disabled={safePage <= 1}
            style={pagerButtonStyle(safePage <= 1)}
          >
            Previous
          </button>
          <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            Page {safePage} / {totalPages}
          </div>
          <button
            type="button"
            onClick={() => onPageChange(safePage + 1)}
            disabled={safePage >= totalPages}
            style={pagerButtonStyle(safePage >= totalPages)}
          >
            Next
          </button>
        </div>
      </div>
      <div style={{ display: "grid", gap: 6 }}>
        {visibleItems.map((item, idx) => renderItem(item, startIndex + idx))}
      </div>
    </div>
  );
}

function pagerButtonStyle(disabled: boolean): React.CSSProperties {
  return {
    background: disabled ? "rgba(148,163,184,0.08)" : "rgba(96,165,250,0.12)",
    color: disabled ? "var(--text-muted)" : "var(--accent)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    padding: "4px 10px",
    fontSize: 11,
    fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
  };
}

function inferUrlPurpose(originalUrl: string, finalUrl: string): string {
  const info = parseUrlInfo(finalUrl || originalUrl);
  const host = info.host.toLowerCase();
  const path = info.path.toLowerCase();

  if (host.endsWith("j2.email")) {
    if (path.includes("/unsubscribe") || path.includes("unsubscribe")) {
      return "an email unsubscribe / recipient-preference link (j2.email infrastructure)";
    }
    if (path.startsWith("/t/")) {
      return "an email tracking or campaign-routing link (j2.email infrastructure)";
    }
    return "an email campaign infrastructure link (j2.email)";
  }

  if (host.endsWith("w3.org")) {
    if (path.endsWith(".dtd") || path.includes("/dtd/")) {
      return "a W3C XHTML/HTML DTD technical resource used by markup templates";
    }
    if (path.includes("/tr/")) {
      return "a W3C standards/specification reference page";
    }
    return "a W3C standards resource";
  }

  if (path.endsWith(".pdf")) return "a document/PDF download URL";
  if (path.endsWith(".xml")) return "an XML data/resource URL";
  if (path.includes("login") || path.includes("signin") || path.includes("auth")) {
    return "an authentication or account-access page";
  }
  return "a general web destination";
}

function parseUrlInfo(raw: string): { host: string; path: string } {
  try {
    const url = new URL(raw);
    return { host: url.hostname || "", path: url.pathname || "" };
  } catch {
    return { host: "", path: "" };
  }
}
