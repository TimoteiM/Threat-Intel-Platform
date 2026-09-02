"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";

import AnalystFeedbackControl from "@/components/shared/AnalystFeedbackControl";
import ConsoleModule from "@/components/ui/ConsoleModule";
import EndpointEventCard from "@/components/report/EndpointEventCard";
import IndicatorSummaryCard from "@/components/report/IndicatorSummaryCard";
import PageHero from "@/components/ui/PageHero";
import { MenuItem, OverflowMenu } from "@/components/ui/Primitives";
import {
  alertInvestigationExportUrl,
  cancelAlertInvestigation,
  createAlertExclusion,
  deleteAlertInvestigation,
  getAlertInvestigation,
  getRunCase,
  getSuppressionCandidate,
  type AlertExportFormat,
} from "@/lib/api";
import type {
  AlertAIReport,
  AlertEndpointEventReport,
  AlertFinding,
  AlertIndicatorReport,
  AlertInvestigationRun,
  AlertReport,
  CorrelatedCase,
  SuppressionCandidate,
} from "@/lib/types";

const ACTIVE_STATUSES = ["queued", "processing", "running"];

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
  not_investigated: "#64748b",
};

function verdictColor(verdict?: string | null): string {
  return VERDICT_COLORS[String(verdict || "").toLowerCase()] || "#94a3b8";
}

function riskColor(score: number): string {
  if (score >= 70) return "#f87171";
  if (score >= 35) return "#fbbf24";
  return "#34d399";
}

export default function AlertInvestigationDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const runId = String(params?.id || "");

  const [run, setRun] = useState<AlertInvestigationRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [copied, setCopied] = useState(false);
  const [urlCopied, setUrlCopied] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    const data = await getAlertInvestigation(runId);
    setRun(data);
    setLoading(false);
    return data;
  }, [runId]);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      try {
        const data = await load();
        if (cancelled) return;
        // Keep polling while the run itself is active *or* a spawned
        // investigation is still going — each read hydrates the finished ones.
        const waitingOnInvestigation = (data.indicator_reports || []).some(
          (report) => report.status === "investigating",
        );
        if (ACTIVE_STATUSES.includes(String(data.status)) || waitingOnInvestigation) {
          timer = setTimeout(poll, waitingOnInvestigation ? 8000 : 4000);
        }
      } catch (e: any) {
        if (cancelled) return;
        setError(e?.message || "Failed to load the alert investigation");
        setLoading(false);
      }
    };

    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [runId, load]);

  const reports: AlertIndicatorReport[] = useMemo(
    () => run?.indicator_reports || [],
    [run],
  );
  const eventReports: AlertEndpointEventReport[] = useMemo(
    () => run?.event_reports || [],
    [run],
  );
  const aiReport: AlertAIReport | null = run?.ai_report || null;
  // The exported list is the integration contract: AI analysis first, then one
  // report per indicator.
  const exportList: AlertReport[] = useMemo(
    () => run?.reports || [...(aiReport ? [aiReport] : []), ...reports],
    [run, aiReport, reports],
  );
  const resolvedIdentifiers = useMemo(
    () => parseResolvedIdentifiers(aiReport?.report_markdown || ""),
    [aiReport],
  );
  const isActive = ACTIVE_STATUSES.includes(String(run?.status));

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(exportList, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — the download button still works */
    }
  };

  // Downloads come from the export endpoint, so the file an analyst saves is
  // byte-for-byte what another platform pulls from the API.
  // "Is this alert part of something bigger" is the question a single alert
  // cannot answer about itself, and the one that changes what an analyst does.
  const [runCase, setRunCase] = useState<CorrelatedCase | null>(null);
  const [suppressOpen, setSuppressOpen] = useState(false);
  const [suppressNote, setSuppressNote] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getRunCase(runId)
      .then((data) => !cancelled && setRunCase(data.case))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const handleDownload = (format: AlertExportFormat = "reports") => {
    const link = document.createElement("a");
    link.href = alertInvestigationExportUrl(runId, { format });
    link.click();
  };

  const handleCopyExportUrl = async () => {
    try {
      await navigator.clipboard.writeText(
        alertInvestigationExportUrl(runId, { format: "reports", download: false, absolute: true }),
      );
      setUrlCopied(true);
      setTimeout(() => setUrlCopied(false), 2000);
    } catch {
      /* clipboard unavailable — the download buttons still work */
    }
  };

  const handleDelete = async () => {
    // Every investigation this run started goes with it — say so before asking.
    const spawned = reports.filter((report) => !!report.investigation).length;
    const consequence = spawned
      ? `\n\nThis also deletes the ${spawned} investigation${spawned === 1 ? "" : "s"} this run started, ` +
        "with their reports and evidence. Investigations it reused, or that another alert run also " +
        "references, are kept."
      : "";
    if (!window.confirm(`Delete "${run?.title || runId}"?${consequence}`)) return;

    setDeleting(true);
    try {
      const result = await deleteAlertInvestigation(runId);
      if (result?.kept_investigations?.length) {
        alert(
          `Run deleted. ${result.kept_investigations.length} investigation(s) were kept because ` +
            "another alert run still references them.",
        );
      }
      router.push("/alert-investigations");
    } catch (e: any) {
      alert(`Failed to delete: ${e?.message || e}`);
      setDeleting(false);
    }
  };

  const handleCancel = async () => {
    try {
      await cancelAlertInvestigation(runId);
      await load();
    } catch (e: any) {
      alert(`Failed to cancel: ${e?.message || e}`);
    }
  };

  if (loading) {
    return <div style={{ padding: 40, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>Loading alert investigation…</div>;
  }

  if (error || !run) {
    return (
      <div style={{ padding: 40 }}>
        <div style={{ color: "#f87171", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
          {error || "Alert investigation not found"}
        </div>
        <button onClick={() => router.push("/alert-investigations")} style={secondaryButtonStyle}>
          Back to alert investigations
        </button>
      </div>
    );
  }

  const summary = run.summary;
  const counts = summary?.classification_counts || {};

  return (
    <div style={{ display: "grid", gap: 18, paddingBottom: 56 }}>
      {runCase && <CaseBanner runCase={runCase} currentRunId={runId} />}
      {suppressOpen && (
        <SuppressDialog
          runId={runId}
          onClose={() => setSuppressOpen(false)}
          onDone={(message) => {
            setSuppressNote(message);
            setSuppressOpen(false);
          }}
        />
      )}
      {suppressNote && (
        <div
          role="status"
          style={{
            padding: "10px 14px", borderRadius: 10, fontSize: 12,
            border: "1px solid rgba(52, 211, 153, 0.35)",
            background: "rgba(52, 211, 153, 0.08)", color: "var(--text)",
          }}
        >
          {suppressNote}
        </div>
      )}
      <PageHero
        title={run.title}
        description={
          isActive
            ? "Extracting indicators and running them through the collectors — this page refreshes automatically."
            : `${summary?.indicators_investigated ?? 0} of ${summary?.indicators_total ?? run.indicator_count} indicator(s) investigated.`
        }
        tone={
          run.overall_verdict === "malicious"
            ? "danger"
            : run.overall_verdict === "suspicious"
              ? "warning"
              : run.status === "failed"
                ? "danger"
                : "info"
        }
        status={
          <span
            style={{
              fontSize: 11,
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              color: isActive ? "#fbbf24" : verdictColor(run.overall_verdict),
            }}
          >
            {isActive ? run.status : run.overall_verdict || run.status}
          </span>
        }
        stats={
          <div style={{ display: "flex", gap: 22, flexWrap: "wrap" }}>
            <HeroStat label="Indicators" value={String(summary?.indicators_total ?? run.indicator_count)} />
            <HeroStat label="Malicious" value={String(counts.malicious ?? 0)} color="#f87171" />
            <HeroStat label="Suspicious" value={String(counts.suspicious ?? 0)} color="#fbbf24" />
            <HeroStat label="Benign" value={String(counts.benign ?? 0)} color="#34d399" />
            <HeroStat
              label="Highest risk"
              value={String(summary?.highest_risk_score ?? 0)}
              color={riskColor(summary?.highest_risk_score ?? 0)}
            />
          </div>
        }
        actions={
          /* Was eight equally-weighted buttons, five of them export variants.
             Now: read the report, and everything else under one control. */
          <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap" }}>
            {isActive && (
              <button onClick={handleCancel} style={secondaryButtonStyle}>
                Cancel run
              </button>
            )}
            {exportList.length > 0 && (
              <button
                onClick={() => router.push(`/alert-investigations/${runId}/report`)}
                title="See the report-ready export rendered — domain reports and the other IOCs, exactly as the API serves them"
                style={{ ...secondaryButtonStyle, borderColor: "var(--accent)", color: "var(--accent)" }}
              >
                Preview report
              </button>
            )}
            <button
              onClick={() => setSuppressOpen(true)}
              title="Stop spending collectors on this shape of alert. The run is still recorded and still counts towards correlation — only the lookups are skipped."
              style={{ ...secondaryButtonStyle, borderColor: "var(--status-warning)", color: "var(--status-warning)" }}
            >
              Suppress
            </button>
            <OverflowMenu label="Export and run actions">
              {(close) => (
                <>
                  {exportList.length > 0 && (
                    <>
                      <MenuItem onClick={() => { close(); handleCopy(); }}>
                        {copied ? "Copied" : `Copy JSON list (${exportList.length})`}
                      </MenuItem>
                      <MenuItem
                        title="The integration contract: [AI report, one report per indicator]"
                        onClick={() => { close(); handleDownload("reports"); }}
                      >
                        Download JSON list
                      </MenuItem>
                      <MenuItem
                        title="Report-ready: [executive summary, indicator + soc_report] — the same data model our SOC PDF renders, without the raw collector dumps"
                        onClick={() => { close(); handleDownload("report"); }}
                      >
                        Download report list
                      </MenuItem>
                      <MenuItem
                        title="Everything, including every collector's raw output. Megabytes per domain."
                        onClick={() => { close(); handleDownload("full"); }}
                      >
                        Download raw evidence list
                      </MenuItem>
                      <MenuItem
                        title="Give this URL to the reporting platform — one GET returns the JSON list"
                        onClick={() => { close(); handleCopyExportUrl(); }}
                      >
                        {urlCopied ? "URL copied" : "Copy export URL"}
                      </MenuItem>
                    </>
                  )}
                  <MenuItem
                    danger
                    disabled={deleting}
                    title="Delete this run and the investigations it started"
                    onClick={() => { close(); handleDelete(); }}
                  >
                    {deleting ? "Deleting…" : "Delete run"}
                  </MenuItem>
                </>
              )}
            </OverflowMenu>
          </div>
        }
      />

      {run.error && (
        <ConsoleModule title="Run error" tone="danger" compact>
          <div style={{ fontSize: 12, color: "#fca5a5", fontFamily: "var(--font-mono)" }}>{run.error}</div>
        </ConsoleModule>
      )}

      {/* Asked once the run has an answer to judge — measuring the decision
          engine is impossible without the analyst's call on it. */}
      {!isActive && <AnalystFeedbackControl subjectType="alert_run" subjectId={runId} compact />}

      {run.alert_body && (
        <ConsoleModule
          title="Alert body"
          description={
            run.extraction
              ? `${run.extraction.total} indicator(s) extracted from ${run.extraction.characters} characters`
              : undefined
          }
          compact
        >
          <pre
            style={{
              margin: 0,
              maxHeight: 220,
              overflow: "auto",
              fontSize: 11.5,
              lineHeight: 1.6,
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {run.alert_body}
          </pre>
        </ConsoleModule>
      )}

      {aiReport && (
        <ConsoleModule
          title="AI assistant analysis"
          description="The raw alert body was sanitised and analysed by the AI assistant — identifiers were tokenised before the model saw them and restored afterwards."
          tone={aiReport.status === "failed" ? "danger" : "info"}
          actions={
            aiReport.assistant_session_id ? (
              <a
                href={`/assistant?session=${aiReport.assistant_session_id}`}
                style={{ ...secondaryButtonStyle, textDecoration: "none", display: "inline-block" }}
              >
                Open in AI Assistant
              </a>
            ) : undefined
          }
        >
          {aiReport.status === "failed" ? (
            <div style={{ fontSize: 12, color: "#fca5a5", fontFamily: "var(--font-mono)" }}>
              {aiReport.error || "The AI assistant could not analyse this alert."}
            </div>
          ) : (
            <>
              <pre
                style={{
                  margin: 0,
                  maxHeight: 420,
                  overflow: "auto",
                  fontSize: 12,
                  lineHeight: 1.65,
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-sans)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {stripResolvedIdentifiers(aiReport.report_markdown || "") || "No report content returned."}
              </pre>

              {/* The backend appends a token→value table to the markdown; render
                  it as rows instead of raw pipes (same treatment as the AI
                  Assistant workspace). The full markdown stays in the export. */}
              {resolvedIdentifiers.length > 0 && (
                <div style={{ display: "grid", gap: 5, marginTop: 12 }}>
                  <div style={sectionLabelStyle}>Values redacted before AI analysis</div>
                  {resolvedIdentifiers.map((row) => (
                    <div key={row.token} style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                      <span style={{ ...metaChipStyle, color: "#fbbf24", borderColor: "rgba(251,191,36,0.3)" }}>
                        {row.token}
                      </span>
                      <span style={{ fontSize: 10.5, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                        {row.category}
                      </span>
                      <span style={{ ...metaChipStyle, color: "var(--accent)", borderColor: "rgba(96,165,250,0.3)" }}>
                        {row.value}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {aiReport.sanitization_summary && Object.keys(aiReport.sanitization_summary).length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 12 }}>
                  {Object.entries(aiReport.sanitization_summary).map(([label, count]) => (
                    <span key={label} style={metaChipStyle}>
                      {count} {label} redacted
                    </span>
                  ))}
                </div>
              )}
            </>
          )}
        </ConsoleModule>
      )}

      {run.indicator_summary?.indicators?.length ? (
        <ConsoleModule
          title="What the sources found"
          description="Facts from the collectors — detections, the file a hash refers to, signatures, feed listings. The AI narrative above reads the alert text only."
          tone={run.overall_verdict === "malicious" ? "danger" : run.overall_verdict === "suspicious" ? "warning" : "info"}
        >
          <IndicatorSummaryCard summary={run.indicator_summary} />
        </ConsoleModule>
      ) : null}

      {eventReports.length > 0 && (
        <ConsoleModule
          title="Endpoint events"
          eyebrow={`${eventReports.length} event${eventReports.length === 1 ? "" : "s"} parsed from the alert body`}
          description="Sysmon/EDR process telemetry, scored on behaviour — what ran, as whom, under which parent."
          tone={
            eventReports.some((report) => report.verdict?.classification === "malicious")
              ? "danger"
              : eventReports.some((report) => report.verdict?.classification === "suspicious")
                ? "warning"
                : "info"
          }
        >
          <div style={{ display: "grid", gap: 10 }}>
            {eventReports.map((report, index) => (
              <EndpointEventCard key={`${report.event?.process_guid || index}`} report={report} />
            ))}
          </div>
        </ConsoleModule>
      )}

      <ConsoleModule
        title="Indicator reports"
        eyebrow={`${reports.length} JSON report${reports.length === 1 ? "" : "s"}`}
        description="One self-contained JSON report per extracted indicator — these follow the AI report in the exported list."
      >
        {reports.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
            {isActive ? "Collectors are still running…" : "No indicator reports were produced."}
          </div>
        ) : (
          <div style={{ display: "grid", gap: 10 }}>
            {reports.map((report, index) => {
              const key = `${report.indicator.type}:${report.indicator.value}:${index}`;
              const isOpen = !!expanded[key];
              const classification = report.verdict?.classification || "inconclusive";
              return (
                <div
                  key={key}
                  style={{
                    border: "1px solid var(--panel-divider-strong)",
                    borderRadius: 14,
                    background: "var(--bg-elevated)",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      padding: "12px 14px",
                      borderLeft: `3px solid ${verdictColor(classification)}`,
                      flexWrap: "wrap",
                    }}
                  >
                    <span style={typeBadgeStyle}>{report.indicator.type}</span>
                    <span
                      style={{
                        flex: 1,
                        minWidth: 220,
                        fontFamily: "var(--font-mono)",
                        fontSize: 12.5,
                        color: "var(--text)",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {report.indicator.value}
                    </span>

                    {report.investigation && (
                      <a
                        href={report.investigation.url || `/investigations/${report.investigation.investigation_id}`}
                        title={
                          report.status === "investigating"
                            ? `Full investigation running (${report.investigation.state}) — this report fills in when it concludes`
                            : "Opens the full investigation this verdict came from"
                        }
                        style={{
                          fontSize: 9.5,
                          fontWeight: 700,
                          letterSpacing: "0.04em",
                          textTransform: "uppercase",
                          padding: "2px 7px",
                          borderRadius: 20,
                          background:
                            report.status === "investigating" ? "rgba(251,191,36,0.14)" : "rgba(96,165,250,0.14)",
                          color: report.status === "investigating" ? "#fbbf24" : "#60a5fa",
                          fontFamily: "var(--font-sans)",
                          textDecoration: "none",
                        }}
                      >
                        {report.status === "investigating"
                          ? `investigating · ${report.investigation.state}`
                          : "investigation"}
                      </a>
                    )}

                    {report.status === "reused" && report.prior_investigation && (
                      <a
                        href={`/investigations/${report.prior_investigation.investigation_id}`}
                        title="Answered from an earlier investigation — no collector was spent"
                        style={{
                          fontSize: 9.5,
                          fontWeight: 700,
                          letterSpacing: "0.04em",
                          textTransform: "uppercase",
                          padding: "2px 7px",
                          borderRadius: 20,
                          background: "rgba(52,211,153,0.14)",
                          color: "#34d399",
                          fontFamily: "var(--font-sans)",
                          textDecoration: "none",
                        }}
                      >
                        reused
                        {report.prior_investigation.age_days != null
                          ? ` · ${Math.max(1, Math.round(report.prior_investigation.age_days))}d`
                          : ""}
                      </a>
                    )}

                    {report.status === "skipped" ? (
                      <span style={{ fontSize: 10.5, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                        skipped · {report.skip_reason?.replace(/_/g, " ")}
                      </span>
                    ) : (
                      <>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            letterSpacing: "0.05em",
                            textTransform: "uppercase",
                            color: verdictColor(classification),
                            fontFamily: "var(--font-sans)",
                          }}
                        >
                          {classification}
                        </span>
                        <span
                          style={{
                            fontSize: 13,
                            fontWeight: 700,
                            fontFamily: "var(--font-mono)",
                            color: riskColor(report.verdict?.risk_score || 0),
                            minWidth: 26,
                            textAlign: "right",
                          }}
                        >
                          {report.verdict?.risk_score ?? 0}
                        </span>
                      </>
                    )}

                    <button
                      onClick={() => setExpanded((prev) => ({ ...prev, [key]: !prev[key] }))}
                      style={{ ...secondaryButtonStyle, padding: "5px 10px", fontSize: 10 }}
                    >
                      {isOpen ? "Hide JSON" : "View JSON"}
                    </button>
                  </div>

                  {report.status !== "skipped" && (
                    <div style={{ padding: "0 14px 12px 17px", display: "grid", gap: 8 }}>
                      {report.status === "investigating" ? (
                        <div style={{ fontSize: 11.5, color: "#fbbf24", fontFamily: "var(--font-sans)" }}>
                          Full investigation in progress — the verdict, findings and evidence appear here (and in
                          the export) as soon as it concludes.
                        </div>
                      ) : (report.findings || []).length > 0 ? (
                        <div style={{ display: "grid", gap: 6 }}>
                          {report.findings.map((finding, i) => (
                            <FindingRow key={`${finding.collector}:${finding.type}:${i}`} finding={finding} />
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontSize: 11.5, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                          Nothing found — every source checked came back empty.
                        </div>
                      )}

                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {report.collector_runs.map((collectorRun) => (
                          <span
                            key={collectorRun.collector}
                            title={collectorRun.error || undefined}
                            style={{
                              fontSize: 10,
                              fontFamily: "var(--font-mono)",
                              padding: "2px 8px",
                              borderRadius: 20,
                              border: "1px solid var(--border)",
                              background: "var(--bg-input)",
                              color:
                                collectorRun.status === "failed"
                                  ? "#f87171"
                                  : collectorRun.status === "completed"
                                    ? "var(--text-secondary)"
                                    : "var(--text-muted)",
                            }}
                          >
                            {collectorRun.collector}
                            {collectorRun.status !== "completed" ? ` · ${collectorRun.status}` : ""}
                          </span>
                        ))}
                        {report.ip_lookup && (
                          <span
                            style={{
                              fontSize: 10,
                              fontFamily: "var(--font-mono)",
                              padding: "2px 8px",
                              borderRadius: 20,
                              border: "1px solid rgba(96,165,250,0.28)",
                              background: "rgba(96,165,250,0.10)",
                              color: "var(--accent)",
                            }}
                          >
                            ip lookup
                            {report.ip_lookup?.abuseipdb?.abuse_confidence_score != null
                              ? ` · abuse ${report.ip_lookup.abuseipdb.abuse_confidence_score}%`
                              : ""}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {isOpen && (
                    <pre
                      style={{
                        margin: 0,
                        padding: "12px 14px",
                        borderTop: "1px solid var(--panel-divider-strong)",
                        background: "var(--bg-input)",
                        maxHeight: 420,
                        overflow: "auto",
                        fontSize: 11,
                        lineHeight: 1.55,
                        fontFamily: "var(--font-mono)",
                        color: "var(--text-secondary)",
                      }}
                    >
                      {JSON.stringify(report, null, 2)}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </ConsoleModule>
    </div>
  );
}

function HeroStat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: "grid", gap: 2 }}>
      <span
        style={{
          fontSize: 18,
          fontWeight: 800,
          fontFamily: "var(--font-mono)",
          color: color || "var(--text)",
          lineHeight: 1,
        }}
      >
        {value}
      </span>
      <span
        style={{
          fontSize: 9.5,
          fontWeight: 600,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
          fontFamily: "var(--font-sans)",
        }}
      >
        {label}
      </span>
    </div>
  );
}

interface ResolvedIdentifierRow {
  token: string;
  category: string;
  value: string;
}

const RESOLVED_SECTION_RE = /---\s*\n+##\s*Resolved Identifiers[\s\S]*$/;

function parseResolvedIdentifiers(markdown: string): ResolvedIdentifierRow[] {
  const rows: ResolvedIdentifierRow[] = [];
  const section = markdown.match(/##\s*Resolved Identifiers[\s\S]*?\n+((?:\|.*\|\n?)+)/);
  if (!section) return rows;
  for (const line of section[1].split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim().replace(/^`|`$/g, ""));
    if (cells.length >= 4 && cells[1] && !cells[1].startsWith("-") && cells[1] !== "Token") {
      rows.push({ token: cells[1], category: cells[2], value: cells[3] });
    }
  }
  return rows;
}

function stripResolvedIdentifiers(markdown: string): string {
  return markdown.replace(RESOLVED_SECTION_RE, "").trim();
}

const SEVERITY_COLORS: Record<string, string> = {
  high: "#f87171",
  medium: "#fbbf24",
  low: "#a3a3a3",
  info: "#60a5fa",
};

function FindingRow({ finding }: { finding: AlertFinding }) {
  const [open, setOpen] = useState(false);
  const color = SEVERITY_COLORS[finding.severity] || "#94a3b8";
  const entries = Object.entries(finding.data || {});

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderLeft: `2px solid ${color}`,
        borderRadius: 8,
        background: "var(--bg-input)",
        padding: "7px 10px",
      }}
    >
      <div
        role={entries.length ? "button" : undefined}
        tabIndex={entries.length ? 0 : undefined}
        onClick={() => entries.length && setOpen((prev) => !prev)}
        onKeyDown={(event) => {
          if (entries.length && (event.key === "Enter" || event.key === " ")) {
            event.preventDefault();
            setOpen((prev) => !prev);
          }
        }}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 9,
          flexWrap: "wrap",
          cursor: entries.length ? "pointer" : "default",
        }}
      >
        <span
          style={{
            fontSize: 8.5,
            fontWeight: 800,
            letterSpacing: "0.07em",
            textTransform: "uppercase",
            color,
            fontFamily: "var(--font-sans)",
            minWidth: 46,
          }}
        >
          {finding.severity}
        </span>
        <span style={{ fontSize: 10.5, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
          {finding.source}
        </span>
        <span style={{ flex: 1, minWidth: 200, fontSize: 11.5, color: "var(--text)", fontFamily: "var(--font-sans)" }}>
          {finding.summary}
        </span>
        {entries.length > 0 && (
          <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
            {open ? "▾ hide detail" : `▸ ${entries.length} detail${entries.length === 1 ? "" : "s"}`}
          </span>
        )}
      </div>

      {open && entries.length > 0 && (
        <div style={{ display: "grid", gap: 4, marginTop: 8, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
          {entries.map(([key, value]) => (
            <div key={key} style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
              <span
                style={{
                  fontSize: 9.5,
                  color: "var(--text-muted)",
                  letterSpacing: "0.05em",
                  textTransform: "uppercase",
                  fontFamily: "var(--font-sans)",
                  minWidth: 140,
                }}
              >
                {key.replace(/_/g, " ")}
              </span>
              <span
                style={{
                  flex: 1,
                  minWidth: 220,
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  color: "var(--text-secondary)",
                  overflowWrap: "anywhere",
                  whiteSpace: "pre-wrap",
                }}
              >
                {formatFindingValue(value)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatFindingValue(value: any): string {
  if (value == null) return "—";
  if (Array.isArray(value)) {
    return value
      .map((item) => (typeof item === "object" ? JSON.stringify(item) : String(item)))
      .join("\n");
  }
  if (typeof value === "object") return JSON.stringify(value, null, 1);
  return String(value);
}

const sectionLabelStyle: React.CSSProperties = {
  fontSize: 9.5,
  fontWeight: 700,
  letterSpacing: "0.06em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
  fontFamily: "var(--font-sans)",
};

const metaChipStyle: React.CSSProperties = {
  fontSize: 10,
  fontFamily: "var(--font-mono)",
  padding: "2px 8px",
  borderRadius: 20,
  border: "1px solid var(--border)",
  background: "var(--bg-elevated)",
  color: "var(--text-secondary)",
};

const dangerButtonStyle: React.CSSProperties = {
  padding: "7px 14px",
  borderRadius: 8,
  border: "1px solid rgba(251, 113, 133, 0.28)",
  background: "rgba(127, 29, 29, 0.14)",
  color: "#fda4af",
  fontSize: 11,
  fontWeight: 600,
  fontFamily: "var(--font-sans)",
  cursor: "pointer",
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: "7px 14px",
  borderRadius: 8,
  border: "1px solid var(--border)",
  background: "var(--bg-elevated)",
  color: "var(--text-secondary)",
  fontSize: 11,
  fontWeight: 600,
  fontFamily: "var(--font-sans)",
  cursor: "pointer",
};

const typeBadgeStyle: React.CSSProperties = {
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: "0.06em",
  textTransform: "uppercase",
  padding: "3px 7px",
  borderRadius: 4,
  border: "1px solid rgba(129,140,248,0.25)",
  background: "rgba(129,140,248,0.12)",
  color: "#818cf8",
  fontFamily: "var(--font-mono)",
};

/* ─── Suppressing a shape of alert ─── */

/**
 * Suppression has to be narrower than the rule.
 *
 * One Wazuh rule accounts for most of this deployment's alerts and produced 173
 * malicious verdicts among them, so "mute the rule" is both the obvious action
 * and the wrong one. The dialog opens on a proposal that names the rule *and*
 * the agent *and* the event shape, and shows every condition before anything is
 * silenced — an analyst commits to a predicate they can read, not a checkbox.
 */
function SuppressDialog({
  runId,
  onClose,
  onDone,
}: {
  runId: string;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [candidate, setCandidate] = useState<SuppressionCandidate | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getSuppressionCandidate(runId)
      .then((data) => {
        if (cancelled) return;
        setCandidate(data);
        setSelected(Object.fromEntries(data.fields.map((f) => [f.field, f.field in data.proposed])));
      })
      .catch((e: any) => !cancelled && setError(e?.message || "Could not read this alert's fields"));
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const chosen = (candidate?.fields || []).filter((f) => selected[f.field]);
  const severityOnly = chosen.length > 0 && chosen.every((f) => f.severity_only);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const result = await createAlertExclusion({
        match_fields: Object.fromEntries(chosen.map((f) => [f.field, f.value])),
        reason: reason.trim(),
        added_by: "ui",
      });
      onDone(
        result.already_listed
          ? "That suppression already existed — it has been updated."
          : `Suppressed. Alerts matching all ${chosen.length} condition(s) will be recorded without collector spend.`,
      );
    } catch (e: any) {
      setError(e?.message || "Could not create the suppression");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Suppress this shape of alert"
      style={{
        position: "fixed", inset: 0, zIndex: 60, display: "grid", placeItems: "center",
        background: "rgba(2, 6, 23, 0.62)", padding: 20,
      }}
      onClick={onClose}
    >
      <div
        onClick={(event) => event.stopPropagation()}
        style={{
          width: "min(640px, 100%)", maxHeight: "84vh", overflowY: "auto",
          background: "var(--panel-card-bg)", border: "1px solid var(--panel-divider-strong)",
          borderRadius: 14, padding: 20, display: "grid", gap: 14,
        }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: 15, color: "var(--text)" }}>Suppress this shape of alert</h2>
          <p style={{ margin: "6px 0 0", fontSize: 12, color: "var(--text-muted)", lineHeight: 1.55 }}>
            Every condition below must match for an alert to be suppressed, so the same rule from a
            different agent keeps being investigated. Suppressed alerts are still recorded — with
            their entity and timing — so they still count towards correlation. Only the collector
            spend is skipped.
          </p>
        </div>

        {error && <div style={{ fontSize: 12, color: "var(--status-danger)" }}>{error}</div>}
        {!candidate && !error && (
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Reading this alert…</div>
        )}

        {candidate?.already_suppressed && (
          <div style={{ fontSize: 12, color: "var(--status-warning)" }}>
            This alert already matched a suppression when it arrived.
          </div>
        )}

        {candidate && (
          <>
            <div style={{ display: "grid", gap: 6 }}>
              {candidate.fields.map((f) => (
                <label
                  key={f.field}
                  style={{
                    display: "flex", alignItems: "baseline", gap: 10, fontSize: 12,
                    color: "var(--text)", cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={!!selected[f.field]}
                    onChange={(e) => setSelected({ ...selected, [f.field]: e.target.checked })}
                  />
                  <span style={{ minWidth: 128, color: "var(--text-muted)" }}>{f.field}</span>
                  <span style={{ fontFamily: "var(--font-mono)" }}>{f.value}</span>
                  {f.severity_only && (
                    <span
                      title="The sender's own severity. Alerts arrive here marked High that resolve benign, so it is wrong in at least one direction — never suppress on this alone."
                      style={{ color: "var(--status-warning)", fontSize: 10 }}
                    >
                      sender's severity
                    </span>
                  )}
                </label>
              ))}
            </div>

            {severityOnly && (
              <div style={{ fontSize: 12, color: "var(--status-warning)", lineHeight: 1.5 }}>
                Those are all the sender's own severity. Alerts arrive here marked High that resolve
                benign, so severity is wrong in at least one direction — add the rule or the agent.
              </div>
            )}

            <label style={{ display: "grid", gap: 5, fontSize: 12, color: "var(--text-muted)" }}>
              Why is this safe to skip?
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={2}
                placeholder="e.g. Routine appsec-agent status heartbeat, no security value"
                style={{
                  padding: "8px 10px", borderRadius: 8, border: "1px solid var(--border)",
                  background: "var(--bg-input)", color: "var(--text)", fontSize: 12, resize: "vertical",
                }}
              />
            </label>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={onClose} style={secondaryButtonStyle}>Cancel</button>
              <button
                onClick={save}
                disabled={saving || chosen.length === 0 || !reason.trim() || severityOnly}
                title={
                  chosen.length === 0 ? "Select at least one condition"
                    : !reason.trim() ? "A reason is required — an unexplained suppression is how a real detection gets silenced for a year"
                    : severityOnly ? "Add the rule or the agent"
                    : `Suppress alerts matching all ${chosen.length} condition(s)`
                }
                style={{
                  ...secondaryButtonStyle,
                  borderColor: "var(--status-warning)",
                  color: "var(--status-warning)",
                  opacity: saving || chosen.length === 0 || !reason.trim() || severityOnly ? 0.5 : 1,
                }}
              >
                {saving ? "Suppressing…" : `Suppress (${chosen.length} condition${chosen.length === 1 ? "" : "s"})`}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ─── This alert is not the whole story ─── */

/**
 * The one thing a single alert cannot tell you about itself.
 *
 * Kerberoasting on a domain controller is suspicious; an account being changed
 * is routine; the two on the same machine within the hour is an intrusion. Both
 * alerts were investigated here and neither could say that, because each was
 * judged alone. This is that sentence, at the top of whichever one you opened.
 */
function CaseBanner({ runCase, currentRunId }: { runCase: CorrelatedCase; currentRunId: string }) {
  const [open, setOpen] = useState(false);
  const tone =
    runCase.score >= 70 ? "var(--status-danger)"
      : runCase.score >= 40 ? "var(--status-warning)"
      : "var(--text-muted)";

  return (
    <section
      style={{
        border: `1px solid ${tone}`,
        borderLeftWidth: 3,
        borderRadius: 12,
        padding: "12px 16px",
        background: "var(--panel-card-bg)",
        display: "grid",
        gap: 8,
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <strong style={{ color: tone, fontSize: 13 }}>
          Part of a wider pattern on {runCase.entity_host}
        </strong>
        <span style={{ color: "var(--text-muted)", fontSize: 12 }}>
          {runCase.alert_count} alerts from {runCase.distinct_rules} independent detections in{" "}
          {runCase.window_hours}h
        </span>
        <span style={{ marginLeft: "auto", color: tone, fontFamily: "var(--font-mono)", fontSize: 12 }}>
          {runCase.score}/100
        </span>
      </div>

      <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.6 }}>
        {runCase.reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>

      {runCase.tactics.length > 0 && (
        <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
          Evidenced tactics: <span style={{ color: "var(--text)" }}>{runCase.tactics.join(" → ")}</span>
        </div>
      )}

      <button
        onClick={() => setOpen(!open)}
        style={{
          justifySelf: "start", background: "none", border: "none", padding: 0,
          color: "var(--accent)", fontSize: 12, cursor: "pointer",
        }}
      >
        {open ? "Hide the other alerts" : `Show the other ${runCase.alert_count - 1} alert(s)`}
      </button>

      {open && (
        <div style={{ display: "grid", gap: 4, paddingLeft: 4 }}>
          {runCase.alerts.map((alert) => {
            const isCurrent = alert.run_id === currentRunId;
            return (
              <div key={alert.run_id} style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                <span style={{ color: "var(--text-dim)", fontSize: 11, fontFamily: "var(--font-mono)", minWidth: 132 }}>
                  {alert.created_at ? new Date(alert.created_at).toLocaleString() : "—"}
                </span>
                {isCurrent ? (
                  <span style={{ fontSize: 12, color: "var(--text)", fontWeight: 700 }}>
                    {alert.detection_rule_name || alert.title} (this alert)
                  </span>
                ) : (
                  <a
                    href={`/alert-investigations/${alert.run_id}`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: 12, color: "var(--accent)" }}
                  >
                    {alert.detection_rule_name || alert.title}
                  </a>
                )}
                {alert.overall_verdict && (
                  <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    {alert.overall_verdict}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

