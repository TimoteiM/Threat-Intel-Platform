"use client";

/**
 * Report preview — renders the `format=report` export, document by document.
 *
 * The page fetches the export endpoint itself rather than rebuilding the view
 * from other API calls, so whatever an analyst reviews here is byte-for-byte
 * what the reporting platform receives. Each document is shown with its
 * `report_type` and can be expanded to its raw JSON.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";

import ConsoleModule from "@/components/ui/ConsoleModule";
import EndpointEventCard from "@/components/report/EndpointEventCard";
import IndicatorSummaryCard from "@/components/report/IndicatorSummaryCard";
import PageHero from "@/components/ui/PageHero";
import { alertInvestigationExportUrl, getAlertInvestigationReportList } from "@/lib/api";
import type {
  AlertEndpointEventReport,
  AlertExecutiveSummaryDocument,
  AlertReportDocument,
  AlertReportIndicatorDocument,
  SocReport,
  SocReportKeyValue,
  SocReportSection,
} from "@/lib/types";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
  not_investigated: "#64748b",
};

const SEVERITY_COLORS: Record<string, string> = {
  high: "#f87171",
  critical: "#f87171",
  medium: "#fbbf24",
  low: "#60a5fa",
  info: "#94a3b8",
  informational: "#94a3b8",
};

function verdictColor(value?: string | null): string {
  return VERDICT_COLORS[String(value || "").toLowerCase()] || "#94a3b8";
}

function severityColor(value?: string | null): string {
  return SEVERITY_COLORS[String(value || "").toLowerCase()] || "#94a3b8";
}

function isExecutiveSummary(doc: AlertReportDocument): doc is AlertExecutiveSummaryDocument {
  return doc.report_type === "executive_summary";
}

function isEndpointEvent(doc: AlertReportDocument): doc is AlertEndpointEventReport {
  return doc.report_type === "endpoint_event";
}

/** Alert titles are whole alert bodies — the full text stays in the summary card. */
function shortTitle(title?: string): string {
  const text = String(title || "").replace(/\s+/g, " ").trim();
  return text.length > 80 ? `${text.slice(0, 79)}…` : text;
}

export default function AlertReportPreviewPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const runId = String(params?.id || "");

  const [documents, setDocuments] = useState<AlertReportDocument[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [rawOpen, setRawOpen] = useState<Record<number, boolean>>({});

  const load = useCallback(async () => {
    try {
      setDocuments(await getAlertInvestigationReportList(runId));
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Could not load the report export");
    } finally {
      setLoading(false);
    }
  }, [runId]);

  useEffect(() => {
    if (runId) load();
  }, [runId, load]);

  const summaryDoc = useMemo(
    () => (documents || []).find(isExecutiveSummary) || null,
    [documents],
  );
  const eventDocs = useMemo(
    () => (documents || []).filter(isEndpointEvent),
    [documents],
  );
  const indicatorDocs = useMemo(
    () =>
      (documents || []).filter(
        (doc): doc is AlertReportIndicatorDocument =>
          !isExecutiveSummary(doc) && !isEndpointEvent(doc),
      ),
    [documents],
  );
  const coverage = useMemo(() => {
    const withReport = indicatorDocs.filter((doc) => !!doc.soc_report).length;
    const skipped = indicatorDocs.filter((doc) => doc.status === "skipped").length;
    const running = indicatorDocs.filter((doc) => doc.status === "investigating").length;
    return { withReport, skipped, running, inline: indicatorDocs.length - withReport - skipped - running };
  }, [indicatorDocs]);

  if (loading) {
    return <div style={{ padding: 40, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>Loading report export…</div>;
  }

  if (error || !documents) {
    return (
      <div style={{ padding: 40 }}>
        <div style={{ color: "#f87171", fontFamily: "var(--font-sans)", marginBottom: 12 }}>
          {error || "No report export available"}
        </div>
        <button onClick={() => router.push(`/alert-investigations/${runId}`)} style={buttonStyle}>
          Back to the alert investigation
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 18, paddingBottom: 56 }}>
      <PageHero
        eyebrow="Report Export Preview"
        // Alert titles are the raw alert body — keep the hero to one line.
        title={shortTitle(summaryDoc?.title) || "Alert report list"}
        description={
          `${documents.length} document${documents.length === 1 ? "" : "s"} — 1 executive summary + ` +
          `${indicatorDocs.length} indicator${indicatorDocs.length === 1 ? "" : "s"}. ` +
          "This is the exact JSON array served by format=report."
        }
        tone={summaryDoc?.overall_verdict === "malicious" ? "danger" : "info"}
        stats={
          <div style={{ display: "flex", gap: 22, flexWrap: "wrap" }}>
            <HeroStat label="Full SOC reports" value={String(coverage.withReport)} color="#60a5fa" />
            <HeroStat label="IOC-only findings" value={String(coverage.inline)} />
            <HeroStat label="Still running" value={String(coverage.running)} color={coverage.running ? "#fbbf24" : undefined} />
            <HeroStat label="Context-only" value={String(coverage.skipped)} />
            {eventDocs.length > 0 && (
              <HeroStat label="Endpoint events" value={String(eventDocs.length)} color="#a78bfa" />
            )}
          </div>
        }
        actions={
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button onClick={() => router.push(`/alert-investigations/${runId}`)} style={buttonStyle}>
              Back to run
            </button>
            <a
              href={alertInvestigationExportUrl(runId, { format: "report" })}
              style={{ ...buttonStyle, textDecoration: "none", display: "inline-block" }}
            >
              Download this JSON
            </a>
            <button onClick={load} style={buttonStyle}>
              Refresh
            </button>
          </div>
        }
      />

      {coverage.running > 0 && (
        <ConsoleModule title="Still collecting" tone="warning" compact>
          <div style={{ fontSize: 12, color: "#fbbf24", fontFamily: "var(--font-sans)" }}>
            {coverage.running} indicator{coverage.running === 1 ? "" : "s"} still have an investigation running — their
            SOC report appears here (and in the export) once it concludes. Refresh to check.
          </div>
        </ConsoleModule>
      )}

      {summaryDoc && (
        <ExecutiveSummaryCard
          doc={summaryDoc}
          index={0}
          open={!!rawOpen[0]}
          onToggleRaw={() => setRawOpen((prev) => ({ ...prev, 0: !prev[0] }))}
        />
      )}

      {eventDocs.map((doc, i) => (
        <ConsoleModule
          key={`event:${i}`}
          title="Endpoint event"
          eyebrow={`Document ${i + 1} · report_type: endpoint_event`}
          description="Sysmon/EDR process telemetry parsed from the alert body and scored on behaviour."
          tone={doc.verdict?.classification === "malicious" ? "danger" : doc.verdict?.classification === "suspicious" ? "warning" : "info"}
        >
          <EndpointEventCard report={doc} />
        </ConsoleModule>
      ))}

      {indicatorDocs.map((doc, i) => {
        const index = eventDocs.length + i + 1;
        return (
          <IndicatorCard
            key={`${doc.indicator?.value}:${index}`}
            doc={doc}
            index={index}
            open={!!rawOpen[index]}
            onToggleRaw={() => setRawOpen((prev) => ({ ...prev, [index]: !prev[index] }))}
          />
        );
      })}
    </div>
  );
}

/* ── Document 0 ───────────────────────────────────────────────────────────── */

function ExecutiveSummaryCard({
  doc,
  index,
  open,
  onToggleRaw,
}: {
  doc: AlertExecutiveSummaryDocument;
  index: number;
  open: boolean;
  onToggleRaw: () => void;
}) {
  const summary = doc.summary;
  return (
    <ConsoleModule
      title="Executive summary"
      eyebrow={`Document ${index} · report_type: executive_summary`}
      description="Run metadata, verdict roll-up and the AI assistant's reading of the alert body."
      tone={doc.overall_verdict === "malicious" ? "danger" : "info"}
      actions={<RawToggle open={open} onToggle={onToggleRaw} />}
    >
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
          <Chip label="Verdict" value={doc.overall_verdict} color={verdictColor(doc.overall_verdict)} />
          <Chip label="Highest risk" value={String(doc.highest_risk_score ?? 0)} />
          <Chip label="Status" value={doc.status} />
          <Chip label="Indicators" value={String(summary?.indicators_total ?? 0)} />
          {!!summary?.indicators_reused && <Chip label="Reused" value={String(summary.indicators_reused)} />}
        </div>

        {!!doc.investigations?.length && (
          <Table
            headers={["Indicator", "Investigation", "State", "Classification", "Risk", "Origin"]}
            rows={doc.investigations.map((item) => [
              item.indicator || "—",
              <a key={item.investigation_id} href={item.url} style={{ color: "#60a5fa" }}>
                {item.investigation_id.slice(0, 8)}…
              </a>,
              item.state || "—",
              item.classification || "—",
              item.risk_score ?? "—",
              item.reused ? "reused" : "this run",
            ])}
          />
        )}

        {doc.indicator_summary?.indicators?.length ? (
          <Block title="What the sources found">
            <IndicatorSummaryCard summary={doc.indicator_summary} />
          </Block>
        ) : null}

        {doc.ai_analysis?.report_markdown && (
          <Block title="AI reading of the alert">
            <pre style={preStyle}>{doc.ai_analysis.report_markdown}</pre>
          </Block>
        )}

        {doc.alert_body && (
          <Block title="Alert body (as received)">
            <pre style={{ ...preStyle, maxHeight: 180 }}>{doc.alert_body}</pre>
          </Block>
        )}

        {open && <RawJson value={doc} />}
      </div>
    </ConsoleModule>
  );
}

/* ── One indicator ────────────────────────────────────────────────────────── */

function IndicatorCard({
  doc,
  index,
  open,
  onToggleRaw,
}: {
  doc: AlertReportIndicatorDocument;
  index: number;
  open: boolean;
  onToggleRaw: () => void;
}) {
  const investigation = doc.investigation || doc.prior_investigation;
  const classification = doc.verdict?.classification;
  return (
    <ConsoleModule
      title={doc.indicator?.value || "Indicator"}
      eyebrow={`Document ${index} · ${doc.indicator?.type || "indicator"} · status: ${doc.status}`}
      description={
        doc.soc_report
          ? "Full SOC report — every section our PDF prints is in this document."
          : doc.status === "skipped"
            ? `Context only — ${(doc.skip_reason || "not investigated").replace(/_/g, " ")}.`
            : "IOC-level findings (no full investigation is run for this indicator type)."
      }
      tone={classification === "malicious" ? "danger" : classification === "suspicious" ? "warning" : "info"}
      actions={<RawToggle open={open} onToggle={onToggleRaw} />}
    >
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
          <Chip label="Verdict" value={classification} color={verdictColor(classification)} />
          <Chip label="Risk" value={String(doc.verdict?.risk_score ?? 0)} />
          {doc.verdict?.confidence != null && <Chip label="Confidence" value={String(doc.verdict.confidence)} />}
          {investigation?.investigation_id && (
            <a href={(investigation as any).url || `/investigations/${investigation.investigation_id}`} style={linkChipStyle}>
              {doc.prior_investigation ? "reused investigation ↗" : "investigation ↗"}
            </a>
          )}
        </div>

        {!!doc.verdict?.reasons?.length && (
          <Block title="Why">
            <ul style={listStyle}>
              {doc.verdict.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          </Block>
        )}

        {doc.soc_report ? (
          <SocReportView report={doc.soc_report} />
        ) : (
          !!doc.findings?.length && (
            <Block title={`Findings (${doc.findings.length})`}>
              <Table
                headers={["Source", "Severity", "Summary"]}
                rows={doc.findings.map((finding) => [
                  finding.collector,
                  <span key="s" style={{ color: severityColor(finding.severity) }}>{finding.severity}</span>,
                  finding.summary,
                ])}
              />
            </Block>
          )
        )}

        {open && <RawJson value={doc} />}
      </div>
    </ConsoleModule>
  );
}

/* ── The SOC report, section by section (mirrors templates/soc_report.html) ── */

function SocReportView({ report }: { report: SocReport }) {
  const derived = report.derived_intelligence || {};
  const engine = derived.confidence_engine || {};
  const iocQuality = derived.ioc_quality || {};

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
        <Chip label="Classification" value={report.verdict?.classification} color={verdictColor(report.verdict?.classification)} />
        <Chip label="Confidence" value={report.verdict?.confidence} />
        <Chip label="Risk score" value={`${report.verdict?.risk_score ?? 0}/100`} />
        <Chip label="Action" value={report.verdict?.recommended_action} />
      </div>

      {!!report.case_metadata?.length && (
        <Block title="Case metadata">
          <KeyValues rows={report.case_metadata} />
        </Block>
      )}

      {report.summary && (
        <Block title="1. Executive summary">
          <p style={paragraphStyle}>{report.summary}</p>
        </Block>
      )}

      {(!!report.assessment_points?.length || report.verdict?.risk_rationale) && (
        <Block title="2. Analyst assessment">
          <ul style={listStyle}>
            {(report.assessment_points || []).map((point, i) => (
              <li key={i}>{point}</li>
            ))}
          </ul>
          {report.verdict?.risk_rationale && (
            <p style={{ ...paragraphStyle, color: "var(--text-muted)", marginTop: 6 }}>
              <strong>Risk rationale:</strong> {report.verdict.risk_rationale}
            </p>
          )}
        </Block>
      )}

      {!!report.key_evidence?.length && (
        <Block title={`3. Evidence matrix (${report.key_evidence.length})`}>
          <Table
            headers={["Source", "Reference", "Observed value / SOC relevance"]}
            rows={report.key_evidence.map((row) => [
              row.source,
              <code key="r" style={codeStyle}>{row.ref}</code>,
              <span key="v">
                {row.value}
                {row.relevance && (
                  <span style={{ display: "block", color: "var(--text-muted)", fontSize: 10.5, marginTop: 2 }}>
                    {row.relevance}
                  </span>
                )}
              </span>,
            ])}
          />
        </Block>
      )}

      {!!report.findings?.length && (
        <Block title={`4. Findings (${report.findings.length})`}>
          <div style={{ display: "grid", gap: 8 }}>
            {report.findings.map((finding, i) => (
              <div
                key={`${finding.id || finding.title}:${i}`}
                style={{
                  border: "1px solid var(--border)",
                  borderLeft: `3px solid ${severityColor(finding.severity)}`,
                  borderRadius: 8,
                  padding: "8px 10px",
                  background: "var(--bg-input)",
                }}
              >
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={{ fontSize: 9.5, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase", color: severityColor(finding.severity) }}>
                    {finding.severity}
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text)" }}>{finding.title}</span>
                  {finding.ttp_name && <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{finding.ttp_name}</span>}
                </div>
                {finding.description && (
                  <div style={{ fontSize: 11.5, color: "var(--text-secondary)", marginTop: 4, lineHeight: 1.55 }}>
                    {finding.description}
                  </div>
                )}
                {!!finding.evidence_arguments?.length && (
                  <div style={{ marginTop: 6 }}>
                    <Table
                      headers={["Reference", "Evidence argument"]}
                      rows={finding.evidence_arguments.map((arg) => [
                        <code key="r" style={codeStyle}>{arg.ref}</code>,
                        arg.argument,
                      ])}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Block>
      )}

      {!!report.iocs?.length && (
        <Block title={`5. Indicators of compromise (${report.iocs.length})`}>
          <Table
            headers={["Type", "Value", "Context", "Confidence"]}
            rows={report.iocs.map((ioc) => [ioc.type, <code key="v" style={codeStyle}>{ioc.value}</code>, ioc.context || "—", ioc.confidence || "—"])}
          />
        </Block>
      )}

      {!!report.recommendations?.length && (
        <Block title={`6. Recommended SOC actions (${report.recommendations.length})`}>
          <ol style={listStyle}>
            {report.recommendations.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ol>
        </Block>
      )}

      {!!Object.keys(engine).length && (
        <Block title="7. Derived SOC intelligence verdict">
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginBottom: 6 }}>
            <Chip label="Derived verdict" value={engine.verdict} color={verdictColor(engine.verdict)} />
            <Chip label="Derived score" value={`${engine.score ?? 0}/100`} />
            <Chip label="Confidence" value={`${engine.confidence || "?"} (${engine.confidence_percent ?? "?"}%)`} />
            <Chip label="Source components" value={String((engine.components || []).length)} />
          </div>
          {!!engine.reasons?.length && (
            <ul style={listStyle}>
              {engine.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          )}
        </Block>
      )}

      {!!iocQuality.items?.length && (
        <Block
          title={`8. IOC quality and actionability (${iocQuality.items.length}${
            iocQuality.total_items && iocQuality.total_items > iocQuality.items.length
              ? ` of ${iocQuality.total_items}`
              : ""
          })`}
        >
          <Table
            headers={["Type", "Value", "Quality", "Labels", "Action"]}
            rows={iocQuality.items.map((item) => [
              item.type,
              <code key="v" style={codeStyle}>{item.value}</code>,
              item.quality_score ?? "—",
              (item.labels || []).join(", ") || "—",
              item.recommended_action || "—",
            ])}
          />
        </Block>
      )}

      {!!report.signals?.length && (
        <Block title={`Appendix — generated signals (${report.signals.length})`}>
          <Table
            headers={["Severity", "Description"]}
            rows={report.signals.map((signal) => [
              <span key="s" style={{ color: severityColor(signal.severity) }}>{signal.severity}</span>,
              signal.description,
            ])}
          />
        </Block>
      )}

      {!!report.evidence_sections?.length && (
        <Block title={`Appendix — detailed technical evidence (${report.evidence_sections.length} sections)`}>
          <div style={{ display: "grid", gap: 10 }}>
            {report.evidence_sections.map((section) => (
              <EvidenceSection key={section.title} section={section} />
            ))}
          </div>
        </Block>
      )}

      {!!report.methodology?.length && (
        <Block title="Appendix — methodology">
          <ol style={listStyle}>
            {report.methodology.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </Block>
      )}
    </div>
  );
}

function EvidenceSection({ section }: { section: SocReportSection }) {
  const hasRows = !!section.rows?.length;
  const hasTable = !!section.table?.rows?.length;
  if (!hasRows && !hasTable) {
    return (
      <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
        {section.title} — collector ran, nothing to report
      </div>
    );
  }
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: "8px 10px", background: "var(--bg-input)" }}>
      <div style={{ fontSize: 11.5, fontWeight: 700, color: "var(--text)", marginBottom: 6, fontFamily: "var(--font-sans)" }}>
        {section.title}
      </div>
      {hasRows && <KeyValues rows={section.rows!} />}
      {hasTable && (
        <div style={{ marginTop: hasRows ? 8 : 0 }}>
          <Table headers={section.table!.headers} rows={section.table!.rows} />
        </div>
      )}
    </div>
  );
}

/* ── Small building blocks ────────────────────────────────────────────────── */

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div
        style={{
          fontSize: 10.5,
          fontWeight: 700,
          letterSpacing: "0.05em",
          textTransform: "uppercase",
          color: "var(--text-dim)",
          fontFamily: "var(--font-sans)",
          marginBottom: 6,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function KeyValues({ rows }: { rows: SocReportKeyValue[] }) {
  const visible = rows.filter((row) => row.value !== null && row.value !== undefined && String(row.value) !== "");
  if (!visible.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "4px 18px" }}>
      {visible.map((row, i) => (
        <div key={`${row.label}:${i}`} style={{ display: "flex", gap: 8, fontSize: 11.5, lineHeight: 1.6 }}>
          <span style={{ color: "var(--text-muted)", minWidth: 120, fontFamily: "var(--font-sans)" }}>{row.label}</span>
          <span style={{ color: "var(--text)", fontFamily: row.mono ? "var(--font-mono)" : "var(--font-sans)", overflowWrap: "anywhere" }}>
            {String(row.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: React.ReactNode[][] }) {
  if (!rows.length) return null;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5, fontFamily: "var(--font-sans)" }}>
        <thead>
          <tr>
            {headers.map((header) => (
              <th
                key={header}
                style={{
                  textAlign: "left",
                  padding: "5px 8px",
                  borderBottom: "1px solid var(--panel-divider-strong)",
                  color: "var(--text-dim)",
                  fontSize: 10,
                  letterSpacing: "0.05em",
                  textTransform: "uppercase",
                  whiteSpace: "nowrap",
                }}
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <td
                  key={j}
                  style={{
                    padding: "5px 8px",
                    borderBottom: "1px solid var(--border)",
                    color: "var(--text-secondary)",
                    verticalAlign: "top",
                    overflowWrap: "anywhere",
                  }}
                >
                  {cell as React.ReactNode}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Chip({ label, value, color }: { label: string; value?: string | null; color?: string }) {
  return (
    <div style={{ display: "grid", gap: 2 }}>
      <span style={{ fontSize: 9.5, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
        {label}
      </span>
      <span style={{ fontSize: 12.5, fontWeight: 700, color: color || "var(--text)", fontFamily: "var(--font-mono)" }}>
        {value || "—"}
      </span>
    </div>
  );
}

function RawToggle({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <button onClick={onToggle} style={{ ...buttonStyle, padding: "5px 10px", fontSize: 10 }}>
      {open ? "Hide JSON" : "View JSON"}
    </button>
  );
}

function RawJson({ value }: { value: unknown }) {
  return <pre style={{ ...preStyle, maxHeight: 420 }}>{JSON.stringify(value, null, 2)}</pre>;
}

function HeroStat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: "grid", gap: 2 }}>
      <span style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
        {label}
      </span>
      <span style={{ fontSize: 18, fontWeight: 700, color: color || "var(--text)", fontFamily: "var(--font-mono)" }}>{value}</span>
    </div>
  );
}

const buttonStyle: React.CSSProperties = {
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

const linkChipStyle: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 700,
  letterSpacing: "0.04em",
  textTransform: "uppercase",
  padding: "3px 8px",
  borderRadius: 20,
  background: "rgba(96,165,250,0.14)",
  color: "#60a5fa",
  fontFamily: "var(--font-sans)",
  textDecoration: "none",
};

const preStyle: React.CSSProperties = {
  margin: 0,
  padding: "10px 12px",
  borderRadius: 8,
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  maxHeight: 300,
  overflow: "auto",
  fontSize: 11,
  lineHeight: 1.6,
  color: "var(--text-secondary)",
  fontFamily: "var(--font-mono)",
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
};

const paragraphStyle: React.CSSProperties = {
  margin: 0,
  fontSize: 12,
  lineHeight: 1.65,
  color: "var(--text-secondary)",
  fontFamily: "var(--font-sans)",
};

const listStyle: React.CSSProperties = {
  margin: 0,
  paddingLeft: 18,
  fontSize: 12,
  lineHeight: 1.7,
  color: "var(--text-secondary)",
  fontFamily: "var(--font-sans)",
};

const codeStyle: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "var(--text)",
};
