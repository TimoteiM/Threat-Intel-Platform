"use client";

import React from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  MarkerType,
  MiniMap,
  Node,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";

import EvidenceTable from "@/components/evidence/EvidenceTable";
import { getArtifactUrl } from "@/lib/api";

type Props = {
  intelligence?: any;
  report?: any;
  evidence?: any;
  detail?: any;
  loading?: boolean;
};

type SocTab = "score" | "timeline" | "graph" | "iocs" | "screenshots" | "collectors" | "changes" | "notes" | "opencti" | "report";

const TAB_LABELS: Array<{ id: SocTab; label: string }> = [
  { id: "score", label: "Score" },
  { id: "timeline", label: "Timeline" },
  { id: "graph", label: "Graph" },
  { id: "iocs", label: "IOC Actions" },
  { id: "screenshots", label: "Screenshots" },
  { id: "collectors", label: "Collectors" },
  { id: "changes", label: "Changes" },
  { id: "notes", label: "Notes" },
  { id: "opencti", label: "OpenCTI" },
  { id: "report", label: "Report" },
];

function arr(value: any): any[] {
  return Array.isArray(value) ? value : [];
}

function text(value: any, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function asNumber(value: any): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function toneFromVerdict(verdict: string): { color: string; bg: string; border: string } {
  const normalized = String(verdict || "").toLowerCase();
  if (normalized === "malicious") return { color: "var(--red)", bg: "rgba(251,113,133,0.10)", border: "rgba(251,113,133,0.28)" };
  if (normalized === "suspicious") return { color: "var(--yellow)", bg: "rgba(251,191,36,0.10)", border: "rgba(251,191,36,0.28)" };
  if (normalized === "benign") return { color: "var(--green)", bg: "rgba(56,217,169,0.10)", border: "rgba(56,217,169,0.28)" };
  return { color: "var(--accent)", bg: "rgba(102,168,255,0.08)", border: "rgba(102,168,255,0.24)" };
}

function severityColor(severity: string) {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "danger") return "var(--red)";
  if (normalized === "warning") return "var(--yellow)";
  if (normalized === "success") return "var(--green)";
  return "var(--accent)";
}

function formatDate(value: any): string {
  if (!value) return "Undated";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function truncate(value: any, max = 90): string {
  const raw = text(value, "");
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 3)}...`;
}

export default function SocIntelligenceTab({ intelligence, report, evidence, detail, loading }: Props) {
  const [active, setActive] = React.useState<SocTab>("score");
  const notesKey = `soc-analyst-notes:${text(detail?.id || detail?.domain || evidence?.domain, "current")}`;
  const [analystNotes, setAnalystNotes] = React.useState("");
  const [analystOverride, setAnalystOverride] = React.useState("");

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const stored = JSON.parse(window.localStorage.getItem(notesKey) || "{}");
      setAnalystNotes(String(stored.notes || ""));
      setAnalystOverride(String(stored.override || ""));
    } catch {
      setAnalystNotes("");
      setAnalystOverride("");
    }
  }, [notesKey]);

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(notesKey, JSON.stringify({ notes: analystNotes, override: analystOverride }));
    } catch {
      // Browser storage may be disabled; notes remain available in component state.
    }
  }, [analystNotes, analystOverride, notesKey]);

  if (loading) {
    return <EmptyState label="Building SOC intelligence..." />;
  }

  if (!intelligence) {
    return <EmptyState label="No derived SOC intelligence is available yet." />;
  }

  const confidence = intelligence?.confidence_engine || {};
  const timeline = arr(intelligence?.evidence_timeline);
  const graph = intelligence?.investigation_graph || {};
  const iocQuality = intelligence?.ioc_quality || {};
  const opencti = intelligence?.opencti_resolver || {};
  const reportBuilder = intelligence?.soc_report_builder || {};
  const tone = toneFromVerdict(confidence?.verdict);

  return (
    <div style={{ display: "grid", gap: 18 }}>
      <div style={metricGridStyle}>
        <Metric label="Verdict" value={text(confidence?.verdict, "unknown").toUpperCase()} color={tone.color} />
        <Metric label="Score" value={`${text(confidence?.score, "0")}/100`} color={tone.color} />
        <Metric label="Confidence" value={text(confidence?.confidence, "unknown").toUpperCase()} color="var(--accent)" />
        <Metric label="Actionable IOCs" value={text(iocQuality?.summary?.actionable_count, "0")} color="var(--green)" />
      </div>

      <div style={segmentedStyle}>
        {TAB_LABELS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActive(tab.id)}
            style={{
              ...segmentButtonStyle,
              color: active === tab.id ? "var(--text-strong)" : "var(--text-secondary)",
              background: active === tab.id ? "rgba(102,168,255,0.14)" : "transparent",
              borderColor: active === tab.id ? "rgba(102,168,255,0.38)" : "transparent",
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {active === "score" && <ScoreBreakdownPanel confidence={confidence} evidence={evidence} report={report} detail={detail} />}
      {active === "timeline" && <TimelinePanel timeline={timeline} />}
      {active === "graph" && <GraphPanel graph={graph} />}
      {active === "iocs" && <IocActionPanel iocQuality={iocQuality} />}
      {active === "screenshots" && <ScreenshotGalleryPanel evidence={evidence} />}
      {active === "collectors" && <CollectorHealthPanel evidence={evidence} />}
      {active === "changes" && <ChangeDetectionPanel evidence={evidence} detail={detail} />}
      {active === "notes" && (
        <AnalystNotesPanel
          notes={analystNotes}
          override={analystOverride}
          onNotesChange={setAnalystNotes}
          onOverrideChange={setAnalystOverride}
        />
      )}
      {active === "opencti" && <OpenCtiPanel opencti={opencti} />}
      {active === "report" && (
        <ReportPreviewPanel
          reportBuilder={reportBuilder}
          confidence={confidence}
          iocQuality={iocQuality}
          report={report}
          evidence={evidence}
          detail={detail}
        />
      )}
    </div>
  );
}

function ScoreBreakdownPanel({ confidence, evidence, report, detail }: { confidence: any; evidence: any; report: any; detail: any }) {
  const components = arr(confidence?.components);
  const finalRisk = evidence?.final_risk || {};
  const votes = confidence?.source_agreement || {};
  const tone = toneFromVerdict(confidence?.verdict || report?.classification || detail?.classification);

  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Derived Verdict" value={text(confidence?.verdict, "unknown").toUpperCase()} color={tone.color} compact />
        <Metric label="Derived Score" value={`${text(confidence?.score, "0")}/100`} color={tone.color} compact />
        <Metric label="Final Risk" value={`${text(finalRisk?.risk_score ?? finalRisk?.score, "-")}/100`} color="var(--accent)" compact />
        <Metric label="Agreement" value={`${asNumber(votes.malicious) + asNumber(votes.suspicious)} risk votes`} color="var(--yellow)" compact />
      </div>
      <div style={twoColStyle}>
        <div>
          <SectionTitle title="Component Scores" />
          <div style={{ display: "grid", gap: 10 }}>
            {components.length ? components.map((component: any, idx: number) => (
              <ComponentScore key={`${component?.source}-${idx}`} component={component} />
            )) : <EmptyState label="No scoring components available." compact />}
          </div>
        </div>
        <div>
          <SectionTitle title="Source Agreement" />
          <EvidenceTable
            data={[
              { verdict: "Malicious", count: votes.malicious || 0 },
              { verdict: "Suspicious", count: votes.suspicious || 0 },
              { verdict: "Benign", count: votes.benign || 0 },
              { verdict: "Unknown", count: votes.unknown || 0 },
            ]}
            columns={[{ key: "verdict" }, { key: "count" }]}
          />
          <SectionTitle title="Final Risk Rationale" />
          <Bullets items={arr(finalRisk?.rationale)} empty="No final-risk rationale is available." />
        </div>
      </div>
    </section>
  );
}

function IocActionPanel({ iocQuality }: { iocQuality: any }) {
  const items = arr(iocQuality?.items);
  const summary = iocQuality?.summary || {};
  const blockNow = items.filter((ioc: any) => {
    const action = String(ioc?.recommended_action || "").toLowerCase();
    return action.includes("block") || (asNumber(ioc?.quality_score) >= 75 && arr(ioc?.labels).includes("actionable"));
  });
  const monitor = items.filter((ioc: any) => String(ioc?.recommended_action || "").toLowerCase().includes("monitor"));
  const enrich = items.filter((ioc: any) => String(ioc?.recommended_action || "").toLowerCase().match(/enrich|review|validate/));
  if (!items.length) return <EmptyState label="No IOCs were available for quality scoring." />;

  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Block Now" value={blockNow.length} color="var(--red)" compact />
        <Metric label="Monitor" value={monitor.length} color="var(--yellow)" compact />
        <Metric label="Needs Enrichment" value={enrich.length} color="var(--accent)" compact />
        <Metric label="Actionable" value={text(summary.actionable_count, "0")} color="var(--green)" compact />
      </div>
      <EvidenceTable
        title="IOC Action Queue"
        data={items.slice(0, 100).map((ioc: any) => ({
          action: text(ioc?.recommended_action),
          type: text(ioc?.type).toUpperCase(),
          value: text(ioc?.value),
          quality: text(ioc?.quality_score),
          labels: arr(ioc?.labels).join(", ") || "-",
          sources: arr(ioc?.sources).join(", ") || "-",
        }))}
        columns={[
          { key: "action", label: "Action", wrap: true },
          { key: "type", label: "Type" },
          { key: "value", label: "Value", wrap: true },
          { key: "quality", label: "Quality" },
          { key: "labels", label: "Labels", wrap: true },
          { key: "sources", label: "Sources", wrap: true },
        ]}
        showHeader
      />
      <SectionTitle title="Copy-Ready High-Value IOCs" />
      <pre style={copyBlockStyle}>{items.filter((ioc: any) => asNumber(ioc?.quality_score) >= 65).slice(0, 80).map((ioc: any) => ioc?.value).filter(Boolean).join("\n") || "No high-value IOCs available."}</pre>
    </section>
  );
}

function ScreenshotGalleryPanel({ evidence }: { evidence: any }) {
  const shots = buildScreenshotRows(evidence);
  if (!shots.length) return <EmptyState label="No screenshot artifacts are available for this investigation." />;
  return (
    <section style={sectionStyle}>
      <div style={screenshotGridStyle}>
        {shots.map((shot, idx) => (
          <a key={`${shot.title}-${idx}`} href={shot.href} target="_blank" rel="noreferrer" style={screenshotCardStyle}>
            <img src={shot.src} alt={shot.title} style={screenshotImageStyle} />
            <div style={screenshotMetaStyle}>
              <strong>{shot.title}</strong>
              <span>{shot.caption}</span>
            </div>
          </a>
        ))}
      </div>
    </section>
  );
}

function CollectorHealthPanel({ evidence }: { evidence: any }) {
  const rows = buildCollectorRows(evidence);
  const failed = rows.filter((row) => row.status === "failed").length;
  const completed = rows.filter((row) => row.status === "completed").length;
  const missing = rows.filter((row) => row.status === "missing").length;
  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Completed" value={completed} color="var(--green)" compact />
        <Metric label="Failed" value={failed} color="var(--red)" compact />
        <Metric label="Missing" value={missing} color="var(--yellow)" compact />
        <Metric label="Collectors" value={rows.length} color="var(--accent)" compact />
      </div>
      <EvidenceTable
        title="Collector Health"
        data={rows}
        columns={[
          { key: "collector", label: "Collector" },
          { key: "status", label: "Status" },
          { key: "duration", label: "Duration" },
          { key: "completed", label: "Completed", wrap: true },
          { key: "error", label: "Error / Note", wrap: true },
        ]}
        showHeader
      />
    </section>
  );
}

function ChangeDetectionPanel({ evidence, detail }: { evidence: any; detail: any }) {
  const diff = evidence?.evidence_diff_json || evidence?.diff || detail?.evidence_diff_json || detail?.diff || {};
  const changes = diff?.changes || diff;
  const entries = Object.entries(changes || {}).filter(([, value]) => value !== undefined && value !== null && JSON.stringify(value) !== "{}");
  return (
    <section style={sectionStyle}>
      {entries.length ? (
        <EvidenceTable
          title="Investigation Changes"
          data={entries.map(([key, value]) => ({
            field: key.replace(/_/g, " "),
            change: compactPreviewValue(value),
          }))}
          columns={[{ key: "field" }, { key: "change", wrap: true }]}
          showHeader
        />
      ) : (
        <EmptyState label="No previous-run diff is attached to this investigation. Add this observable to Watchlist or compare recurring runs to populate changes." />
      )}
    </section>
  );
}

function AnalystNotesPanel({
  notes,
  override,
  onNotesChange,
  onOverrideChange,
}: {
  notes: string;
  override: string;
  onNotesChange: (value: string) => void;
  onOverrideChange: (value: string) => void;
}) {
  return (
    <section style={sectionStyle}>
      <div style={twoColStyle}>
        <label style={fieldLabelStyle}>
          Analyst verdict override
          <select value={override} onChange={(event) => onOverrideChange(event.target.value)} style={selectStyle}>
            <option value="">No override</option>
            <option value="benign">Benign</option>
            <option value="suspicious">Suspicious</option>
            <option value="malicious">Malicious</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
        </label>
        <div style={noteInfoStyle}>
          Analyst notes are stored locally in this browser for fast triage. They do not replace the generated report until a backend review workflow is added.
        </div>
      </div>
      <label style={{ ...fieldLabelStyle, marginTop: 12 }}>
        Analyst notes
        <textarea
          value={notes}
          onChange={(event) => onNotesChange(event.target.value)}
          placeholder="Record manual validation, false-positive rationale, escalation notes, or customer-facing caveats."
          style={textareaStyle}
        />
      </label>
    </section>
  );
}

function VerdictPanel({ confidence, tone }: { confidence: any; tone: { color: string; bg: string; border: string } }) {
  const components = arr(confidence?.components);
  const reasons = arr(confidence?.reasons);
  const mitigating = arr(confidence?.mitigating_factors);
  const votes = confidence?.source_agreement || {};

  return (
    <section style={sectionStyle}>
      <div style={{ ...verdictHeroStyle, background: tone.bg, borderColor: tone.border }}>
        <div>
          <div style={eyebrowStyle}>Derived verdict</div>
          <div style={{ color: tone.color, fontSize: 30, fontWeight: 800, lineHeight: 1.1 }}>
            {text(confidence?.verdict, "unknown").toUpperCase()}
          </div>
          <div style={{ marginTop: 10, color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.7 }}>
            {text(confidence?.explanation, "No scoring explanation available.")}
          </div>
        </div>
        <div style={scoreRingStyle}>
          <div style={{ fontSize: 30, fontWeight: 800, color: tone.color }}>{text(confidence?.score, "0")}</div>
          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.12em" }}>score</div>
        </div>
      </div>

      <div style={twoColStyle}>
        <div>
          <SectionTitle title="Source Components" />
          <div style={{ display: "grid", gap: 10 }}>
            {components.length ? components.map((component: any, idx: number) => (
              <ComponentScore key={`${component?.source}-${idx}`} component={component} />
            )) : <EmptyState label="No scoring components available." compact />}
          </div>
        </div>
        <div>
          <SectionTitle title="Source Agreement" />
          <EvidenceTable
            data={[
              { verdict: "Malicious", count: votes.malicious || 0 },
              { verdict: "Suspicious", count: votes.suspicious || 0 },
              { verdict: "Benign", count: votes.benign || 0 },
              { verdict: "Unknown", count: votes.unknown || 0 },
            ]}
            columns={[{ key: "verdict" }, { key: "count" }]}
          />
          <SectionTitle title="Key Reasons" />
          <Bullets items={reasons} empty="No high-signal reasons were derived." />
          {mitigating.length ? (
            <>
              <SectionTitle title="Mitigating Factors" />
              <Bullets items={mitigating} />
            </>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function TimelinePanel({ timeline }: { timeline: any[] }) {
  if (!timeline.length) return <EmptyState label="No timeline events were derived." />;

  return (
    <section style={sectionStyle}>
      <div style={timelineStyle}>
        {timeline.slice(0, 80).map((event: any, idx: number) => (
          <div key={event?.id || idx} style={timelineItemStyle}>
            <div style={{ ...timelineDotStyle, background: severityColor(event?.severity) }} />
            <div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
                <span style={timelineTimeStyle}>{formatDate(event?.timestamp)}</span>
                <span style={sourcePillStyle}>{text(event?.source).toUpperCase()}</span>
              </div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)", marginTop: 6 }}>
                {text(event?.title)}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.65, marginTop: 4 }}>
                {truncate(event?.description || event?.value, 220)}
              </div>
              {event?.value ? (
                <div style={monoValueStyle}>{truncate(event.value, 180)}</div>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function GraphPanel({ graph }: { graph: any }) {
  const { nodes, edges, sourceById } = React.useMemo(() => buildFlowGraph(graph), [graph]);
  const preferredNodeId = React.useMemo(() => {
    const sourceNodes = Object.values(sourceById);
    return (
      sourceNodes.find((node: any) => String(node?.type || "").toLowerCase() === "url")?.id
      || sourceNodes.find((node: any) => String(node?.type || "").toLowerCase() === "process")?.id
      || sourceNodes[0]?.id
      || ""
    );
  }, [sourceById]);
  const [selectedNodeId, setSelectedNodeId] = React.useState<string>("");

  React.useEffect(() => {
    setSelectedNodeId((current) => current && sourceById[current] ? current : String(preferredNodeId || ""));
  }, [preferredNodeId, sourceById]);

  if (!nodes.length) return <EmptyState label="No relationship graph could be derived." />;
  const selectedNode = sourceById[selectedNodeId] || sourceById[preferredNodeId] || null;
  const stats = graphStats(Object.values(sourceById), edges);

  return (
    <section style={sectionStyle}>
      <div style={graphInsightGridStyle}>
        <div style={graphShellStyle}>
          <ReactFlowProvider>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              minZoom={0.2}
              maxZoom={1.6}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
              onNodeClick={(_, node) => setSelectedNodeId(String(node.id))}
            >
              <Background color="rgba(148,163,184,0.18)" gap={24} />
              <MiniMap nodeStrokeWidth={3} zoomable pannable />
              <Controls />
            </ReactFlow>
          </ReactFlowProvider>
        </div>
        <GraphNodeInspector node={selectedNode} stats={stats} />
      </div>
    </section>
  );
}

function IocQualityPanel({ iocQuality }: { iocQuality: any }) {
  const items = arr(iocQuality?.items);
  const summary = iocQuality?.summary || {};
  if (!items.length) return <EmptyState label="No IOCs were available for quality scoring." />;

  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Total" value={text(summary.total_count, "0")} color="var(--accent)" compact />
        <Metric label="High Value" value={text(summary.high_value_count, "0")} color="var(--red)" compact />
        <Metric label="Actionable" value={text(summary.actionable_count, "0")} color="var(--green)" compact />
        <Metric label="Low Value" value={text(summary.low_value_count, "0")} color="var(--text-muted)" compact />
      </div>
      <EvidenceTable
        title="Scored IOCs"
        data={items.slice(0, 80).map((ioc: any) => ({
          type: text(ioc?.type).toUpperCase(),
          value: text(ioc?.value),
          score: text(ioc?.quality_score),
          labels: arr(ioc?.labels).join(", ") || "-",
          action: text(ioc?.recommended_action),
          sources: arr(ioc?.sources).join(", ") || "-",
        }))}
        columns={[
          { key: "type", label: "Type" },
          { key: "value", label: "Value", wrap: true },
          { key: "score", label: "Quality" },
          { key: "labels", label: "Labels", wrap: true },
          { key: "action", label: "Action", wrap: true },
          { key: "sources", label: "Sources", wrap: true },
        ]}
        showHeader
      />
    </section>
  );
}

function OpenCtiPanel({ opencti }: { opencti: any }) {
  const matched = opencti?.matched_observable;
  const related = arr(opencti?.related_entities);
  const counts = opencti?.relationship_counts || {};

  return (
    <section style={sectionStyle}>
      <div style={twoColStyle}>
        <div>
          <SectionTitle title="Resolution" />
          <EvidenceTable
            data={[
              { field: "Status", value: text(opencti?.status) },
              { field: "Matched term", value: text(opencti?.matched_term) },
              { field: "Searched terms", value: arr(opencti?.searched_terms).join(", ") || "-" },
              { field: "Observable", value: matched?.value || "-" },
              { field: "Entity type", value: matched?.entity_type || "-" },
              { field: "Score", value: matched?.score ?? "-" },
              { field: "STIX ID", value: matched?.standard_id || matched?.id || "-" },
              { field: "Labels", value: arr(matched?.labels).join(", ") || "-" },
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
          <SectionTitle title="Recommendations" />
          <Bullets items={arr(opencti?.recommendations)} empty="No OpenCTI-specific recommendations." />
        </div>
        <div>
          <SectionTitle title="Relationship Counts" />
          <EvidenceTable
            data={Object.entries(counts).map(([key, value]) => ({
              object: key.replace(/_/g, " "),
              count: value,
            }))}
            columns={[{ key: "object" }, { key: "count" }]}
          />
          <SectionTitle title="Related Objects" />
          <EvidenceTable
            data={related.slice(0, 30).map((item: any) => ({
              type: text(item?.type).replace(/_/g, " "),
              name: text(item?.name),
              context: text(item?.description),
              date: item?.date ? formatDate(item.date) : "-",
            }))}
            columns={[
              { key: "type", label: "Type" },
              { key: "name", label: "Name", wrap: true },
              { key: "context", label: "Context", wrap: true },
              { key: "date", label: "Date", wrap: true },
            ]}
            showHeader
          />
        </div>
      </div>
    </section>
  );
}

function ReportPreviewPanel({
  reportBuilder,
  confidence,
  iocQuality,
  report,
  evidence,
  detail,
}: {
  reportBuilder: any;
  confidence: any;
  iocQuality: any;
  report: any;
  evidence: any;
  detail: any;
}) {
  const preview = reportBuilder?.preview || {};
  const sections = arr(reportBuilder?.sections).filter((section: any) => (
    !["evidence_timeline", "opencti_resolution", "limitations", "collector_execution_summary"].includes(String(section?.id || ""))
  ));
  const evidenceRows = arr(preview?.evidence_matrix).length
    ? arr(preview.evidence_matrix)
    : arr(reportBuilder?.evidence_matrix).length
      ? arr(reportBuilder.evidence_matrix)
      : deriveEvidenceMatrix(evidence, report);
  const findings = arr(preview?.findings).length ? arr(preview.findings) : arr(report?.findings);
  const reportIocs = arr(preview?.iocs).length ? arr(preview.iocs) : arr(report?.iocs);
  const qualityIocs = arr(preview?.ioc_quality).length ? arr(preview.ioc_quality) : arr(iocQuality?.items);
  const actions = arr(preview?.recommended_actions).length
    ? arr(preview.recommended_actions)
    : arr(reportBuilder?.priority_actions).length
      ? arr(reportBuilder.priority_actions)
      : arr(report?.recommended_steps);
  const title = text(preview?.title || reportBuilder?.recommended_title, `SOC Investigation Report - ${text(detail?.domain || evidence?.domain, "Observable")}`);
  const classification = text(preview?.classification || confidence?.verdict || report?.classification, "unknown").toUpperCase();
  const riskScore = preview?.risk_score ?? confidence?.score ?? report?.risk_score ?? "-";
  const summary = text(report?.primary_reasoning || preview?.summary || report?.executive_summary || confidence?.explanation, "No executive summary is available yet.");
  const verdictReasons = arr(preview?.verdict_rationale).length ? arr(preview.verdict_rationale) : arr(confidence?.reasons);
  const derived = preview?.derived_verdict || {};
  const readiness = text(reportBuilder?.readiness_score, "0");

  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Readiness" value={`${text(reportBuilder?.readiness_score, "0")}%`} color="var(--green)" compact />
        <Metric label="Profile" value={text(reportBuilder?.export_profile, "SOC")} color="var(--accent)" compact />
        <Metric label="Sections" value={text(sections.length, "0")} color="var(--yellow)" compact />
      </div>

      <div style={reportPreviewShellStyle}>
        <div style={reportPreviewHeaderStyle}>
          <div>
            <div style={reportPreviewEyebrowStyle}>Official SOC Report Preview</div>
            <h2 style={reportPreviewTitleStyle}>{title}</h2>
          </div>
          <div style={reportPreviewBadgeStyle}>{readiness}% ready</div>
        </div>

        <div style={reportPreviewMetaStyle}>
          <PreviewMeta label="Observable" value={detail?.domain || evidence?.domain || "-"} mono />
          <PreviewMeta label="Classification" value={classification} />
          <PreviewMeta label="Risk Score" value={String(riskScore)} />
          <PreviewMeta label="Confidence" value={text(preview?.confidence || report?.confidence || confidence?.confidence, "unknown").toUpperCase()} />
        </div>

        <PreviewSection number="1" title="Executive Summary">
          <p style={reportPreviewParagraphStyle}>{summary}</p>
        </PreviewSection>

        <PreviewSection number="2" title="Verdict and Confidence Rationale">
          <div style={reportPreviewTwoColStyle}>
            <PreviewMeta label="Platform Verdict" value={classification} />
            <PreviewMeta label="Derived Verdict" value={text(derived?.verdict || confidence?.verdict, "unknown").toUpperCase()} />
            <PreviewMeta label="Derived Score" value={`${text(derived?.score ?? confidence?.score, "0")}/100`} />
            <PreviewMeta label="Derived Confidence" value={text(derived?.confidence || confidence?.confidence, "unknown").toUpperCase()} />
          </div>
          <PreviewBullets items={verdictReasons} />
        </PreviewSection>

        <PreviewSection number="3" title="Evidence Matrix">
          {evidenceRows.length ? (
            <PreviewTable
              columns={[
                { key: "source", label: "Evidence Source" },
                { key: "ref", label: "Evidence Reference", mono: true },
                { key: "value", label: "Observed Value / SOC Relevance" },
              ]}
              rows={evidenceRows.slice(0, 16).map((row: any) => ({
                ...row,
                value: row?.relevance ? `${text(row.value)} ${text(row.relevance)}` : text(row?.value),
              }))}
            />
          ) : <PreviewMuted>No reportable evidence references were available.</PreviewMuted>}
        </PreviewSection>

        <PreviewSection number="4" title="Findings">
          {findings.length ? (
            <div style={{ display: "grid", gap: 10 }}>
              {findings.slice(0, 6).map((finding: any, idx: number) => (
                <div key={`${finding?.title || "finding"}-${idx}`} style={reportFindingStyle}>
                  <span style={previewSeverityStyle(finding?.severity)}>{text(finding?.severity, "info").toUpperCase()}</span>
                  <div style={{ fontWeight: 800, marginTop: 6 }}>{text(finding?.title, "Untitled finding")}</div>
                  <div style={reportPreviewSmallStyle}>{text(finding?.description, "")}</div>
                </div>
              ))}
            </div>
          ) : <PreviewMuted>No analyst findings are available yet.</PreviewMuted>}
        </PreviewSection>

        <PreviewSection number="5" title="Indicators of Compromise">
          {reportIocs.length ? (
            <PreviewTable
              columns={[
                { key: "type", label: "Type" },
                { key: "value", label: "Value", mono: true },
                { key: "context", label: "Context" },
                { key: "confidence", label: "Confidence" },
              ]}
              rows={reportIocs.slice(0, 14)}
            />
          ) : <PreviewMuted>No primary report IOCs are available yet.</PreviewMuted>}
        </PreviewSection>

        <PreviewSection number="6" title="Recommended SOC Actions">
          <PreviewBullets items={actions} />
        </PreviewSection>

        <PreviewSection number="7" title="Derived SOC Intelligence Verdict">
          <p style={reportPreviewParagraphStyle}>{text(derived?.explanation || confidence?.explanation, "No derived verdict explanation is available.")}</p>
        </PreviewSection>

        <PreviewSection number="8" title="IOC Quality and Actionability">
          {qualityIocs.length ? (
            <PreviewTable
              columns={[
                { key: "type", label: "Type" },
                { key: "value", label: "Value", mono: true },
                { key: "quality", label: "Quality" },
                { key: "labels", label: "Labels" },
                { key: "action", label: "Action" },
              ]}
              rows={qualityIocs.slice(0, 14).map((ioc: any) => ({
                type: text(ioc?.type).toUpperCase(),
                value: text(ioc?.value),
                quality: text(ioc?.quality ?? ioc?.quality_score),
                labels: Array.isArray(ioc?.labels) ? arr(ioc.labels).join(", ") : text(ioc?.labels, "-"),
                action: text(ioc?.action || ioc?.recommended_action),
              }))}
            />
          ) : <PreviewMuted>No IOC quality rows are available yet.</PreviewMuted>}
        </PreviewSection>
      </div>
    </section>
  );
}

function PreviewSection({ number, title, children }: { number: string; title: string; children: React.ReactNode }) {
  return (
    <section style={reportPreviewSectionStyle}>
      <h3 style={reportPreviewSectionTitleStyle}>{number}. {title}</h3>
      {children}
    </section>
  );
}

function PreviewMeta({ label, value, mono = false }: { label: string; value: any; mono?: boolean }) {
  return (
    <div style={reportPreviewMetaItemStyle}>
      <div style={reportPreviewMetaLabelStyle}>{label}</div>
      <div style={{ ...reportPreviewMetaValueStyle, fontFamily: mono ? "var(--font-mono)" : undefined }}>
        {text(value)}
      </div>
    </div>
  );
}

function PreviewTable({
  columns,
  rows,
}: {
  columns: Array<{ key: string; label: string; mono?: boolean }>;
  rows: any[];
}) {
  if (!rows.length) return <PreviewMuted>No rows available.</PreviewMuted>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={reportPreviewTableStyle}>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} style={reportPreviewThStyle}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={idx}>
              {columns.map((column) => (
                <td
                  key={column.key}
                  style={{
                    ...reportPreviewTdStyle,
                    fontFamily: column.mono ? "var(--font-mono)" : undefined,
                    wordBreak: column.mono ? "break-all" : "normal",
                  }}
                >
                  {text(row?.[column.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PreviewBullets({ items }: { items: any[] }) {
  const cleaned = items.map((item) => text(item, "")).filter(Boolean);
  if (!cleaned.length) return <PreviewMuted>No entries available.</PreviewMuted>;
  return (
    <ul style={reportPreviewListStyle}>
      {cleaned.slice(0, 8).map((item, idx) => <li key={`${item}-${idx}`}>{item}</li>)}
    </ul>
  );
}

function PreviewMuted({ children }: { children: React.ReactNode }) {
  return <div style={reportPreviewMutedStyle}>{children}</div>;
}

function deriveEvidenceMatrix(evidence: any, report: any): any[] {
  const rows: any[] = [];
  const seen = new Set<string>();

  function addRef(ref: any, source: string, relevance = "") {
    let refText = text(ref, "").trim();
    if (!refText || rows.length >= 24) return;
    if (refText.startsWith("evidence.")) refText = refText.slice("evidence.".length);
    const key = refText.toLowerCase();
    if (seen.has(key)) return;
    const value = resolveEvidenceRef(evidence, refText);
    if (!hasPreviewValue(value)) return;
    seen.add(key);
    rows.push({ source, ref: refText, value: compactPreviewValue(value), relevance });
  }

  arr(report?.key_evidence).forEach((ref) => addRef(ref, "Analyst key evidence", "Listed by the analyst report as evidence supporting the verdict."));
  arr(report?.findings).slice(0, 10).forEach((finding: any) => {
    arr(finding?.evidence_refs).slice(0, 4).forEach((ref) => addRef(ref, `Finding: ${text(finding?.title, "Finding")}`, text(finding?.description, "")));
  });
  arr(evidence?.signals).slice(0, 18).forEach((signal: any) => {
    arr(signal?.evidence_refs).slice(0, 3).forEach((ref) => {
      addRef(ref, `${text(signal?.severity, "info").toUpperCase()} signal: ${text(signal?.category, "Signal")}`, text(signal?.description, ""));
    });
  });
  [
    ["final_risk.risk_score", "Composite risk score"],
    ["vt.malicious_count", "VirusTotal malicious detections"],
    ["vt.suspicious_count", "VirusTotal suspicious detections"],
    ["opencti.score", "OpenCTI score"],
    ["hybrid_analysis.items", "Sandbox submissions"],
    ["http.final_url", "HTTP final URL"],
    ["whois.domain_age_days", "WHOIS domain age"],
    ["dns.a", "DNS A records"],
    ["hosting.asn_org", "Hosting ASN organization"],
  ].forEach(([ref, source]) => addRef(ref, source));
  return rows;
}

function resolveEvidenceRef(evidence: any, ref: string): any {
  let current = evidence;
  for (const rawSegment of ref.split(".")) {
    if (current === null || current === undefined) return undefined;
    const segment = rawSegment.trim();
    const match = segment.match(/^([^\[]+)(?:\[(\d+)\])?$/);
    if (!match) return undefined;
    const key = match[1];
    current = current?.[key];
    if (match[2] !== undefined) {
      const idx = Number(match[2]);
      if (!Array.isArray(current) || idx < 0 || idx >= current.length) return undefined;
      current = current[idx];
    }
  }
  return current;
}

function hasPreviewValue(value: any): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function compactPreviewValue(value: any): string {
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return truncate(value, 260);
  if (Array.isArray(value)) {
    if (value.every((item) => ["string", "number", "boolean"].includes(typeof item))) {
      const shown = value.slice(0, 8).map((item) => String(item));
      return shown.join(", ") + (value.length > 8 ? ` (+${value.length - 8} more)` : "");
    }
    return `${value.length} structured item(s) collected.`;
  }
  if (value && typeof value === "object") {
    const important = ["status", "verdict", "risk_score", "risk_level", "confidence", "score", "found", "malicious_count", "suspicious_count", "asn_org", "country"];
    const pairs = important
      .filter((key) => value[key] !== undefined && ["string", "number", "boolean"].includes(typeof value[key]))
      .map((key) => `${key}=${String(value[key])}`);
    if (pairs.length) return pairs.slice(0, 8).join("; ");
    return `Structured fields: ${Object.keys(value).slice(0, 8).join(", ")}`;
  }
  return text(value, "");
}

function previewSeverityStyle(severity: any): React.CSSProperties {
  const color = severityColor(severity);
  return {
    display: "inline-flex",
    padding: "3px 7px",
    borderRadius: 6,
    color,
    background: "rgba(15,23,42,0.05)",
    border: "1px solid rgba(15,23,42,0.12)",
    fontSize: 10,
    fontWeight: 800,
  };
}

function ComponentScore({ component }: { component: any }) {
  const score = Math.max(0, Math.min(100, asNumber(component?.score)));
  const tone = toneFromVerdict(component?.verdict || "");
  return (
    <div style={componentStyle}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 8 }}>
        <div style={{ fontSize: 13, color: "var(--text-primary)", fontWeight: 700 }}>
          {text(component?.source).replace(/_/g, " ")}
        </div>
        <div style={{ fontSize: 12, color: tone.color, fontWeight: 800 }}>{score}/100</div>
      </div>
      <div style={barTrackStyle}>
        <div style={{ ...barFillStyle, width: `${score}%`, background: tone.color }} />
      </div>
      {arr(component?.reasons).length ? (
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.55 }}>
          {arr(component.reasons).slice(0, 2).join(" ")}
        </div>
      ) : null}
    </div>
  );
}

function GraphNodeInspector({ node, stats }: { node: any; stats: Record<string, number> }) {
  if (!node) {
    return <EmptyState label="Select a graph node to inspect its full value and metadata." />;
  }
  const color = nodeColor(node);
  const rows = graphNodeDetailRows(node);
  return (
    <aside style={graphInspectorStyle}>
      <div>
        <div style={eyebrowStyle}>Graph Overview</div>
        <div style={graphStatsGridStyle}>
          <GraphStat label="Nodes" value={stats.nodes} />
          <GraphStat label="Edges" value={stats.edges} />
          <GraphStat label="URLs" value={stats.urls} />
          <GraphStat label="Processes" value={stats.processes} />
        </div>
      </div>

      <div style={graphInspectorCardStyle}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ ...sourcePillStyle, color, borderColor: `${color}55`, background: `${color}14` }}>
            {text(node?.type, "node").toUpperCase()}
          </span>
          {node?.score !== undefined && node?.score !== null ? (
            <span style={graphScorePillStyle}>{text(node.score)}/100</span>
          ) : null}
        </div>
        <div style={graphInspectorTitleStyle}>{text(node?.label || node?.value)}</div>
        <div style={graphFullValueStyle}>{text(node?.value || node?.label)}</div>
      </div>

      {rows.length ? (
        <div style={graphDetailListStyle}>
          {rows.map((row) => (
            <div key={row.label} style={graphDetailRowStyle}>
              <div style={graphDetailLabelStyle}>{row.label}</div>
              <div style={{ ...graphDetailValueStyle, fontFamily: row.mono ? "var(--font-mono)" : undefined }}>
                {row.value}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState label="No additional metadata is available for this graph node." compact />
      )}
    </aside>
  );
}

function GraphStat({ label, value }: { label: string; value: any }) {
  return (
    <div style={graphStatStyle}>
      <div style={{ ...eyebrowStyle, fontSize: 9 }}>{label}</div>
      <div style={{ color: "var(--text-primary)", fontWeight: 800, fontSize: 18 }}>{text(value, "0")}</div>
    </div>
  );
}

function GraphNodeLabel({ node }: { node: any }) {
  const type = String(node?.type || "").toUpperCase();
  const value = text(node?.label || node?.value);
  return (
    <div title={text(node?.value || node?.label)} style={{ display: "grid", gap: 5 }}>
      <div style={{
        color: "var(--text-primary)",
        fontSize: 11,
        fontWeight: 800,
        lineHeight: 1.35,
        wordBreak: "break-word",
      }}>
        {truncate(value, 42)}
      </div>
      <div style={{ color: "var(--text-muted)", fontSize: 9, fontWeight: 800, letterSpacing: "0.08em" }}>
        {type}
      </div>
    </div>
  );
}

function graphStats(nodes: any[], edges: Edge[]): Record<string, number> {
  return {
    nodes: nodes.length,
    edges: edges.length,
    urls: nodes.filter((node) => String(node?.type || "").toLowerCase() === "url").length,
    processes: nodes.filter((node) => String(node?.type || "").toLowerCase() === "process").length,
  };
}

function graphNodeDetailRows(node: any): Array<{ label: string; value: string; mono?: boolean }> {
  const fields: Array<[string, string, boolean?]> = [
    ["Group", "group"],
    ["Context", "context"],
    ["PID", "pid", true],
    ["PPID", "ppid", true],
    ["User", "user"],
    ["Path", "path", true],
    ["Command Line", "command_line", true],
    ["SHA256", "sha256", true],
    ["SHA1", "sha1", true],
    ["MD5", "md5", true],
    ["Process Score", "process_score"],
    ["Indicators", "indicators"],
    ["Network Activity", "network_activity"],
    ["File Activity", "file_activity"],
    ["MITRE Tags", "mitre_tags"],
    ["Process", "process"],
    ["Source", "source"],
    ["URL", "url", true],
    ["Protocol", "protocol"],
    ["Port", "port"],
    ["Threat Name", "threat_name"],
    ["Status Code", "status_code"],
    ["Action", "action"],
    ["Labels", "labels"],
  ];
  return fields
    .map(([label, key, mono]) => ({ label, value: detailValue(node?.[key]), mono }))
    .filter((row) => row.value);
}

function detailValue(value: any): string {
  if (value === null || value === undefined || value === "" || value === "-") return "";
  if (Array.isArray(value)) return value.map((item) => text(item, "")).filter(Boolean).join(", ");
  if (typeof value === "object") return Object.entries(value).map(([key, val]) => `${key}: ${text(val)}`).join(", ");
  return text(value, "");
}

const EXPECTED_COLLECTORS = [
  "dns",
  "http",
  "tls",
  "whois",
  "hosting",
  "intel",
  "vt",
  "threat_feeds",
  "brave_osint",
  "urlscan",
  "hybrid_analysis",
  "opencti",
  "final_risk",
];

function buildCollectorRows(evidence: any): Array<{ collector: string; status: string; duration: string; completed: string; error: string }> {
  const rows: Array<{ collector: string; status: string; duration: string; completed: string; error: string }> = [];
  const seen = new Set<string>();
  Object.entries(evidence || {}).forEach(([key, value]: [string, any]) => {
    if (!value || typeof value !== "object") return;
    const meta = value.meta;
    if (!meta || typeof meta !== "object") return;
    const collector = String(meta.collector || key);
    seen.add(key);
    seen.add(collector);
    rows.push({
      collector: collector.replace(/_/g, " "),
      status: String(meta.status || "completed"),
      duration: meta.duration_ms != null ? `${meta.duration_ms}ms` : "-",
      completed: meta.completed_at ? formatDate(meta.completed_at) : "-",
      error: meta.error || arr(value.notes).slice(0, 2).join(" ") || "-",
    });
  });
  EXPECTED_COLLECTORS.forEach((collector) => {
    if (seen.has(collector)) return;
    rows.push({
      collector: collector.replace(/_/g, " "),
      status: "missing",
      duration: "-",
      completed: "-",
      error: "No evidence payload present",
    });
  });
  const rank: Record<string, number> = { failed: 0, missing: 1, completed: 2, success: 2 };
  return rows.sort((a, b) => (rank[a.status] ?? 3) - (rank[b.status] ?? 3) || a.collector.localeCompare(b.collector));
}

function buildScreenshotRows(evidence: any): Array<{ title: string; caption: string; src: string; href: string }> {
  const rows: Array<{ title: string; caption: string; src: string; href: string }> = [];
  const localArtifact = evidence?.screenshot?.artifact_id;
  if (localArtifact) {
    const url = getArtifactUrl(String(localArtifact));
    rows.push({
      title: "Local Browser Capture",
      caption: evidence?.screenshot?.final_url || "Captured by local screenshot collector",
      src: url,
      href: url,
    });
  }
  const urlscanArtifact = evidence?.urlscan?.screenshot_artifact_id;
  if (urlscanArtifact) {
    const url = getArtifactUrl(String(urlscanArtifact));
    rows.push({
      title: "URLScan Screenshot",
      caption: evidence?.urlscan?.page_url || evidence?.urlscan?.scan_id || "URLScan capture",
      src: url,
      href: url,
    });
  }
  const visual = evidence?.visual_comparison || {};
  [
    ["Investigated Visual", visual?.investigated_screenshot_artifact_id],
    ["Client Visual", visual?.client_screenshot_artifact_id],
  ].forEach(([title, artifact]) => {
    if (!artifact) return;
    const url = getArtifactUrl(String(artifact));
    rows.push({ title: String(title), caption: "Visual comparison artifact", src: url, href: url });
  });
  arr(evidence?.hybrid_analysis?.items).forEach((item: any) => {
    const intel = item?.sandbox_intelligence || {};
    arr(intel?.screenshot_thumbnails).slice(0, 4).forEach((shot: any, idx: number) => {
      const src = String(shot?.url || "");
      if (!src) return;
      rows.push({
        title: `AnyRun Thumbnail ${idx + 1}`,
        caption: shot?.label || item?.analysis_id || "AnyRun embedded thumbnail",
        src,
        href: shot?.report_url || src,
      });
    });
  });
  const seen = new Set<string>();
  return rows.filter((row) => {
    const key = `${row.title}|${row.src}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildFlowGraph(graph: any): { nodes: Node[]; edges: Edge[]; sourceById: Record<string, any> } {
  const sourceNodes = arr(graph?.nodes);
  const sourceEdges = arr(graph?.edges);
  const sourceById: Record<string, any> = {};
  const counters: Record<string, number> = {};
  const groupColumn: Record<string, number> = {
    observable: 0,
    ioc: 1,
    infrastructure: 2,
    web: 2,
    sandbox: 1,
    process: 2,
    network: 3,
    file: 3,
    opencti: 4,
  };

  const flowNodes: Node[] = sourceNodes.slice(0, 140).map((node: any) => {
    sourceById[String(node.id)] = node;
    const group = String(node?.group || node?.type || "other");
    const col = groupColumn[group] ?? 2;
    const row = counters[group] || 0;
    counters[group] = row + 1;
    const color = nodeColor(node);
    return {
      id: String(node.id),
      type: "default",
      position: { x: col * 260, y: row * 92 + (group === "observable" ? 120 : 0) },
      data: { label: <GraphNodeLabel node={node} /> },
      style: {
        width: 190,
        minHeight: 58,
        borderRadius: 12,
        border: `1px solid ${color}`,
        background: "rgba(8,15,29,0.92)",
        color: "var(--text-primary)",
        boxShadow: `0 0 0 4px ${color}16`,
      },
    };
  });
  const known = new Set(flowNodes.map((node) => node.id));
  const flowEdges: Edge[] = sourceEdges
    .filter((edge: any) => known.has(String(edge?.source)) && known.has(String(edge?.target)))
    .slice(0, 220)
    .map((edge: any) => {
      const color = severityColor(edge?.severity);
      return {
        id: String(edge.id),
        source: String(edge.source),
        target: String(edge.target),
        label: truncate(edge?.label, 28),
        type: "smoothstep",
        markerEnd: { type: MarkerType.ArrowClosed, color },
        style: { stroke: color, strokeWidth: 1.8 },
        labelStyle: { fill: "var(--text-secondary)", fontSize: 10, fontWeight: 700 },
        labelBgStyle: { fill: "rgba(8,15,29,0.86)", fillOpacity: 0.9 },
      };
    });
  return { nodes: flowNodes, edges: flowEdges, sourceById };
}

function nodeColor(node: any) {
  const type = String(node?.type || "").toLowerCase();
  const score = asNumber(node?.score);
  if (score >= 70) return "var(--red)";
  if (type.includes("opencti") || type.includes("attack") || type.includes("malware")) return "#a78bfa";
  if (type.includes("process") || type.includes("sandbox")) return "var(--yellow)";
  if (type.includes("ip") || type.includes("domain") || type.includes("url")) return "var(--accent)";
  if (type.includes("file") || type.includes("hash")) return "var(--green)";
  return "var(--text-muted)";
}

function Metric({ label, value, color, compact = false }: { label: string; value: React.ReactNode; color: string; compact?: boolean }) {
  return (
    <div style={{ ...metricStyle, minHeight: compact ? 72 : 92 }}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ fontSize: compact ? 20 : 26, color, fontWeight: 800, lineHeight: 1.15, wordBreak: "break-word" }}>
        {value}
      </div>
    </div>
  );
}

function SectionTitle({ title }: { title: string }) {
  return <div style={sectionTitleStyle}>{title}</div>;
}

function Bullets({ items, empty }: { items: any[]; empty?: string }) {
  const cleaned = items.map((item) => text(item, "")).filter(Boolean);
  if (!cleaned.length) return <EmptyState label={empty || "No entries."} compact />;
  return (
    <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.75 }}>
      {cleaned.slice(0, 10).map((item, idx) => <li key={`${item}-${idx}`}>{item}</li>)}
    </ul>
  );
}

function EmptyState({ label, compact = false }: { label: string; compact?: boolean }) {
  return (
    <div style={{
      padding: compact ? "10px 12px" : "24px 18px",
      border: "1px solid var(--border-dim)",
      borderRadius: "var(--radius-sm)",
      color: "var(--text-muted)",
      fontSize: 12,
      background: "rgba(15,23,42,0.34)",
    }}>
      {label}
    </div>
  );
}

const metricGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
  gap: 10,
};

const metricStyle: React.CSSProperties = {
  padding: "14px 15px",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "rgba(15,23,42,0.38)",
  display: "grid",
  alignContent: "center",
  gap: 8,
};

const segmentedStyle: React.CSSProperties = {
  display: "flex",
  gap: 6,
  flexWrap: "wrap",
  padding: 6,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "rgba(15,23,42,0.34)",
};

const segmentButtonStyle: React.CSSProperties = {
  padding: "7px 11px",
  border: "1px solid transparent",
  borderRadius: "var(--radius-sm)",
  fontSize: 11,
  fontWeight: 700,
  cursor: "pointer",
  fontFamily: "var(--font-sans)",
};

const sectionStyle: React.CSSProperties = {
  display: "grid",
  gap: 18,
};

const verdictHeroStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) 116px",
  gap: 18,
  alignItems: "center",
  padding: 18,
  border: "1px solid",
  borderRadius: "var(--radius)",
};

const scoreRingStyle: React.CSSProperties = {
  width: 108,
  height: 108,
  borderRadius: "50%",
  display: "grid",
  placeItems: "center",
  alignContent: "center",
  border: "1px solid var(--border)",
  background: "rgba(8,15,29,0.62)",
};

const twoColStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
  gap: 18,
  alignItems: "start",
};

const threeColStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
  gap: 16,
  alignItems: "start",
};

const eyebrowStyle: React.CSSProperties = {
  fontSize: 10,
  color: "var(--text-muted)",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  fontWeight: 800,
};

const sectionTitleStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 800,
  color: "var(--accent)",
  paddingBottom: 8,
  marginBottom: 10,
  borderBottom: "1px solid var(--border-dim)",
  letterSpacing: "0.04em",
  textTransform: "uppercase",
};

const componentStyle: React.CSSProperties = {
  padding: 12,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.34)",
};

const copyBlockStyle: React.CSSProperties = {
  margin: 0,
  minHeight: 120,
  maxHeight: 280,
  overflow: "auto",
  padding: 12,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(2,6,23,0.45)",
  color: "var(--text-secondary)",
  fontSize: 12,
  lineHeight: 1.55,
  whiteSpace: "pre-wrap",
  wordBreak: "break-all",
};

const screenshotGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
  gap: 14,
};

const screenshotCardStyle: React.CSSProperties = {
  display: "block",
  overflow: "hidden",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.38)",
  color: "inherit",
  textDecoration: "none",
};

const screenshotImageStyle: React.CSSProperties = {
  display: "block",
  width: "100%",
  aspectRatio: "16 / 9",
  objectFit: "contain",
  background: "#020617",
};

const screenshotMetaStyle: React.CSSProperties = {
  display: "grid",
  gap: 3,
  padding: "9px 10px",
  fontSize: 12,
  color: "var(--text-secondary)",
};

const fieldLabelStyle: React.CSSProperties = {
  display: "grid",
  gap: 8,
  color: "var(--text-primary)",
  fontSize: 12,
  fontWeight: 700,
};

const selectStyle: React.CSSProperties = {
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(2,6,23,0.45)",
  color: "var(--text-primary)",
  padding: "9px 10px",
};

const textareaStyle: React.CSSProperties = {
  minHeight: 240,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(2,6,23,0.45)",
  color: "var(--text-primary)",
  padding: 12,
  resize: "vertical",
  lineHeight: 1.55,
};

const noteInfoStyle: React.CSSProperties = {
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.36)",
  padding: 12,
  color: "var(--text-secondary)",
  fontSize: 12,
  lineHeight: 1.6,
};

const barTrackStyle: React.CSSProperties = {
  height: 8,
  borderRadius: 999,
  overflow: "hidden",
  background: "rgba(148,163,184,0.14)",
};

const barFillStyle: React.CSSProperties = {
  height: "100%",
  borderRadius: 999,
};

const timelineStyle: React.CSSProperties = {
  display: "grid",
  gap: 0,
  borderLeft: "1px solid var(--border)",
  marginLeft: 10,
};

const timelineItemStyle: React.CSSProperties = {
  position: "relative",
  padding: "0 0 18px 24px",
};

const timelineDotStyle: React.CSSProperties = {
  position: "absolute",
  left: -6,
  top: 4,
  width: 11,
  height: 11,
  borderRadius: "50%",
  boxShadow: "0 0 0 5px rgba(102,168,255,0.12)",
};

const timelineTimeStyle: React.CSSProperties = {
  color: "var(--text-muted)",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
};

const sourcePillStyle: React.CSSProperties = {
  padding: "2px 7px",
  borderRadius: 999,
  color: "var(--accent)",
  border: "1px solid rgba(102,168,255,0.24)",
  background: "rgba(102,168,255,0.08)",
  fontSize: 10,
  fontWeight: 800,
  letterSpacing: "0.06em",
};

const monoValueStyle: React.CSSProperties = {
  marginTop: 6,
  fontSize: 11,
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  wordBreak: "break-all",
};

const graphShellStyle: React.CSSProperties = {
  height: 640,
  minHeight: 420,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  overflow: "hidden",
  background: "#071525",
};

const graphInsightGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) minmax(320px, 380px)",
  gap: 14,
  alignItems: "stretch",
};

const graphInspectorStyle: React.CSSProperties = {
  minHeight: 420,
  maxHeight: 640,
  overflow: "auto",
  display: "grid",
  alignContent: "start",
  gap: 12,
  padding: 14,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "rgba(8,15,29,0.72)",
};

const graphStatsGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
  gap: 8,
  marginTop: 10,
};

const graphStatStyle: React.CSSProperties = {
  padding: "9px 10px",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.46)",
};

const graphInspectorCardStyle: React.CSSProperties = {
  display: "grid",
  gap: 10,
  padding: 12,
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.54)",
};

const graphInspectorTitleStyle: React.CSSProperties = {
  color: "var(--text-primary)",
  fontSize: 15,
  fontWeight: 800,
  lineHeight: 1.45,
  wordBreak: "break-word",
};

const graphFullValueStyle: React.CSSProperties = {
  padding: 10,
  border: "1px solid rgba(102,168,255,0.22)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(102,168,255,0.07)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  lineHeight: 1.65,
  wordBreak: "break-all",
};

const graphScorePillStyle: React.CSSProperties = {
  padding: "2px 7px",
  borderRadius: 999,
  color: "var(--yellow)",
  border: "1px solid rgba(251,191,36,0.28)",
  background: "rgba(251,191,36,0.10)",
  fontSize: 10,
  fontWeight: 800,
};

const graphDetailListStyle: React.CSSProperties = {
  display: "grid",
  gap: 8,
};

const graphDetailRowStyle: React.CSSProperties = {
  padding: "9px 10px",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.34)",
};

const graphDetailLabelStyle: React.CSSProperties = {
  color: "var(--text-muted)",
  fontSize: 10,
  fontWeight: 800,
  textTransform: "uppercase",
};

const graphDetailValueStyle: React.CSSProperties = {
  marginTop: 4,
  color: "var(--text-primary)",
  fontSize: 11,
  lineHeight: 1.55,
  wordBreak: "break-word",
};

const reportPreviewShellStyle: React.CSSProperties = {
  padding: 28,
  border: "1px solid rgba(148,163,184,0.30)",
  borderRadius: 8,
  background: "#f8fafc",
  color: "#1e293b",
  boxShadow: "0 20px 44px rgba(0,0,0,0.24)",
  display: "grid",
  gap: 22,
};

const reportPreviewHeaderStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 18,
  borderBottom: "2px solid #cbd5e1",
  paddingBottom: 16,
};

const reportPreviewEyebrowStyle: React.CSSProperties = {
  fontSize: 11,
  color: "#64748b",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  fontWeight: 800,
};

const reportPreviewTitleStyle: React.CSSProperties = {
  margin: "5px 0 0",
  color: "#0f172a",
  fontSize: 24,
  lineHeight: 1.2,
  fontWeight: 850,
};

const reportPreviewBadgeStyle: React.CSSProperties = {
  flex: "0 0 auto",
  padding: "7px 10px",
  borderRadius: 6,
  color: "#047857",
  background: "#d1fae5",
  border: "1px solid #86efac",
  fontSize: 11,
  fontWeight: 850,
  textTransform: "uppercase",
};

const reportPreviewMetaStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 10,
};

const reportPreviewTwoColStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 10,
  marginBottom: 12,
};

const reportPreviewMetaItemStyle: React.CSSProperties = {
  padding: "9px 10px",
  border: "1px solid #dbe3ee",
  borderRadius: 6,
  background: "#ffffff",
};

const reportPreviewMetaLabelStyle: React.CSSProperties = {
  fontSize: 10,
  color: "#64748b",
  textTransform: "uppercase",
  fontWeight: 800,
};

const reportPreviewMetaValueStyle: React.CSSProperties = {
  marginTop: 4,
  color: "#0f172a",
  fontSize: 13,
  lineHeight: 1.45,
  fontWeight: 750,
  wordBreak: "break-word",
};

const reportPreviewSectionStyle: React.CSSProperties = {
  display: "grid",
  gap: 10,
};

const reportPreviewSectionTitleStyle: React.CSSProperties = {
  margin: 0,
  paddingBottom: 8,
  borderBottom: "1px solid #cbd5e1",
  color: "#0f172a",
  fontSize: 15,
  lineHeight: 1.35,
  fontWeight: 850,
  textTransform: "uppercase",
};

const reportPreviewParagraphStyle: React.CSSProperties = {
  margin: 0,
  color: "#334155",
  fontSize: 13,
  lineHeight: 1.72,
};

const reportPreviewSmallStyle: React.CSSProperties = {
  marginTop: 5,
  color: "#475569",
  fontSize: 12,
  lineHeight: 1.65,
};

const reportPreviewTableStyle: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: 12,
  color: "#243244",
};

const reportPreviewThStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "7px 8px",
  border: "1px solid #dbe3ee",
  background: "#e8eef7",
  color: "#334155",
  fontSize: 10,
  textTransform: "uppercase",
  fontWeight: 850,
};

const reportPreviewTdStyle: React.CSSProperties = {
  verticalAlign: "top",
  padding: "8px",
  border: "1px solid #dbe3ee",
  background: "#ffffff",
  lineHeight: 1.55,
};

const reportPreviewListStyle: React.CSSProperties = {
  margin: 0,
  paddingLeft: 18,
  color: "#334155",
  fontSize: 12,
  lineHeight: 1.75,
};

const reportPreviewMutedStyle: React.CSSProperties = {
  padding: "10px 12px",
  border: "1px dashed #cbd5e1",
  borderRadius: 6,
  background: "#ffffff",
  color: "#64748b",
  fontSize: 12,
};

const reportFindingStyle: React.CSSProperties = {
  padding: 10,
  border: "1px solid #dbe3ee",
  borderRadius: 6,
  background: "#ffffff",
  color: "#1e293b",
};
