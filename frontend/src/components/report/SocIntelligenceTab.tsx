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

type Props = {
  intelligence?: any;
  loading?: boolean;
};

type SocTab = "verdict" | "timeline" | "graph" | "iocs" | "opencti" | "report";

const TAB_LABELS: Array<{ id: SocTab; label: string }> = [
  { id: "verdict", label: "Verdict" },
  { id: "timeline", label: "Timeline" },
  { id: "graph", label: "Graph" },
  { id: "iocs", label: "IOC Quality" },
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

export default function SocIntelligenceTab({ intelligence, loading }: Props) {
  const [active, setActive] = React.useState<SocTab>("verdict");

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

      {active === "verdict" && <VerdictPanel confidence={confidence} tone={tone} />}
      {active === "timeline" && <TimelinePanel timeline={timeline} />}
      {active === "graph" && <GraphPanel graph={graph} />}
      {active === "iocs" && <IocQualityPanel iocQuality={iocQuality} />}
      {active === "opencti" && <OpenCtiPanel opencti={opencti} />}
      {active === "report" && <ReportBuilderPanel reportBuilder={reportBuilder} />}
    </div>
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
  const { nodes, edges } = React.useMemo(() => buildFlowGraph(graph), [graph]);
  if (!nodes.length) return <EmptyState label="No relationship graph could be derived." />;

  return (
    <section style={sectionStyle}>
      <div style={graphShellStyle}>
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            minZoom={0.25}
            maxZoom={1.5}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable
          >
            <Background color="rgba(148,163,184,0.18)" gap={24} />
            <MiniMap nodeStrokeWidth={3} zoomable pannable />
            <Controls />
          </ReactFlow>
        </ReactFlowProvider>
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

function ReportBuilderPanel({ reportBuilder }: { reportBuilder: any }) {
  const sections = arr(reportBuilder?.sections);
  return (
    <section style={sectionStyle}>
      <div style={metricGridStyle}>
        <Metric label="Readiness" value={`${text(reportBuilder?.readiness_score, "0")}%`} color="var(--green)" compact />
        <Metric label="Profile" value={text(reportBuilder?.export_profile, "SOC")} color="var(--accent)" compact />
        <Metric label="Sections" value={text(sections.length, "0")} color="var(--yellow)" compact />
      </div>
      <SectionTitle title="Official SOC Sections" />
      <div style={{ display: "grid", gap: 10 }}>
        {sections.map((section: any) => (
          <div key={section?.id || section?.title} style={reportSectionStyle}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
              <div style={{ fontSize: 14, color: "var(--text-primary)", fontWeight: 700 }}>{text(section?.title)}</div>
              <span style={statusBadgeStyle(section?.status)}>{text(section?.status).replace(/_/g, " ").toUpperCase()}</span>
            </div>
            <div style={{ marginTop: 6, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.65 }}>
              {text(section?.purpose)}
            </div>
          </div>
        ))}
      </div>
      <SectionTitle title="Priority Actions" />
      <Bullets items={arr(reportBuilder?.priority_actions)} />
    </section>
  );
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

function buildFlowGraph(graph: any): { nodes: Node[]; edges: Edge[] } {
  const sourceNodes = arr(graph?.nodes);
  const sourceEdges = arr(graph?.edges);
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
    const group = String(node?.group || node?.type || "other");
    const col = groupColumn[group] ?? 2;
    const row = counters[group] || 0;
    counters[group] = row + 1;
    const color = nodeColor(node);
    return {
      id: String(node.id),
      type: "default",
      position: { x: col * 260, y: row * 92 + (group === "observable" ? 120 : 0) },
      data: { label: `${truncate(node?.label || node?.value, 42)}\n${String(node?.type || "").toUpperCase()}` },
      style: {
        width: 190,
        minHeight: 58,
        borderRadius: 12,
        border: `1px solid ${color}`,
        background: "rgba(8,15,29,0.92)",
        color: "var(--text-primary)",
        fontSize: 11,
        fontWeight: 700,
        whiteSpace: "pre-line",
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
  return { nodes: flowNodes, edges: flowEdges };
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

function statusBadgeStyle(status: any): React.CSSProperties {
  const normalized = String(status || "").toLowerCase();
  const color = normalized === "ready" ? "var(--green)" : normalized === "needs_data" || normalized === "needs_review" ? "var(--yellow)" : "var(--text-muted)";
  const background =
    normalized === "ready" ? "rgba(56,217,169,0.12)" :
    normalized === "needs_data" || normalized === "needs_review" ? "rgba(251,191,36,0.12)" :
    "rgba(120,145,178,0.10)";
  const border =
    normalized === "ready" ? "rgba(56,217,169,0.32)" :
    normalized === "needs_data" || normalized === "needs_review" ? "rgba(251,191,36,0.32)" :
    "rgba(120,145,178,0.20)";
  return {
    padding: "4px 8px",
    borderRadius: 999,
    color,
    background,
    border: `1px solid ${border}`,
    fontSize: 10,
    fontWeight: 800,
    letterSpacing: "0.06em",
  };
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

const reportSectionStyle: React.CSSProperties = {
  padding: "12px 14px",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.34)",
};
