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

import * as api from "@/lib/api";

type Severity = "all" | "critical" | "high" | "medium" | "low";

const SEVERITIES: Severity[] = ["all", "critical", "high", "medium", "low"];

export default function SOCIndicatorsGraphPage() {
  const [query, setQuery] = React.useState("");
  const [severity, setSeverity] = React.useState<Severity>("all");
  const [graph, setGraph] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.getSOCIndicatorGraph({ search: query.trim(), severity, limit: 320 });
      setGraph(data);
      setSelectedId((current) => current && data?.nodes?.some((node: any) => node.id === current) ? current : data?.nodes?.[0]?.id || "");
    } catch (err: any) {
      setError(err?.message || "Could not load SOC indicator graph.");
    } finally {
      setLoading(false);
    }
  }, [query, severity]);

  React.useEffect(() => {
    const timer = window.setTimeout(() => {
      load();
    }, 220);
    return () => window.clearTimeout(timer);
  }, [load]);

  const { nodes, edges, sourceById } = React.useMemo(() => buildFlowGraph(graph), [graph]);
  const selected = sourceById[selectedId] || sourceById[nodes[0]?.id] || null;

  return (
    <main style={pageStyle}>
      <section style={headerStyle}>
        <div>
          <h1 style={titleStyle}>SOC Indicators Graph</h1>
          <p style={subtitleStyle}>
            Platform-wide relations from assistant sanitization, investigation IOCs, linked cases, and co-observed indicators.
          </p>
        </div>
        <div style={toolbarStyle}>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search indicator, user, IP, domain..."
            style={searchStyle}
          />
          <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity)} style={selectStyle}>
            {SEVERITIES.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All severities" : item}</option>
            ))}
          </select>
          <button type="button" onClick={() => { setQuery(""); setSeverity("all"); }} style={buttonStyle}>
            Reset
          </button>
        </div>
      </section>

      <section style={summaryGridStyle}>
        <Metric label="Indicators" value={graph?.summary?.indicator_nodes ?? 0} tone="info" />
        <Metric label="Assistant Cases" value={graph?.summary?.assistant_cases ?? 0} tone="success" />
        <Metric label="Investigations" value={graph?.summary?.investigation_cases ?? 0} tone="warning" />
        <Metric label="Relations" value={graph?.summary?.edges ?? 0} tone="danger" />
      </section>

      <section style={workspaceStyle}>
        <div style={graphPanelStyle}>
          {loading ? (
            <Empty label="Loading indicator graph..." />
          ) : error ? (
            <Empty label={error} danger />
          ) : nodes.length ? (
            <ReactFlowProvider>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                fitView
                minZoom={0.12}
                maxZoom={1.8}
                nodesDraggable
                nodesConnectable={false}
                elementsSelectable
                onNodeClick={(_, node) => setSelectedId(String(node.id))}
              >
                <Background color="rgba(148,163,184,0.16)" gap={28} />
                <MiniMap nodeStrokeWidth={3} zoomable pannable />
                <Controls />
              </ReactFlow>
            </ReactFlowProvider>
          ) : (
            <Empty label="No SOC indicators are available yet. Run AI Assistant sessions or investigations to populate the graph." />
          )}
        </div>
        <IndicatorInspector node={selected} />
      </section>
    </main>
  );
}

function buildFlowGraph(graph: any): { nodes: Node[]; edges: Edge[]; sourceById: Record<string, any> } {
  const sourceNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const sourceEdges = Array.isArray(graph?.edges) ? graph.edges : [];
  const sourceById: Record<string, any> = {};
  const counters: Record<string, number> = {};
  const columnByKind: Record<string, number> = {
    assistant: 0,
    investigation: 0,
    indicator: 1,
  };

  const flowNodes: Node[] = sourceNodes.map((node: any) => {
    sourceById[String(node.id)] = node;
    const kind = String(node.kind || "indicator");
    const type = String(node.type || kind);
    const column = columnByKind[kind] ?? 1;
    const bucket = kind === "indicator" ? type : kind;
    const row = counters[bucket] || 0;
    counters[bucket] = row + 1;
    const color = severityColor(node.severity);
    return {
      id: String(node.id),
      type: "default",
      position: {
        x: column * 360 + (kind === "indicator" ? typeOffset(type) : 0),
        y: row * 112 + (kind === "indicator" ? 48 : 20),
      },
      data: { label: <NodeLabel node={node} /> },
      style: {
        width: kind === "indicator" ? 230 : 260,
        minHeight: 78,
        borderRadius: 16,
        border: `1px solid ${color}`,
        background: kind === "indicator" ? "rgba(10,18,34,0.95)" : "rgba(20,27,48,0.96)",
        color: "var(--text-primary)",
        boxShadow: `0 0 0 4px ${color}18, 0 18px 40px rgba(0,0,0,0.24)`,
      },
    };
  });
  const known = new Set(flowNodes.map((node) => node.id));
  const flowEdges: Edge[] = sourceEdges
    .filter((edge: any) => known.has(String(edge.source)) && known.has(String(edge.target)))
    .map((edge: any) => {
      const color = severityColor(edge.severity);
      return {
        id: String(edge.id),
        source: String(edge.source),
        target: String(edge.target),
        type: "smoothstep",
        label: truncate(edge.label, 32),
        markerEnd: { type: MarkerType.ArrowClosed, color },
        style: {
          stroke: color,
          strokeWidth: edge.dashed ? 1.2 : 2,
          strokeDasharray: edge.dashed ? "7 7" : undefined,
        },
        labelStyle: { fill: "var(--text-secondary)", fontSize: 10, fontWeight: 800 },
        labelBgStyle: { fill: "rgba(8,15,29,0.9)", fillOpacity: 0.92 },
      };
    });
  return { nodes: flowNodes, edges: flowEdges, sourceById };
}

function NodeLabel({ node }: { node: any }) {
  const color = severityColor(node.severity);
  return (
    <div title={node.value || node.label} style={{ display: "grid", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ ...nodeIconStyle, borderColor: `${color}66`, color }}>{nodeIcon(node)}</span>
        <div style={{ minWidth: 0 }}>
          <div style={nodeTitleStyle}>{truncate(node.label || node.value, 34)}</div>
          <div style={nodeSubtitleStyle}>{node.kind === "indicator" ? node.type : node.kind}</div>
        </div>
      </div>
      <span style={{ ...severityPillStyle, color, borderColor: `${color}66`, background: `${color}18` }}>
        {String(node.severity || "medium").toUpperCase()}
      </span>
    </div>
  );
}

function IndicatorInspector({ node }: { node: any }) {
  if (!node) {
    return (
      <aside style={inspectorStyle}>
        <Empty label="Select an indicator to inspect relations, confidence, and source cases." />
      </aside>
    );
  }
  const color = severityColor(node.severity);
  return (
    <aside style={inspectorStyle}>
      <div style={inspectorCardStyle}>
        <div style={{ ...smallPillStyle, color, borderColor: `${color}66`, background: `${color}16` }}>
          {String(node.kind || "indicator").toUpperCase()}
        </div>
        <h2 style={inspectorTitleStyle}>{node.label || node.value}</h2>
        <div style={inspectorValueStyle}>{node.value || node.label}</div>
        <div style={inspectorGridStyle}>
          <InspectorStat label="Severity" value={node.severity || "medium"} />
          <InspectorStat label="Confidence" value={node.confidence || "medium"} />
          <InspectorStat label="Seen" value={node.occurrences ?? 1} />
          <InspectorStat label="Type" value={node.type || node.kind} />
        </div>
      </div>

      <div style={inspectorCardStyle}>
        <h3 style={panelTitleStyle}>Analyst Summary</h3>
        <p style={paragraphStyle}>{node.summary || "No summary is available for this node."}</p>
        <Detail label="Sources" value={Array.isArray(node.sources) ? node.sources.join(", ") : node.kind} />
        <Detail label="First seen" value={formatDate(node.first_seen)} />
        <Detail label="Last seen" value={formatDate(node.last_seen)} />
        {node.risk_score !== undefined && node.risk_score !== null ? <Detail label="Risk score" value={node.risk_score} /> : null}
      </div>

      {node.url ? (
        <a href={node.url} style={openLinkStyle}>Open source case</a>
      ) : null}
    </aside>
  );
}

function Metric({ label, value, tone }: { label: string; value: any; tone: "info" | "success" | "warning" | "danger" }) {
  const color = tone === "success" ? "var(--green)" : tone === "warning" ? "var(--yellow)" : tone === "danger" ? "var(--red)" : "var(--accent)";
  return (
    <div style={metricStyle}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ color, fontSize: 26, fontWeight: 900 }}>{value}</div>
    </div>
  );
}

function InspectorStat({ label, value }: { label: string; value: any }) {
  return (
    <div style={statStyle}>
      <div style={eyebrowStyle}>{label}</div>
      <strong>{String(value).toUpperCase()}</strong>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: any }) {
  return (
    <div style={detailStyle}>
      <span>{label}</span>
      <strong>{String(value || "-")}</strong>
    </div>
  );
}

function Empty({ label, danger = false }: { label: string; danger?: boolean }) {
  return (
    <div style={{ ...emptyStyle, color: danger ? "var(--red)" : "var(--text-muted)" }}>
      {label}
    </div>
  );
}

function nodeIcon(node: any): string {
  const type = String(node.type || node.kind || "").toLowerCase();
  if (node.kind === "assistant") return "AI";
  if (node.kind === "investigation") return "CASE";
  if (type === "ip") return "IP";
  if (type === "email" || type === "account") return "@";
  if (type === "url" || type === "domain") return "URL";
  if (type === "hash") return "#";
  return "IOC";
}

function severityColor(severity: any): string {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return "#fb7185";
  if (value === "high") return "#f97316";
  if (value === "medium") return "#fbbf24";
  if (value === "low") return "#38d9a9";
  return "#66a8ff";
}

function typeOffset(type: string): number {
  const order = ["ip", "url", "domain", "email", "account", "host", "hash", "sid"];
  const idx = Math.max(0, order.indexOf(type));
  return (idx % 3) * 280;
}

function truncate(value: any, max: number): string {
  const text = String(value || "");
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}

function formatDate(value: any): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

const pageStyle: React.CSSProperties = {
  display: "grid",
  gap: 18,
  padding: "18px clamp(14px, 2vw, 28px) 28px",
  minHeight: "calc(100vh - 72px)",
};

const headerStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(260px, 1fr) minmax(320px, 0.9fr)",
  gap: 18,
  alignItems: "end",
};

const titleStyle: React.CSSProperties = {
  margin: 0,
  color: "var(--text-strong)",
  fontSize: 28,
  fontWeight: 900,
};

const subtitleStyle: React.CSSProperties = {
  margin: "6px 0 0",
  color: "var(--text-secondary)",
  lineHeight: 1.55,
  fontSize: 13,
};

const toolbarStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(160px, 1fr) 150px 86px",
  gap: 10,
};

const searchStyle: React.CSSProperties = {
  height: 40,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(2,6,23,0.52)",
  color: "var(--text-primary)",
  padding: "0 12px",
};

const selectStyle: React.CSSProperties = {
  ...searchStyle,
  textTransform: "capitalize",
};

const buttonStyle: React.CSSProperties = {
  height: 40,
  border: "1px solid rgba(102,168,255,0.32)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(102,168,255,0.14)",
  color: "var(--text-primary)",
  fontWeight: 800,
  cursor: "pointer",
};

const summaryGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
  gap: 10,
};

const metricStyle: React.CSSProperties = {
  minHeight: 82,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "rgba(15,23,42,0.42)",
  padding: 14,
  display: "grid",
  alignContent: "center",
  gap: 8,
};

const workspaceStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) 360px",
  gap: 16,
  minHeight: 690,
};

const graphPanelStyle: React.CSSProperties = {
  minHeight: 690,
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "radial-gradient(circle at 30% 20%, rgba(34,211,238,0.08), transparent 30%), rgba(8,15,29,0.72)",
  overflow: "hidden",
};

const inspectorStyle: React.CSSProperties = {
  display: "grid",
  alignContent: "start",
  gap: 16,
};

const inspectorCardStyle: React.CSSProperties = {
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius)",
  background: "rgba(15,23,42,0.58)",
  padding: 18,
};

const nodeIconStyle: React.CSSProperties = {
  width: 38,
  height: 38,
  borderRadius: 12,
  border: "1px solid",
  display: "grid",
  placeItems: "center",
  background: "rgba(2,6,23,0.46)",
  fontSize: 10,
  fontWeight: 900,
  flex: "0 0 auto",
};

const nodeTitleStyle: React.CSSProperties = {
  color: "var(--text-primary)",
  fontWeight: 900,
  fontSize: 13,
  lineHeight: 1.25,
  wordBreak: "break-word",
};

const nodeSubtitleStyle: React.CSSProperties = {
  color: "var(--text-secondary)",
  fontSize: 11,
  marginTop: 2,
  textTransform: "capitalize",
};

const severityPillStyle: React.CSSProperties = {
  justifySelf: "start",
  padding: "3px 8px",
  borderRadius: 999,
  border: "1px solid",
  fontSize: 10,
  fontWeight: 900,
};

const smallPillStyle: React.CSSProperties = {
  display: "inline-flex",
  padding: "4px 8px",
  borderRadius: 999,
  border: "1px solid",
  fontSize: 10,
  fontWeight: 900,
};

const inspectorTitleStyle: React.CSSProperties = {
  margin: "14px 0 6px",
  color: "var(--text-strong)",
  fontSize: 20,
  lineHeight: 1.25,
  wordBreak: "break-word",
};

const inspectorValueStyle: React.CSSProperties = {
  color: "var(--text-secondary)",
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  wordBreak: "break-all",
};

const inspectorGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 10,
  marginTop: 16,
};

const statStyle: React.CSSProperties = {
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(2,6,23,0.32)",
  padding: 11,
  color: "var(--text-primary)",
  display: "grid",
  gap: 6,
};

const panelTitleStyle: React.CSSProperties = {
  margin: 0,
  color: "var(--text-primary)",
  fontSize: 15,
};

const paragraphStyle: React.CSSProperties = {
  color: "var(--text-secondary)",
  fontSize: 13,
  lineHeight: 1.7,
};

const detailStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  gap: 12,
  borderTop: "1px solid var(--border-dim)",
  paddingTop: 10,
  marginTop: 10,
  color: "var(--text-secondary)",
  fontSize: 12,
};

const openLinkStyle: React.CSSProperties = {
  display: "block",
  textAlign: "center",
  border: "1px solid rgba(102,168,255,0.36)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(102,168,255,0.12)",
  color: "var(--accent)",
  padding: "11px 12px",
  textDecoration: "none",
  fontWeight: 800,
};

const emptyStyle: React.CSSProperties = {
  height: "100%",
  display: "grid",
  placeItems: "center",
  padding: 28,
  textAlign: "center",
  fontSize: 13,
};

const eyebrowStyle: React.CSSProperties = {
  color: "var(--text-muted)",
  fontSize: 10,
  fontWeight: 900,
  textTransform: "uppercase",
};
