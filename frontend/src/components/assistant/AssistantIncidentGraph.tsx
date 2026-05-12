"use client";

import React from "react";
import ConsoleModule from "@/components/ui/ConsoleModule";
import StatusPill from "@/components/ui/StatusPill";

type GraphNode = {
  id: string;
  type: string;
  label: string;
  subtitle?: string;
  severity: string;
  x: number;
  y: number;
  details?: string;
};

type GraphEdge = {
  from: string;
  to: string;
  label?: string;
};

export default function AssistantIncidentGraph({ graph }: { graph: any }) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes as GraphNode[] : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges as GraphEdge[] : [];
  const [query, setQuery] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [selectedId, setSelectedId] = React.useState(nodes[0]?.id || "");

  React.useEffect(() => {
    setSelectedId((current) => nodes.some((node) => node.id === current) ? current : nodes[0]?.id || "");
  }, [nodes]);

  const nodesById = React.useMemo(() => Object.fromEntries(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = nodesById[selectedId] || nodes[0] || null;
  const connectedIds = React.useMemo(() => {
    const ids = new Set<string>();
    if (!selected) return ids;
    ids.add(selected.id);
    edges.forEach((edge) => {
      if (edge.from === selected.id) ids.add(edge.to);
      if (edge.to === selected.id) ids.add(edge.from);
    });
    return ids;
  }, [edges, selected]);

  const filteredNodes = nodes.filter((node) => {
    const q = query.trim().toLowerCase();
    const matchesQuery = !q || `${node.label} ${node.subtitle || ""} ${node.type} ${node.severity}`.toLowerCase().includes(q);
    const matchesSeverity = severity === "all" || node.severity === severity;
    return matchesQuery && matchesSeverity;
  });
  const visibleIds = new Set(filteredNodes.map((node) => node.id));
  const visibleEdges = edges.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to));
  const checks = Array.isArray(graph?.data_checks) ? graph.data_checks : [];
  const passedChecks = checks.filter((check: any) => check?.passed).length;

  return (
    <ConsoleModule
      eyebrow="SOC investigation graph"
      title={graph?.summary?.incident || "Assistant incident graph"}
      description="Per-session relationship view for the alert, indicators, affected identities, assets, and follow-on activity."
      tone={riskTone(graph?.summary?.risk)}
      compact
      actions={<StatusPill tone={riskTone(graph?.summary?.risk)} outline>{graph?.summary?.score ?? 0}/100</StatusPill>}
    >
      <div style={heroStyle}>
        <Metric label="Risk score" value={graph?.summary?.score ?? 0} />
        <Metric label="Indicators" value={nodes.length} />
        <Metric label="High+" value={nodes.filter((node) => ["critical", "high"].includes(node.severity)).length} />
        <Metric label="Confidence" value={graph?.summary?.confidence || "Medium"} />
      </div>

      <div style={layoutStyle}>
        <div style={graphShellStyle}>
          <div style={toolbarStyle}>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicator, user, IP, domain..." style={inputStyle} />
            <select value={severity} onChange={(event) => setSeverity(event.target.value)} style={selectStyle}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button type="button" onClick={() => { setQuery(""); setSeverity("all"); setSelectedId(nodes[0]?.id || ""); }} style={buttonStyle}>Reset</button>
          </div>
          <div style={canvasViewportStyle}>
            <div style={canvasStyle}>
              <svg style={svgStyle}>
                <defs>
                  <marker id="assistant-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                    <path d="M0,0 L0,6 L9,3 z" fill="rgba(148,163,184,0.72)" />
                  </marker>
                </defs>
                {visibleEdges.map((edge, idx) => (
                  <GraphEdgeView key={`${edge.from}-${edge.to}-${idx}`} edge={edge} nodesById={nodesById} activeNodeId={selected?.id} />
                ))}
              </svg>
              {filteredNodes.map((node) => (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => setSelectedId(node.id)}
                  style={{
                    ...nodeStyle,
                    left: node.x,
                    top: node.y,
                    borderColor: severityColor(node.severity),
                    boxShadow: selected?.id === node.id ? `0 0 0 2px #67e8f9, 0 18px 40px ${severityColor(node.severity)}33` : `0 18px 40px ${severityColor(node.severity)}22`,
                    opacity: selected && !connectedIds.has(node.id) ? 0.42 : 1,
                  }}
                >
                  <div style={nodeHeaderStyle}>
                    <span style={nodeIconStyle}>{typeIcon(node.type)}</span>
                    <span style={{ minWidth: 0 }}>
                      <strong style={nodeTitleStyle}>{node.label}</strong>
                      <span style={nodeSubtitleStyle}>{node.subtitle || node.type}</span>
                    </span>
                  </div>
                  <span style={{ ...severityBadgeStyle, borderColor: severityColor(node.severity), color: severityColor(node.severity) }}>
                    {node.severity}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <aside style={inspectorStyle}>
          <Panel title="Selected indicator">
            {selected ? (
              <>
                <StatusPill tone={riskTone(selected.severity)} outline>{selected.type}</StatusPill>
                <h3 style={inspectorTitleStyle}>{selected.label}</h3>
                <p style={paragraphStyle}>{selected.details || selected.subtitle || "No details available."}</p>
                <div style={statGridStyle}>
                  <MiniStat label="Severity" value={selected.severity} />
                  <MiniStat label="Connections" value={Math.max(0, connectedIds.size - 1)} />
                </div>
              </>
            ) : <p style={paragraphStyle}>Select a node to inspect details.</p>}
          </Panel>

          <Panel title="Analyst summary">
            <p style={paragraphStyle}>{nodes[0]?.details || graph?.summary?.incident || "No graph summary available."}</p>
            <MiniStat label="Last seen" value={graph?.summary?.lastSeen || "-"} full />
          </Panel>

          <Panel title="Recommended actions">
            <div style={{ display: "grid", gap: 8 }}>
              {(Array.isArray(graph?.recommended_actions) ? graph.recommended_actions : []).slice(0, 5).map((action: string, idx: number) => (
                <div key={`${action}-${idx}`} style={actionStyle}>{action}</div>
              ))}
            </div>
          </Panel>

          {checks.length ? (
            <Panel title="Graph data checks">
              <MiniStat label="Passed" value={`${passedChecks}/${checks.length}`} full />
              <div style={{ display: "grid", gap: 6, marginTop: 10 }}>
                {checks.map((check: any) => (
                  <div key={check.name} style={checkRowStyle}>
                    <span>{check.name}</span>
                    <strong style={{ color: check.passed ? "var(--green)" : "var(--red)" }}>{check.passed ? "pass" : "fail"}</strong>
                  </div>
                ))}
              </div>
            </Panel>
          ) : null}
        </aside>
      </div>
    </ConsoleModule>
  );
}

function GraphEdgeView({ edge, nodesById, activeNodeId }: { edge: GraphEdge; nodesById: Record<string, GraphNode>; activeNodeId?: string }) {
  const from = nodesById[edge.from];
  const to = nodesById[edge.to];
  if (!from || !to) return null;
  const x1 = from.x + 95;
  const y1 = from.y + 42;
  const x2 = to.x + 95;
  const y2 = to.y + 42;
  const midX = (x1 + x2) / 2;
  const midY = (y1 + y2) / 2;
  const active = activeNodeId && (edge.from === activeNodeId || edge.to === activeNodeId);
  return (
    <g>
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={active ? "#67e8f9" : "rgba(148,163,184,0.48)"} strokeWidth={active ? 2.8 : 1.5} strokeDasharray={active ? "0" : "6 6"} markerEnd="url(#assistant-arrow)" />
      <foreignObject x={midX - 58} y={midY - 14} width="116" height="28">
        <div style={{ ...edgeLabelStyle, borderColor: active ? "rgba(103,232,249,0.56)" : "rgba(148,163,184,0.26)", color: active ? "#cffafe" : "var(--text-secondary)" }}>
          {edge.label || "related"}
        </div>
      </foreignObject>
    </g>
  );
}

function Metric({ label, value }: { label: string; value: any }) {
  return <div style={metricStyle}><strong>{value}</strong><span>{label}</span></div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <div style={panelStyle}><h3 style={panelTitleStyle}>{title}</h3>{children}</div>;
}

function MiniStat({ label, value, full = false }: { label: string; value: any; full?: boolean }) {
  return <div style={{ ...miniStatStyle, gridColumn: full ? "1 / -1" : undefined }}><span>{label}</span><strong>{String(value)}</strong></div>;
}

function severityColor(severity: string) {
  if (severity === "critical") return "#fb7185";
  if (severity === "high") return "#fb923c";
  if (severity === "medium") return "#fde047";
  return "#94a3b8";
}

function riskTone(value: any): "neutral" | "info" | "success" | "warning" | "danger" {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "danger";
  if (normalized === "medium") return "warning";
  if (normalized === "low") return "success";
  return "info";
}

function typeIcon(type: string) {
  return ({ alert: "!", ip: "IP", geo: "G", user: "@", success: "*", endpoint: "E", mail: "M", domain: "D", malware: "#" } as Record<string, string>)[type] || "I";
}

const heroStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10, marginBottom: 14 };
const metricStyle: React.CSSProperties = { display: "grid", gap: 4, padding: 12, border: "1px solid var(--border-dim)", borderRadius: 14, background: "rgba(2,6,23,0.34)", textAlign: "center", color: "var(--text-secondary)" };
const layoutStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(0, 1fr) 340px", gap: 16 };
const graphShellStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 16, overflow: "hidden", background: "rgba(8,15,29,0.58)" };
const toolbarStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(180px, 1fr) 150px 82px", gap: 10, padding: 12, borderBottom: "1px solid var(--border-dim)" };
const inputStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 14, background: "rgba(2,6,23,0.5)", color: "var(--text-primary)", padding: "9px 11px" };
const selectStyle: React.CSSProperties = { ...inputStyle };
const buttonStyle: React.CSSProperties = { border: "1px solid rgba(102,168,255,0.28)", borderRadius: 14, background: "rgba(102,168,255,0.14)", color: "var(--text-primary)", fontWeight: 800 };
const canvasViewportStyle: React.CSSProperties = { height: 680, overflow: "auto", background: "radial-gradient(circle at 30% 20%, rgba(34,211,238,0.08), transparent 30%), radial-gradient(circle at 80% 60%, rgba(248,113,113,0.08), transparent 30%)" };
const canvasStyle: React.CSSProperties = { position: "relative", width: 1240, height: 760 };
const svgStyle: React.CSSProperties = { position: "absolute", inset: 0, width: "100%", height: "100%" };
const nodeStyle: React.CSSProperties = { position: "absolute", width: 190, minHeight: 92, border: "1px solid", borderRadius: 16, padding: 12, textAlign: "left", background: "rgba(15,23,42,0.82)", color: "var(--text-primary)", cursor: "pointer", transition: "opacity 140ms ease, transform 140ms ease" };
const nodeHeaderStyle: React.CSSProperties = { display: "flex", gap: 9, alignItems: "flex-start" };
const nodeIconStyle: React.CSSProperties = { width: 34, height: 34, borderRadius: 12, display: "grid", placeItems: "center", background: "rgba(2,6,23,0.48)", fontSize: 10, fontWeight: 900, flex: "0 0 auto" };
const nodeTitleStyle: React.CSSProperties = { display: "block", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontSize: 13 };
const nodeSubtitleStyle: React.CSSProperties = { display: "block", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--text-secondary)", fontSize: 11, marginTop: 2 };
const severityBadgeStyle: React.CSSProperties = { display: "inline-flex", marginTop: 12, border: "1px solid", borderRadius: 999, padding: "3px 8px", fontSize: 10, textTransform: "uppercase", fontWeight: 900 };
const edgeLabelStyle: React.CSSProperties = { border: "1px solid", borderRadius: 999, background: "rgba(2,6,23,0.72)", textAlign: "center", fontSize: 10, padding: "4px 7px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
const inspectorStyle: React.CSSProperties = { display: "grid", gap: 12, alignContent: "start" };
const panelStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 16, background: "rgba(15,23,42,0.42)", padding: 15 };
const panelTitleStyle: React.CSSProperties = { margin: "0 0 12px", fontSize: 15, color: "var(--text-primary)" };
const inspectorTitleStyle: React.CSSProperties = { margin: "10px 0 8px", color: "var(--text-strong)", wordBreak: "break-word" };
const paragraphStyle: React.CSSProperties = { margin: 0, color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.65 };
const statGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 12 };
const miniStatStyle: React.CSSProperties = { display: "flex", justifyContent: "space-between", gap: 10, border: "1px solid var(--border-dim)", borderRadius: 12, padding: 10, color: "var(--text-secondary)", fontSize: 12 };
const actionStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 12, padding: 10, color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.5 };
const checkRowStyle: React.CSSProperties = { display: "flex", justifyContent: "space-between", gap: 10, color: "var(--text-secondary)", fontSize: 12 };
