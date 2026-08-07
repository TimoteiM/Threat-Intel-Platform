"use client";

import React from "react";
import dagre from "dagre";
import ReactFlow, {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlowProvider,
  getBezierPath,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "reactflow";
import "reactflow/dist/style.css";
import "./AssistantIncidentGraph.css";
import ConsoleModule from "@/components/ui/ConsoleModule";
import StatusPill from "@/components/ui/StatusPill";

type Severity = "low" | "medium" | "high" | "critical";

type SocGraphNode = {
  id: string;
  type: string;
  label: string;
  value: string;
  severity: Severity;
  category: string;
  source: string[];
  metadata: Record<string, any>;
  evidence: string[];
  rawRefs: string[];
  details?: string;
};

type SocGraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  confidence?: number;
  sourceName?: string;
  evidence: string[];
  rawRefs: string[];
};

type SocGraph = {
  summary: Record<string, any>;
  nodes: SocGraphNode[];
  edges: SocGraphEdge[];
  recommendedActions: string[];
  centralNodeId: string;
};

const NODE_WIDTH = 220;
const NODE_HEIGHT = 86;
const CLUSTER_GAP_X = 145;
const CLUSTER_GAP_Y = 90;
const FIRST_HOP_LIMIT = 42;

const nodeTypes = { socEntity: SocEntityNode };
const edgeTypes = { socEdge: SocEntityEdge };

export default function AssistantIncidentGraph({ graph, fullPage = false }: { graph: any; fullPage?: boolean }) {
  return (
    <ReactFlowProvider>
      <AssistantIncidentGraphInner graph={graph} fullPage={fullPage} />
    </ReactFlowProvider>
  );
}

function AssistantIncidentGraphInner({ graph, fullPage }: { graph: any; fullPage: boolean }) {
  const flow = useReactFlow();
  const normalized = React.useMemo(() => normalizeSocGraph(graph), [graph]);
  const [query, setQuery] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [typeFilter, setTypeFilter] = React.useState("all");
  const [relationshipFilter, setRelationshipFilter] = React.useState("all");
  const [sourceFilter, setSourceFilter] = React.useState("all");
  const [selectedId, setSelectedId] = React.useState(normalized.centralNodeId);
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set([normalized.centralNodeId]));
  const [showFullGraph, setShowFullGraph] = React.useState(false);
  const [showLabels, setShowLabels] = React.useState(true);
  const [showEdgeLabels, setShowEdgeLabels] = React.useState(false);
  const [manualPositions, setManualPositions] = React.useState<Record<string, { x: number; y: number }>>({});
  const [zoom, setZoom] = React.useState(1);

  React.useEffect(() => {
    setSelectedId(normalized.centralNodeId);
    setExpandedIds(new Set([normalized.centralNodeId]));
    setShowFullGraph(normalized.nodes.length <= FIRST_HOP_LIMIT);
    setManualPositions({});
  }, [normalized.centralNodeId, normalized.nodes.length]);

  const adjacency = React.useMemo(() => buildAdjacency(normalized.edges), [normalized.edges]);
  const searchMatches = React.useMemo(() => findSearchMatches(normalized.nodes, query), [normalized.nodes, query]);
  const shortestPath = React.useMemo(
    () => selectedId ? shortestPathIds(normalized.centralNodeId, selectedId, adjacency) : new Set<string>(),
    [adjacency, normalized.centralNodeId, selectedId],
  );
  const visibleIds = React.useMemo(
    () => computeVisibleNodeIds(normalized, adjacency, expandedIds, showFullGraph, searchMatches),
    [adjacency, expandedIds, normalized, searchMatches, showFullGraph],
  );
  const filtered = React.useMemo(
    () => applyGraphFilters(normalized, visibleIds, { severity, typeFilter, relationshipFilter, sourceFilter }),
    [normalized, relationshipFilter, severity, sourceFilter, typeFilter, visibleIds],
  );
  const layouted = React.useMemo(
    () => layoutSocGraph(filtered.nodes, filtered.edges, normalized.centralNodeId),
    [filtered.edges, filtered.nodes, normalized.centralNodeId],
  );

  const selected = normalized.nodes.find((node) => node.id === selectedId) || normalized.nodes[0] || null;
  const relatedEdges = React.useMemo(
    () => normalized.edges.filter((edge) => edge.source === selectedId || edge.target === selectedId),
    [normalized.edges, selectedId],
  );
  const typeOptions = React.useMemo(() => uniqueSorted(normalized.nodes.map((node) => node.type)), [normalized.nodes]);
  const relationshipOptions = React.useMemo(() => uniqueSorted(normalized.edges.map((edge) => edge.type)), [normalized.edges]);
  const sourceOptions = React.useMemo(
    () => uniqueSorted([...normalized.nodes.flatMap((node) => node.source), ...normalized.edges.map((edge) => edge.sourceName || "").filter(Boolean)]),
    [normalized.edges, normalized.nodes],
  );

  const flowNodes: Node[] = React.useMemo(
    () => layouted.nodes.map((node) => ({
      id: node.id,
      type: "socEntity",
      position: manualPositions[node.id] || node.position,
      data: {
        node: node.raw,
        selected: node.id === selectedId,
        dimmed: Boolean(selectedId && !shortestPath.has(node.id) && !adjacency.get(selectedId)?.has(node.id) && node.id !== selectedId && searchMatches.size === 0),
        highlighted: searchMatches.has(node.id) || shortestPath.has(node.id),
        showLabel: showLabels && zoom >= 0.58,
        canExpand: Boolean(adjacency.get(node.id)?.size),
        expanded: expandedIds.has(node.id) || showFullGraph,
        onExpand: () => toggleExpanded(node.id),
      },
      draggable: true,
    })),
    [adjacency, expandedIds, layouted.nodes, manualPositions, searchMatches, selectedId, shortestPath, showFullGraph, showLabels, zoom],
  );

  const flowEdges: Edge[] = React.useMemo(
    () => layouted.edges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: "socEdge",
      label: edge.label,
      markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(edge) },
      data: {
        edge,
        active: selectedId ? edge.source === selectedId || edge.target === selectedId || (shortestPath.has(edge.source) && shortestPath.has(edge.target)) : false,
        showLabel: showEdgeLabels || (selectedId ? edge.source === selectedId || edge.target === selectedId : false),
      },
    })),
    [layouted.edges, selectedId, shortestPath, showEdgeLabels],
  );

  React.useEffect(() => {
    const match = searchMatches.values().next().value;
    if (!query.trim() || !match) return;
    setSelectedId(match);
    setExpandedIds((current) => new Set([...Array.from(current), normalized.centralNodeId, match]));
    const target = layouted.nodes.find((node) => node.id === match);
    if (target) {
      window.setTimeout(() => flow.setCenter(target.position.x + NODE_WIDTH / 2, target.position.y + NODE_HEIGHT / 2, { zoom: 1.05, duration: 320 }), 0);
    }
  }, [flow, layouted.nodes, normalized.centralNodeId, query, searchMatches]);

  React.useEffect(() => {
    window.setTimeout(() => flow.fitView({ padding: 0.18, duration: 350, maxZoom: 1.05 }), 80);
  }, [flow, layouted.layoutKey]);

  function toggleExpanded(id: string) {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(id) && id !== normalized.centralNodeId) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function resetGraph() {
    setQuery("");
    setSeverity("all");
    setTypeFilter("all");
    setRelationshipFilter("all");
    setSourceFilter("all");
    setSelectedId(normalized.centralNodeId);
    setExpandedIds(new Set([normalized.centralNodeId]));
    setShowFullGraph(normalized.nodes.length <= FIRST_HOP_LIMIT);
    window.setTimeout(() => flow.fitView({ padding: 0.18, duration: 300, maxZoom: 1.05 }), 0);
  }

  function selectNode(_: React.MouseEvent, node: Node) {
    setSelectedId(node.id);
    flow.setCenter(node.position.x + NODE_WIDTH / 2, node.position.y + NODE_HEIGHT / 2, { zoom: Math.max(0.9, zoom), duration: 280 });
  }

  const title = normalized.summary?.incident || selected?.label || "SOC investigation graph";
  const investigationType = String(normalized.summary?.investigationType || "generic_multi_cluster_investigation");

  return (
    <ConsoleModule
      eyebrow="SOC investigation graph"
      title={title}
      description={`OpenCTI-style ${typeLabel(investigationType)} graph. First-hop relationships are shown by default; expand nodes for deeper pivots.`}
      tone={riskTone(normalized.summary?.risk)}
      compact
      actions={<GraphBadges graph={normalized} />}
    >
      <div className="assistant-graph-metrics">
        <Metric label="Risk score" value={normalized.summary?.score ?? 0} />
        <Metric label="Visible nodes" value={flowNodes.length} />
        <Metric label="Total nodes" value={normalized.nodes.length} />
        <Metric label="Confidence" value={normalized.summary?.confidence || "Medium"} />
      </div>

      <div className={fullPage ? "assistant-graph-layout assistant-graph-layout--full" : "assistant-graph-layout"}>
        <section className="assistant-graph-shell">
          <div className="assistant-graph-toolbar">
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicator, user, IP, domain, hash..." className="assistant-graph-input" />
            <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="assistant-graph-select">
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="assistant-graph-select">
              <option value="all">All types</option>
              {typeOptions.map((type) => <option key={type} value={type}>{typeLabel(type)}</option>)}
            </select>
            <select value={relationshipFilter} onChange={(event) => setRelationshipFilter(event.target.value)} className="assistant-graph-select">
              <option value="all">All relationships</option>
              {relationshipOptions.map((type) => <option key={type} value={type}>{relationshipLabel(type)}</option>)}
            </select>
            <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)} className="assistant-graph-select">
              <option value="all">All sources</option>
              {sourceOptions.map((source) => <option key={source} value={source}>{source}</option>)}
            </select>
            <button type="button" onClick={resetGraph} className="assistant-graph-button">Reset</button>
          </div>

          <div className="assistant-graph-controlbar">
            <button type="button" onClick={() => flow.zoomIn({ duration: 180 })}>+</button>
            <button type="button" onClick={() => flow.zoomOut({ duration: 180 })}>-</button>
            <button type="button" onClick={() => flow.fitView({ padding: 0.18, duration: 250 })}>Fit</button>
            <button type="button" onClick={resetGraph}>Reset layout</button>
            <button type="button" onClick={() => setShowLabels((value) => !value)} className={showLabels ? "is-active" : ""}>Labels</button>
            <button type="button" onClick={() => setShowEdgeLabels((value) => !value)} className={showEdgeLabels ? "is-active" : ""}>Edge labels</button>
            <button type="button" onClick={() => setShowFullGraph((value) => !value)} className={showFullGraph ? "is-active" : ""}>Full graph</button>
            <button type="button" onClick={() => exportGraphSvg(flowNodes, flowEdges)}>SVG</button>
            <button type="button" onClick={() => exportGraphPng(flowNodes, flowEdges)}>PNG</button>
          </div>

          <div className="assistant-graph-canvas">
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodeClick={selectNode}
              onNodeDragStop={(_, node) => setManualPositions((current) => ({ ...current, [String(node.id)]: node.position }))}
              onMove={(_, viewport) => setZoom(viewport.zoom)}
              minZoom={0.18}
              maxZoom={1.85}
              fitView
              fitViewOptions={{ padding: 0.18, maxZoom: 1.05 }}
              proOptions={{ hideAttribution: true }}
              defaultEdgeOptions={{ type: "socEdge" }}
            >
              <Background color="rgba(148,163,184,0.18)" gap={28} />
              <Controls showInteractive={false} />
              <MiniMap
                nodeColor={(node) => entityStyle(node.data?.node?.type).color}
                nodeStrokeWidth={3}
                pannable
                zoomable
                className="assistant-graph-minimap"
              />
            </ReactFlow>
          </div>
        </section>

        <aside className="assistant-graph-side">
          <DetailsPanel
            selected={selected}
            relatedEdges={relatedEdges}
            relatedNodes={normalized.nodes}
            onSelect={setSelectedId}
            onExpand={(id) => setExpandedIds((current) => new Set([...Array.from(current), id]))}
          />
          <Legend nodes={normalized.nodes} edges={normalized.edges} />
          <Panel title="Graph logic">
            <p className="assistant-graph-muted">
              Layout is computed by category clusters with Dagre. The default view is depth-limited to first-hop relationships so large investigations stay usable.
            </p>
          </Panel>
        </aside>
      </div>
    </ConsoleModule>
  );
}

function SocEntityNode({ data }: NodeProps) {
  const node: SocGraphNode = data.node;
  const style = entityStyle(node.type);
  const important = ["alert", "incident", "domain", "ip", "url", "file", "hash"].includes(node.type);
  return (
    <div
      className={[
        "assistant-graph-node",
        important ? "assistant-graph-node--important" : "",
        data.selected ? "is-selected" : "",
        data.highlighted ? "is-highlighted" : "",
        data.dimmed ? "is-dimmed" : "",
      ].filter(Boolean).join(" ")}
      style={{ "--entity-color": style.color, "--severity-color": severityColor(node.severity) } as React.CSSProperties}
      title={`${node.type}: ${node.value}`}
    >
      <Handle type="target" position={Position.Left} className="assistant-graph-handle" />
      <div className="assistant-graph-node__top">
        <span className="assistant-graph-node__icon">{style.icon}</span>
        <span className="assistant-graph-node__type">{typeLabel(node.type)}</span>
        <span className="assistant-graph-node__severity">{node.severity}</span>
      </div>
      {data.showLabel ? (
        <>
          <strong className="assistant-graph-node__label">{node.label}</strong>
          <span className="assistant-graph-node__value">{node.value}</span>
        </>
      ) : null}
      <button
        type="button"
        className="assistant-graph-node__expand"
        onClick={(event) => {
          event.stopPropagation();
          data.onExpand();
        }}
        disabled={!data.canExpand}
        title={data.expanded ? "Collapse relationships" : "Expand relationships"}
      >
        {data.expanded ? "-" : "+"}
      </button>
      <Handle type="source" position={Position.Right} className="assistant-graph-handle" />
    </div>
  );
}

function SocEntityEdge(props: EdgeProps) {
  const [path, labelX, labelY] = getBezierPath(props);
  const edge: SocGraphEdge | undefined = props.data?.edge;
  const active = Boolean(props.data?.active);
  const showLabel = Boolean(props.data?.showLabel);
  return (
    <>
      <BaseEdge
        path={path}
        markerEnd={props.markerEnd}
        style={{
          stroke: edge ? edgeColor(edge) : "rgba(148,163,184,0.38)",
          strokeWidth: active ? 2.8 : 1.35,
          opacity: active ? 0.95 : 0.48,
        }}
      />
      {showLabel && edge ? (
        <EdgeLabelRenderer>
          <div className="assistant-graph-edge-label" style={{ transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)` }}>
            {relationshipLabel(edge.type)}
          </div>
        </EdgeLabelRenderer>
      ) : null}
    </>
  );
}

function DetailsPanel({
  selected,
  relatedEdges,
  relatedNodes,
  onSelect,
  onExpand,
}: {
  selected: SocGraphNode | null;
  relatedEdges: SocGraphEdge[];
  relatedNodes: SocGraphNode[];
  onSelect: (id: string) => void;
  onExpand: (id: string) => void;
}) {
  if (!selected) {
    return <Panel title="Selected entity"><p className="assistant-graph-muted">Select a node to inspect evidence.</p></Panel>;
  }
  const relatedById = new Map(relatedNodes.map((node) => [node.id, node]));
  const mitre = relatedEdges
    .map((edge) => relatedById.get(edge.source === selected.id ? edge.target : edge.source))
    .filter((node): node is SocGraphNode => Boolean(node && node.type === "mitre"));

  return (
    <Panel title="Selected entity">
      <div className="assistant-graph-details-head">
        <StatusPill tone={riskTone(selected.severity)} outline>{typeLabel(selected.type)}</StatusPill>
        <button type="button" onClick={() => navigator.clipboard?.writeText(selected.value)} className="assistant-graph-mini-button">Copy</button>
      </div>
      <h3 className="assistant-graph-details-title">{selected.label}</h3>
      <p className="assistant-graph-muted">{selected.details || selected.value}</p>
      <div className="assistant-graph-stat-grid">
        <MiniStat label="Severity" value={selected.severity} />
        <MiniStat label="Risk" value={selected.metadata?.riskScore ?? "-"} />
        <MiniStat label="First seen" value={selected.metadata?.firstSeen || "-"} />
        <MiniStat label="Last seen" value={selected.metadata?.lastSeen || "-"} />
        <MiniStat label="Source" value={selected.source.join(", ") || "-"} full />
      </div>
      {mitre.length ? (
        <div className="assistant-graph-list">
          <strong>Related MITRE</strong>
          {mitre.slice(0, 6).map((node) => <button key={node.id} type="button" onClick={() => onSelect(node.id)}>{node.label}</button>)}
        </div>
      ) : null}
      <div className="assistant-graph-list">
        <strong>Relationships</strong>
        {relatedEdges.slice(0, 10).map((edge) => {
          const otherId = edge.source === selected.id ? edge.target : edge.source;
          const other = relatedById.get(otherId);
          return (
            <button key={edge.id} type="button" onClick={() => other && onSelect(other.id)}>
              <span>{relationshipLabel(edge.type)}</span>
              <small>{other?.label || otherId}</small>
            </button>
          );
        })}
      </div>
      <div className="assistant-graph-actions">
        <button type="button" onClick={() => onExpand(selected.id)}>Expand relationships</button>
      </div>
      {selected.evidence.length || selected.rawRefs.length ? (
        <div className="assistant-graph-evidence">
          <strong>Raw evidence</strong>
          {[...selected.evidence, ...selected.rawRefs].slice(0, 8).map((item) => <code key={item}>{item}</code>)}
        </div>
      ) : null}
    </Panel>
  );
}

function Legend({ nodes, edges }: { nodes: SocGraphNode[]; edges: SocGraphEdge[] }) {
  const types = uniqueSorted(nodes.map((node) => node.type)).slice(0, 12);
  const rels = uniqueSorted(edges.map((edge) => edge.type)).slice(0, 10);
  return (
    <Panel title="Legend">
      <div className="assistant-graph-legend">
        {types.map((type) => {
          const style = entityStyle(type);
          return <span key={type}><i style={{ background: style.color }}>{style.icon}</i>{typeLabel(type)}</span>;
        })}
      </div>
      <div className="assistant-graph-relationships">
        {rels.map((type) => <span key={type}>{relationshipLabel(type)}</span>)}
      </div>
    </Panel>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="assistant-graph-panel"><h3>{title}</h3>{children}</div>;
}

function Metric({ label, value }: { label: string; value: any }) {
  return <div className="assistant-graph-metric"><strong>{value}</strong><span>{label}</span></div>;
}

function MiniStat({ label, value, full = false }: { label: string; value: any; full?: boolean }) {
  return <div className="assistant-graph-mini-stat" style={{ gridColumn: full ? "1 / -1" : undefined }}><span>{label}</span><strong>{String(value)}</strong></div>;
}

function GraphBadges({ graph }: { graph: SocGraph }) {
  return (
    <div className="assistant-graph-badges">
      <StatusPill tone="info" outline>{typeLabel(String(graph.summary?.investigationType || "SOC graph"))}</StatusPill>
      <StatusPill tone={riskTone(graph.summary?.risk)} outline>{graph.summary?.score ?? 0}/100</StatusPill>
    </div>
  );
}

function normalizeSocGraph(graph: any): SocGraph {
  const legacyNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const legacyEdges = Array.isArray(graph?.edges) ? graph.edges : [];
  const nodes: SocGraphNode[] = legacyNodes.map((node: any): SocGraphNode => {
    const type = normalizeEntityType(node.type);
    const value = String(node.value || node.label || node.subtitle || node.id);
    return {
      id: String(node.id || `${type}:${value}`),
      type,
      label: String(node.label || value),
      value,
      severity: normalizeSeverity(node.severity),
      category: categoryForType(type),
      source: normalizeSources(node.source || node.sources || node.metadata?.source || node.rawRefs),
      metadata: {
        firstSeen: node.firstSeen || node.metadata?.firstSeen || node.time || graph?.summary?.firstSeen,
        lastSeen: node.lastSeen || node.metadata?.lastSeen || graph?.summary?.lastSeen,
        riskScore: node.riskScore || node.metadata?.riskScore || severityScore(node.severity),
        verdict: node.verdict || node.metadata?.verdict,
        role: node.role,
      },
      evidence: Array.isArray(node.evidence) ? node.evidence : [],
      rawRefs: Array.isArray(node.rawRefs) ? node.rawRefs : [],
      details: node.details || node.takeaway || node.subtitle,
    };
  });

  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = legacyEdges
    .map((edge: any, index: number): SocGraphEdge => {
      const source = String(edge.source || edge.from);
      const target = String(edge.target || edge.to);
      const type = normalizeRelationshipType(edge.type || edge.kind || edge.label);
      return {
        id: String(edge.id || `${source}->${target}:${type}:${index}`),
        source,
        target,
        type,
        label: String(edge.label || relationshipLabel(type)),
        confidence: confidenceToNumber(edge.confidence),
        sourceName: normalizeSources(edge.sourceName || edge.source_system || edge.vendor || edge.rawRefs)[0],
        evidence: Array.isArray(edge.evidence) ? edge.evidence : [],
        rawRefs: Array.isArray(edge.rawRefs) ? edge.rawRefs : [],
      };
    })
    .filter((edge: SocGraphEdge) => nodeIds.has(edge.source) && nodeIds.has(edge.target));

  const centralNodeId = chooseCentralNode(nodes, edges, graph?.summary);
  return {
    summary: graph?.summary || {},
    nodes,
    edges,
    recommendedActions: Array.isArray(graph?.recommendedActions) ? graph.recommendedActions : Array.isArray(graph?.recommended_actions) ? graph.recommended_actions : [],
    centralNodeId,
  };
}

function layoutSocGraph(nodes: SocGraphNode[], edges: SocGraphEdge[], centralNodeId: string) {
  const graph = new dagre.graphlib.Graph({ compound: true });
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({
    rankdir: "LR",
    nodesep: CLUSTER_GAP_Y,
    ranksep: CLUSTER_GAP_X,
    marginx: 80,
    marginy: 70,
  });

  // Layout logic: each entity type maps to a SOC/CTI category. Dagre keeps edges routed left-to-right
  // while category offsets spread entities into OpenCTI-like bands instead of a narrow vertical chain.
  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target));
  dagre.layout(graph);

  const categories = uniqueSorted(nodes.map((node) => node.category));
  const categoryIndex = new Map(categories.map((category, index) => [category, index]));
  const central = graph.node(centralNodeId);
  const layoutedNodes = nodes.map((node) => {
    const position = graph.node(node.id) || { x: 0, y: 0 };
    const categoryOffset = (categoryIndex.get(node.category) || 0) * 95;
    const isCentral = node.id === centralNodeId;
    return {
      id: node.id,
      raw: node,
      position: {
        x: isCentral ? 0 : Math.round(position.x - NODE_WIDTH / 2 + (position.x > (central?.x || 0) ? categoryOffset : -categoryOffset * 0.35)),
        y: isCentral ? 0 : Math.round(position.y - NODE_HEIGHT / 2 + categoryOffset),
      },
    };
  });
  return { nodes: layoutedNodes, edges, layoutKey: `${nodes.map((node) => node.id).join("|")}::${edges.map((edge) => edge.id).join("|")}` };
}

function computeVisibleNodeIds(graph: SocGraph, adjacency: Map<string, Set<string>>, expandedIds: Set<string>, showFullGraph: boolean, searchMatches: Set<string>) {
  if (showFullGraph) return new Set(graph.nodes.map((node) => node.id));
  const visible = new Set<string>([graph.centralNodeId]);
  const firstHop = Array.from(adjacency.get(graph.centralNodeId) || []).slice(0, FIRST_HOP_LIMIT);
  firstHop.forEach((id) => visible.add(id));
  // Expansion logic: analysts reveal second and third hops intentionally, keeping large cases responsive.
  expandedIds.forEach((id) => {
    visible.add(id);
    Array.from(adjacency.get(id) || []).forEach((neighbor) => visible.add(neighbor));
  });
  searchMatches.forEach((id) => {
    visible.add(id);
    Array.from(adjacency.get(id) || []).forEach((neighbor) => visible.add(neighbor));
  });
  return visible;
}

function applyGraphFilters(graph: SocGraph, visibleIds: Set<string>, filters: { severity: string; typeFilter: string; relationshipFilter: string; sourceFilter: string }) {
  // Filtering logic is applied before React Flow nodes are created so hidden nodes do not participate in rendering.
  const nodes = graph.nodes.filter((node) => {
    if (!visibleIds.has(node.id)) return false;
    if (filters.severity !== "all" && node.severity !== filters.severity) return false;
    if (filters.typeFilter !== "all" && node.type !== filters.typeFilter) return false;
    if (filters.sourceFilter !== "all" && !node.source.includes(filters.sourceFilter)) return false;
    return true;
  });
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return false;
    if (filters.relationshipFilter !== "all" && edge.type !== filters.relationshipFilter) return false;
    if (filters.sourceFilter !== "all" && edge.sourceName !== filters.sourceFilter) return false;
    return true;
  });
  return { nodes, edges };
}

function buildAdjacency(edges: SocGraphEdge[]) {
  const map = new Map<string, Set<string>>();
  edges.forEach((edge) => {
    if (!map.has(edge.source)) map.set(edge.source, new Set());
    if (!map.has(edge.target)) map.set(edge.target, new Set());
    map.get(edge.source)?.add(edge.target);
    map.get(edge.target)?.add(edge.source);
  });
  return map;
}

function shortestPathIds(start: string, end: string, adjacency: Map<string, Set<string>>) {
  if (start === end) return new Set([start]);
  const queue = [start];
  const previous = new Map<string, string | null>([[start, null]]);
  while (queue.length) {
    const current = queue.shift()!;
    for (const next of Array.from(adjacency.get(current) || [])) {
      if (previous.has(next)) continue;
      previous.set(next, current);
      if (next === end) {
        const path = new Set<string>();
        let cursor: string | null = end;
        while (cursor) {
          path.add(cursor);
          cursor = previous.get(cursor) || null;
        }
        return path;
      }
      queue.push(next);
    }
  }
  return new Set([start, end]);
}

function findSearchMatches(nodes: SocGraphNode[], query: string) {
  const q = query.trim().toLowerCase();
  if (!q) return new Set<string>();
  return new Set(nodes.filter((node) => `${node.label} ${node.value} ${node.type} ${node.source.join(" ")}`.toLowerCase().includes(q)).map((node) => node.id));
}

function chooseCentralNode(nodes: SocGraphNode[], edges: SocGraphEdge[], summary: any) {
  const preferred = nodes.find((node) => ["primary_alert", "campaign", "incident"].includes(String(node.metadata?.role || "").toLowerCase()));
  if (preferred) return preferred.id;
  const alert = nodes.find((node) => ["alert", "incident"].includes(node.type));
  if (alert) return alert.id;
  const incident = String(summary?.incident || "").toLowerCase();
  const mentioned = nodes.find((node) => incident.includes(node.value.toLowerCase()));
  if (mentioned) return mentioned.id;
  const degree = new Map<string, number>();
  edges.forEach((edge) => {
    degree.set(edge.source, (degree.get(edge.source) || 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) || 0) + 1);
  });
  return [...nodes].sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0))[0]?.id || "";
}

function normalizeEntityType(type: any) {
  const value = String(type || "observable").toLowerCase();
  if (value === "success") return "alert";
  if (value === "mail") return "email";
  if (value === "endpoint") return "host";
  if (value === "network") return "network";
  if (value === "volume") return "detection";
  return value;
}

function categoryForType(type: string) {
  if (["alert", "incident", "detection"].includes(type)) return "Alert / Incident";
  if (["ip", "domain", "url", "hash"].includes(type)) return "Indicators";
  if (["geo", "app", "cloud"].includes(type)) return "Infrastructure";
  if (["host", "endpoint", "user"].includes(type)) return "Assets / Users";
  if (["process", "command", "file", "registry"].includes(type)) return "Endpoint Activity";
  if (["network"].includes(type)) return "Network Connections";
  if (["mitre"].includes(type)) return "MITRE ATT&CK";
  if (["email"].includes(type)) return "Email / Cloud";
  return "Observables";
}

function normalizeRelationshipType(type: any) {
  const value = String(type || "associated_with").toLowerCase().replace(/\s+/g, "_");
  if (value.includes("target")) return "contains_indicator";
  if (value.includes("spawn")) return "executed";
  if (value.includes("auth")) return "logged_in";
  if (value.includes("mitre") || value.includes("maps")) return "mapped_to_mitre";
  if (value.includes("block")) return "blocked_by";
  if (value.includes("query")) return "queried";
  if (value.includes("connect")) return "contacted";
  if (value.includes("download")) return "downloaded";
  if (value.includes("generated")) return "detected_by";
  return value || "associated_with";
}

function relationshipLabel(type: string) {
  return String(type || "associated_with").replace(/_/g, " ");
}

function normalizeSeverity(value: any): Severity {
  const severity = String(value || "medium").toLowerCase();
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") return severity;
  return "medium";
}

function normalizeSources(value: any): string[] {
  const raw = Array.isArray(value) ? value : value ? [value] : [];
  const joined = raw.map((item) => String(item));
  const known = ["SentinelOne", "Exabeam", "Cloudflare", "Palo Alto", "Okta", "Microsoft 365", "Trend Micro", "OpenCTI"];
  const found = known.filter((source) => joined.some((item) => item.toLowerCase().includes(source.toLowerCase())));
  return found.length ? found : joined.length ? uniqueSorted(joined.slice(0, 3)) : ["Normalized logs"];
}

function confidenceToNumber(value: any) {
  if (typeof value === "number") return value;
  const normalized = String(value || "").toLowerCase();
  if (normalized === "high") return 90;
  if (normalized === "medium") return 65;
  if (normalized === "low") return 35;
  return undefined;
}

function severityScore(value: any) {
  const severity = normalizeSeverity(value);
  return { critical: 95, high: 80, medium: 55, low: 25 }[severity];
}

function entityStyle(type: string) {
  const map: Record<string, { icon: string; color: string }> = {
    alert: { icon: "!", color: "#67e8f9" },
    incident: { icon: "!", color: "#67e8f9" },
    detection: { icon: "#", color: "#93c5fd" },
    ip: { icon: "IP", color: "#38bdf8" },
    domain: { icon: "D", color: "#22c55e" },
    url: { icon: "/", color: "#2dd4bf" },
    hash: { icon: "H", color: "#a78bfa" },
    user: { icon: "@", color: "#facc15" },
    host: { icon: "H", color: "#f59e0b" },
    process: { icon: "P", color: "#fb923c" },
    file: { icon: "F", color: "#c084fc" },
    command: { icon: "$", color: "#f97316" },
    network: { icon: "N", color: "#60a5fa" },
    mitre: { icon: "T", color: "#fb7185" },
    email: { icon: "M", color: "#e879f9" },
    cloud: { icon: "C", color: "#7dd3fc" },
  };
  return map[type] || { icon: "O", color: "#94a3b8" };
}

function severityColor(severity: string) {
  if (severity === "critical") return "#fb7185";
  if (severity === "high") return "#fb923c";
  if (severity === "medium") return "#fde047";
  return "#94a3b8";
}

function edgeColor(edge: SocGraphEdge) {
  if (edge.type.includes("blocked") || edge.type.includes("quarantined")) return "#22c55e";
  if (edge.type.includes("executed") || edge.type.includes("downloaded")) return "#fb923c";
  if (edge.type.includes("mitre")) return "#fb7185";
  return "#67e8f9";
}

function riskTone(value: any): "neutral" | "info" | "success" | "warning" | "danger" {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "danger";
  if (normalized === "medium") return "warning";
  if (normalized === "low") return "success";
  return "info";
}

function typeLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function uniqueSorted(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function exportGraphSvg(nodes: Node[], edges: Edge[]) {
  const svg = buildExportSvg(nodes, edges);
  downloadBlob("soc-investigation-graph.svg", "image/svg+xml", svg);
}

function exportGraphPng(nodes: Node[], edges: Edge[]) {
  const canvas = document.createElement("canvas");
  canvas.width = 1800;
  canvas.height = 1100;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.fillStyle = "#08111f";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  const bounds = graphBounds(nodes);
  const scale = Math.min(1, (canvas.width - 120) / bounds.width, (canvas.height - 120) / bounds.height);
  const ox = 60 - bounds.minX * scale;
  const oy = 60 - bounds.minY * scale;
  edges.forEach((edge) => {
    const from = nodes.find((node) => node.id === edge.source);
    const to = nodes.find((node) => node.id === edge.target);
    if (!from || !to) return;
    ctx.strokeStyle = "rgba(103,232,249,0.46)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo((from.position.x + NODE_WIDTH / 2) * scale + ox, (from.position.y + NODE_HEIGHT / 2) * scale + oy);
    ctx.lineTo((to.position.x + NODE_WIDTH / 2) * scale + ox, (to.position.y + NODE_HEIGHT / 2) * scale + oy);
    ctx.stroke();
  });
  nodes.forEach((node) => {
    const raw = node.data?.node as SocGraphNode;
    ctx.fillStyle = "#0f172a";
    ctx.strokeStyle = severityColor(raw?.severity || "medium");
    ctx.lineWidth = 2;
    ctx.fillRect(node.position.x * scale + ox, node.position.y * scale + oy, NODE_WIDTH * scale, NODE_HEIGHT * scale);
    ctx.strokeRect(node.position.x * scale + ox, node.position.y * scale + oy, NODE_WIDTH * scale, NODE_HEIGHT * scale);
    ctx.fillStyle = "#e5eefb";
    ctx.font = `${Math.max(10, 13 * scale)}px sans-serif`;
    ctx.fillText(raw?.label || node.id, node.position.x * scale + ox + 10, node.position.y * scale + oy + 28);
  });
  canvas.toBlob((blob) => blob && downloadBlob("soc-investigation-graph.png", "image/png", blob));
}

function buildExportSvg(nodes: Node[], edges: Edge[]) {
  const bounds = graphBounds(nodes);
  const width = Math.max(1200, bounds.width + 160);
  const height = Math.max(800, bounds.height + 160);
  const ox = 80 - bounds.minX;
  const oy = 80 - bounds.minY;
  const nodeMarkup = nodes.map((node) => {
    const raw = node.data?.node as SocGraphNode;
    return `<g><rect x="${node.position.x + ox}" y="${node.position.y + oy}" width="${NODE_WIDTH}" height="${NODE_HEIGHT}" rx="10" fill="#0f172a" stroke="${severityColor(raw?.severity || "medium")}" stroke-width="2"/><text x="${node.position.x + ox + 12}" y="${node.position.y + oy + 32}" fill="#e5eefb" font-family="Arial" font-size="13">${escapeXml(raw?.label || node.id)}</text><text x="${node.position.x + ox + 12}" y="${node.position.y + oy + 54}" fill="#94a3b8" font-family="Arial" font-size="11">${escapeXml(raw?.type || "")}</text></g>`;
  }).join("");
  const edgeMarkup = edges.map((edge) => {
    const from = nodes.find((node) => node.id === edge.source);
    const to = nodes.find((node) => node.id === edge.target);
    if (!from || !to) return "";
    return `<line x1="${from.position.x + ox + NODE_WIDTH / 2}" y1="${from.position.y + oy + NODE_HEIGHT / 2}" x2="${to.position.x + ox + NODE_WIDTH / 2}" y2="${to.position.y + oy + NODE_HEIGHT / 2}" stroke="#67e8f9" stroke-opacity="0.48" stroke-width="2"/>`;
  }).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="#08111f"/>${edgeMarkup}${nodeMarkup}</svg>`;
}

function graphBounds(nodes: Node[]) {
  const xs = nodes.map((node) => node.position.x);
  const ys = nodes.map((node) => node.position.y);
  const minX = Math.min(...xs, 0);
  const minY = Math.min(...ys, 0);
  const maxX = Math.max(...xs.map((x) => x + NODE_WIDTH), NODE_WIDTH);
  const maxY = Math.max(...ys.map((y) => y + NODE_HEIGHT), NODE_HEIGHT);
  return { minX, minY, maxX, maxY, width: maxX - minX, height: maxY - minY };
}

function downloadBlob(filename: string, type: string, content: Blob | string) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function escapeXml(value: string) {
  return value.replace(/[<>&"']/g, (char) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" }[char] || char));
}
