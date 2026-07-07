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
  useReactFlow,
} from "reactflow";
import "reactflow/dist/style.css";

import * as api from "@/lib/api";

type Severity = "all" | "critical" | "high" | "medium" | "low";
type GraphMode = "overview" | "investigation" | "indicator" | "full";

type ExplorerFilters = {
  severity: Severity;
  entityType: string;
  relationshipType: string;
  source: string;
  status: string;
  startDate: string;
  endDate: string;
};

type ExplorerNode = {
  id: string;
  kind: string;
  type: string;
  label: string;
  value: string;
  severity: string;
  confidence?: string;
  sources: string[];
  occurrences?: number;
  first_seen?: string;
  last_seen?: string;
  risk_score?: number;
  status?: string;
  url?: string;
  summary?: string;
  aggregate?: boolean;
  aggregateType?: string;
  count?: number;
  hiddenCount?: number;
};

type ExplorerEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  severity?: string;
  dashed?: boolean;
};

type NavigationPoint = {
  mode: GraphMode;
  selectedId: string;
  label: string;
};

const SEVERITIES: Severity[] = ["all", "critical", "high", "medium", "low"];
const MODES: Array<{ id: GraphMode; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "investigation", label: "Investigation" },
  { id: "indicator", label: "Indicator" },
  { id: "full", label: "Full graph" },
];

const DEFAULT_CLUSTER_LIMIT = 18;
const DEFAULT_RELATED_LIMIT = 42;
const FULL_GRAPH_LIMIT = 320;
const NODE_WIDTH = 236;
const NODE_HEIGHT = 88;

export default function SOCIndicatorsGraphPage() {
  return (
    <ReactFlowProvider>
      <SOCIndicatorsGraphWorkspace />
    </ReactFlowProvider>
  );
}

function SOCIndicatorsGraphWorkspace() {
  const flow = useReactFlow();
  const [query, setQuery] = React.useState("");
  const [filters, setFilters] = React.useState<ExplorerFilters>({
    severity: "all",
    entityType: "all",
    relationshipType: "all",
    source: "all",
    status: "all",
    startDate: "",
    endDate: "",
  });
  const [mode, setMode] = React.useState<GraphMode>("overview");
  const [graph, setGraph] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(true);
  const [searching, setSearching] = React.useState(false);
  const [error, setError] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");
  const [searchMatchId, setSearchMatchId] = React.useState("");
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());
  const [clusterLimits, setClusterLimits] = React.useState<Record<string, number>>({});
  const [manualPositions, setManualPositions] = React.useState<Record<string, { x: number; y: number }>>({});
  const [showLabels, setShowLabels] = React.useState(true);
  const [zoom, setZoom] = React.useState(1);
  const [backStack, setBackStack] = React.useState<NavigationPoint[]>([]);
  const [forwardStack, setForwardStack] = React.useState<NavigationPoint[]>([]);
  const [copyStatus, setCopyStatus] = React.useState("");
  const latestExplorerNodesRef = React.useRef<Node[]>([]);
  const lastSearchFocusKeyRef = React.useRef("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.getSOCIndicatorGraph({ severity: filters.severity, limit: 650 });
      setGraph(data);
      const nodes = normalizeNodes(data?.nodes);
      setSelectedId((current) => {
        if (current && nodes.some((node) => node.id === current)) return current;
        return pickInitialSelection(nodes);
      });
    } catch (err: any) {
      setError(err?.message || "Could not load SOC indicator graph.");
    } finally {
      setLoading(false);
    }
  }, [filters.severity]);

  React.useEffect(() => {
    const timer = window.setTimeout(load, 220);
    return () => window.clearTimeout(timer);
  }, [load]);

  const normalized = React.useMemo(() => ({
    nodes: normalizeNodes(graph?.nodes),
    edges: normalizeEdges(graph?.edges),
  }), [graph]);

  const options = React.useMemo(() => buildFilterOptions(normalized.nodes, normalized.edges), [normalized.edges, normalized.nodes]);
  const filtered = React.useMemo(
    () => applyFilters(normalized.nodes, normalized.edges, filters),
    [filters, normalized.edges, normalized.nodes],
  );
  React.useEffect(() => {
    const term = query.trim();
    if (!term) {
      setSearchMatchId("");
      lastSearchFocusKeyRef.current = "";
      return;
    }
    if (term.length < 3) {
      setSearchMatchId("");
      setSelectedId("");
      return;
    }
    const match = findNodeByQuery(filtered.nodes, term);
    setSearchMatchId(match?.id || "");
    if (!match) {
      setSelectedId("");
      return;
    }
    setMode("indicator");
    setSelectedId(match.id);
  }, [filtered.nodes, query]);

  React.useEffect(() => {
    const term = query.trim();
    if (term.length < 3) return;
    const timer = window.setTimeout(async () => {
      setSearching(true);
      try {
        const data = await api.getSOCIndicatorGraph({ search: term, severity: filters.severity, limit: 650 });
        setGraph(data);
        const nodes = normalizeNodes(data?.nodes);
        const match = findNodeByQuery(nodes, term);
        setSearchMatchId(match?.id || "");
        setSelectedId(match?.id || "");
        if (match) setMode("indicator");
      } catch (err: any) {
        setError(err?.message || "Could not search SOC indicator graph.");
      } finally {
        setSearching(false);
      }
    }, 360);
    return () => window.clearTimeout(timer);
  }, [filters.severity, query]);
  const selected = React.useMemo(
    () => filtered.nodes.find((node) => node.id === selectedId) || normalized.nodes.find((node) => node.id === selectedId) || null,
    [filtered.nodes, normalized.nodes, selectedId],
  );
  const selectedIdForMode = React.useMemo(
    () => searchMatchId || chooseModeCenter(mode, selected, filtered.nodes, query.trim().length >= 3 ? query : ""),
    [filtered.nodes, mode, query, searchMatchId, selected],
  );
  const selectedForMode = React.useMemo(
    () => filtered.nodes.find((node) => node.id === selectedIdForMode) || selected,
    [filtered.nodes, selected, selectedIdForMode],
  );
  const graphQuery = query.trim().length >= 3 ? query : "";
  const currentNavigation = React.useMemo(
    () => makeNavigationPoint(mode, selectedIdForMode, selectedForMode),
    [mode, selectedForMode, selectedIdForMode],
  );

  const explorer = React.useMemo(
    () => buildExplorerGraph({
      mode,
      nodes: filtered.nodes,
      edges: filtered.edges,
      selectedId: selectedIdForMode,
      query: graphQuery,
      expandedIds,
      clusterLimits,
      manualPositions,
      showLabels,
      zoom,
    }),
    [clusterLimits, expandedIds, filtered.edges, filtered.nodes, graphQuery, manualPositions, mode, selectedIdForMode, showLabels, zoom],
  );

  React.useEffect(() => {
    if (query.trim()) return;
    window.setTimeout(() => flow.fitView({ padding: 0.18, duration: 300, maxZoom: mode === "overview" ? 1 : 0.98 }), 90);
  }, [flow, explorer.layoutKey, mode, query]);

  React.useEffect(() => {
    latestExplorerNodesRef.current = explorer.nodes;
  }, [explorer.nodes]);

  React.useEffect(() => {
    const term = query.trim().toLowerCase();
    if (!term || term.length < 3) {
      lastSearchFocusKeyRef.current = "";
      return;
    }
    const focusKey = `${term}:${selectedIdForMode}`;
    if (lastSearchFocusKeyRef.current === focusKey) return;
    const match = latestExplorerNodesRef.current.find((node) => String(node.id) === selectedIdForMode);
    if (!match) return;
    lastSearchFocusKeyRef.current = focusKey;
    window.setTimeout(() => flow.setCenter(match.position.x + NODE_WIDTH / 2, match.position.y + NODE_HEIGHT / 2, { zoom: 1.08, duration: 0 }), 40);
  }, [flow, query, selectedIdForMode]);

  function updateFilter<K extends keyof ExplorerFilters>(key: K, value: ExplorerFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function reset() {
    setQuery("");
    setFilters({ severity: "all", entityType: "all", relationshipType: "all", source: "all", status: "all", startDate: "", endDate: "" });
    setMode("overview");
    setExpandedIds(new Set());
    setClusterLimits({});
    setManualPositions({});
    setSelectedId("");
    setSearchMatchId("");
    setBackStack([]);
    setForwardStack([]);
  }

  function applyNavigation(point: NavigationPoint) {
    setMode(point.mode);
    setSelectedId(point.selectedId);
    setExpandedIds(new Set());
    if (point.mode === "overview") setQuery("");
  }

  function rememberCurrent() {
    setBackStack((current) => {
      const last = current[current.length - 1];
      if (last && last.mode === currentNavigation.mode && last.selectedId === currentNavigation.selectedId) return current;
      return [...current, currentNavigation].slice(-30);
    });
    setForwardStack([]);
  }

  function navigateTo(point: Partial<NavigationPoint>) {
    rememberCurrent();
    applyNavigation({
      mode: point.mode || mode,
      selectedId: point.selectedId ?? selectedIdForMode,
      label: point.label || selectedForMode?.label || typeLabel(point.mode || mode),
    });
  }

  function goBack() {
    setBackStack((current) => {
      const previous = current[current.length - 1];
      if (!previous) return current;
      setForwardStack((future) => [currentNavigation, ...future].slice(0, 30));
      applyNavigation(previous);
      return current.slice(0, -1);
    });
  }

  function goForward() {
    setForwardStack((current) => {
      const next = current[0];
      if (!next) return current;
      setBackStack((past) => [...past, currentNavigation].slice(-30));
      applyNavigation(next);
      return current.slice(1);
    });
  }

  function goOverview() {
    rememberCurrent();
    setMode("overview");
    setSelectedId("");
    setQuery("");
    setExpandedIds(new Set());
  }

  function focusNode(id: string, nextMode?: GraphMode) {
    rememberCurrent();
    setSelectedId(id);
    if (nextMode) setMode(nextMode);
    setExpandedIds(new Set());
    const node = explorer.nodes.find((item) => item.id === id);
    if (node) flow.setCenter(node.position.x + NODE_WIDTH / 2, node.position.y + NODE_HEIGHT / 2, { zoom: 1.02, duration: 260 });
  }

  function expandNode(id: string) {
    setExpandedIds((current) => new Set([...Array.from(current), id]));
  }

  function collapseNode(id: string) {
    setExpandedIds((current) => {
      const next = new Set(current);
      next.delete(id);
      return next;
    });
  }

  function showMore(clusterId: string) {
    setClusterLimits((current) => ({ ...current, [clusterId]: (current[clusterId] || DEFAULT_CLUSTER_LIMIT) + DEFAULT_CLUSTER_LIMIT }));
    setExpandedIds((current) => new Set([...Array.from(current), clusterId]));
  }

  function openRelatedEntity(node: ExplorerNode | null | undefined) {
    const url = openableNodeUrl(node);
    if (!url) return;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  async function copyValue(value: string) {
    const text = String(value || "");
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        fallbackCopy(text);
      }
      setCopyStatus("Copied");
    } catch {
      try {
        fallbackCopy(text);
        setCopyStatus("Copied");
      } catch {
        setCopyStatus("Copy failed");
      }
    }
    window.setTimeout(() => setCopyStatus(""), 1600);
  }

  return (
    <main style={pageStyle}>
      <section style={headerStyle}>
        <div>
          <h1 style={titleStyle}>SOC Indicators Graph</h1>
          <p style={subtitleStyle}>
            OpenCTI-style relationship explorer for indicators, assistant cases, investigations, and co-observed platform entities.
          </p>
        </div>
        <div style={toolbarStyle}>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicator, case, user, IP, domain..." style={searchStyle} />
          <button type="button" onClick={reset} style={buttonStyle}>Reset</button>
        </div>
      </section>

      <section style={summaryGridStyle}>
        <Metric label="Indicators" value={graph?.summary?.indicator_nodes ?? 0} tone="info" />
        <Metric label="Assistant Cases" value={graph?.summary?.assistant_cases ?? 0} tone="success" />
        <Metric label="Investigations" value={graph?.summary?.investigation_cases ?? 0} tone="warning" />
        <Metric label="Relations" value={graph?.summary?.edges ?? 0} tone="danger" />
      </section>

      <section style={controlSurfaceStyle}>
        <div style={navigationBarStyle}>
          <button type="button" onClick={goBack} disabled={!backStack.length} style={!backStack.length ? disabledNavButtonStyle : navButtonStyle}>Back</button>
          <button type="button" onClick={goForward} disabled={!forwardStack.length} style={!forwardStack.length ? disabledNavButtonStyle : navButtonStyle}>Forward</button>
          <button type="button" onClick={goOverview} style={navButtonStyle}>Overview</button>
          <div style={breadcrumbStyle}>
            <span>SOC Graph</span>
            <strong>{typeLabel(mode)}</strong>
            {selectedForMode ? <em>{truncate(selectedForMode.label || selectedForMode.value, 54)}</em> : null}
          </div>
          <div style={hintStyle}>{modeHint(mode)}</div>
        </div>
        <div style={modeTabsStyle}>
          {MODES.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                if (item.id === "overview") goOverview();
                else navigateTo({ mode: item.id, selectedId: selectedIdForMode, label: item.label });
              }}
              style={mode === item.id ? activeTabStyle : tabStyle}
            >
              {item.label}
            </button>
          ))}
        </div>
        <div style={filterGridStyle}>
          <select value={filters.severity} onChange={(event) => updateFilter("severity", event.target.value as Severity)} style={selectStyle}>
            {SEVERITIES.map((item) => <option key={item} value={item}>{item === "all" ? "All severities" : item}</option>)}
          </select>
          <select value={filters.entityType} onChange={(event) => updateFilter("entityType", event.target.value)} style={selectStyle}>
            <option value="all">All entity types</option>
            {options.entityTypes.map((item) => <option key={item} value={item}>{typeLabel(item)}</option>)}
          </select>
          <select value={filters.relationshipType} onChange={(event) => updateFilter("relationshipType", event.target.value)} style={selectStyle}>
            <option value="all">All relationships</option>
            {options.relationshipTypes.map((item) => <option key={item} value={item}>{relationshipLabel(item)}</option>)}
          </select>
          <select value={filters.source} onChange={(event) => updateFilter("source", event.target.value)} style={selectStyle}>
            <option value="all">All sources</option>
            {options.sources.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select value={filters.status} onChange={(event) => updateFilter("status", event.target.value)} style={selectStyle}>
            <option value="all">All statuses</option>
            {options.statuses.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <input type="date" value={filters.startDate} onChange={(event) => updateFilter("startDate", event.target.value)} style={searchStyle} />
          <input type="date" value={filters.endDate} onChange={(event) => updateFilter("endDate", event.target.value)} style={searchStyle} />
        </div>
      </section>

      <section style={workspaceStyle}>
        <div style={graphPanelStyle}>
          <div style={graphControlStyle}>
            <button type="button" onClick={() => flow.zoomIn({ duration: 160 })} style={floatingControlButtonStyle}>+</button>
            <button type="button" onClick={() => flow.zoomOut({ duration: 160 })} style={floatingControlButtonStyle}>-</button>
            <button type="button" onClick={() => flow.fitView({ padding: 0.18, duration: 240 })} style={floatingControlButtonStyle}>Fit</button>
            <button type="button" onClick={() => setShowLabels((value) => !value)} style={showLabels ? { ...floatingControlButtonStyle, ...activeControlButtonStyle } : floatingControlButtonStyle}>Labels</button>
            <span>{searching ? "Searching..." : `${explorer.visibleCount} visible of ${filtered.nodes.length}`}</span>
          </div>
          {loading ? (
            <Empty label="Loading indicator graph..." />
          ) : error ? (
            <Empty label={error} danger />
          ) : explorer.nodes.length ? (
            <ReactFlow
              nodes={explorer.nodes}
              edges={explorer.edges}
              fitView
              fitViewOptions={{ padding: 0.18, maxZoom: mode === "overview" ? 1 : 0.98 }}
              minZoom={0.08}
              maxZoom={1.8}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
              onMove={(_, viewport) => setZoom(viewport.zoom)}
              onNodeClick={(_, node) => {
                const raw = node.data?.raw as ExplorerNode | undefined;
                if (raw?.aggregate && raw.aggregateType) {
                  setSelectedId(raw.id);
                  setExpandedIds((current) => {
                    const next = new Set(current);
                    if (next.has(raw.id)) next.delete(raw.id);
                    else next.add(raw.id);
                    return next;
                  });
                } else {
                  focusNode(String(node.id), raw?.kind === "indicator" ? "indicator" : raw?.kind === "assistant" || raw?.kind === "investigation" ? "investigation" : undefined);
                }
              }}
              onNodeDoubleClick={(_, node) => {
                const raw = node.data?.raw as ExplorerNode | undefined;
                openRelatedEntity(raw);
              }}
              onNodeDragStop={(_, node) => setManualPositions((current) => ({ ...current, [String(node.id)]: node.position }))}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="rgba(148,163,184,0.16)" gap={28} />
              <MiniMap nodeStrokeWidth={3} zoomable pannable nodeColor={(node) => node.data?.color || severityColor(node.data?.raw?.severity)} />
              <Controls showInteractive={false} />
            </ReactFlow>
          ) : (
            <Empty label="No SOC indicators match the current graph mode and filters." />
          )}
        </div>
        <aside style={inspectorStyle}>
          <ExplorerInspector
            node={selectedForMode}
            allNodes={filtered.nodes}
            allEdges={filtered.edges}
            mode={mode}
            copyStatus={copyStatus}
            onCopy={copyValue}
            onExpand={expandNode}
            onCollapse={collapseNode}
            onFocus={focusNode}
            onOpenCase={openRelatedEntity}
          />
          <Legend nodes={filtered.nodes} edges={filtered.edges} />
          {explorer.moreClusters.length ? (
            <div style={inspectorCardStyle}>
              <h3 style={panelTitleStyle}>Show More Related Entities</h3>
              <div style={actionGridStyle}>
                {explorer.moreClusters.map((cluster) => (
                  <button key={cluster.id} type="button" onClick={() => showMore(cluster.id)} style={actionButtonStyle}>
                    {cluster.label} +{cluster.hidden}
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </aside>
      </section>
    </main>
  );
}

function buildExplorerGraph({
  mode,
  nodes,
  edges,
  selectedId,
  query,
  expandedIds,
  clusterLimits,
  manualPositions,
  showLabels,
  zoom,
}: {
  mode: GraphMode;
  nodes: ExplorerNode[];
  edges: ExplorerEdge[];
  selectedId: string;
  query: string;
  expandedIds: Set<string>;
  clusterLimits: Record<string, number>;
  manualPositions: Record<string, { x: number; y: number }>;
  showLabels: boolean;
  zoom: number;
}) {
  const adjacency = buildAdjacency(edges);
  const center = nodes.find((node) => node.id === selectedId) || nodes[0];
  if (!center) return { nodes: [], edges: [], visibleCount: 0, moreClusters: [], layoutKey: "empty" };

  if (mode === "overview") {
    return buildOverviewGraph(nodes, edges, expandedIds, clusterLimits, manualPositions, showLabels, zoom);
  }

  const visibleIds = new Set<string>([center.id]);
  const firstHop = Array.from(adjacency.get(center.id) || []);
  const grouped = groupNodeIds(firstHop, nodes);
  const moreClusters: Array<{ id: string; label: string; hidden: number }> = [];

  // Expansion logic: start with first-hop entities grouped by type. Only expanded nodes reveal their next hop.
  Object.entries(grouped).forEach(([group, ids]) => {
    const clusterId = `${mode}:${center.id}:${group}`;
    const limit = mode === "full" ? FULL_GRAPH_LIMIT : clusterLimits[clusterId] || DEFAULT_CLUSTER_LIMIT;
    ids.slice(0, limit).forEach((id) => visibleIds.add(id));
    if (ids.length > limit) moreClusters.push({ id: clusterId, label: typeLabel(group), hidden: ids.length - limit });
  });

  expandedIds.forEach((id) => {
    if (!visibleIds.has(id)) return;
    visibleIds.add(id);
    const directNeighbors = Array.from(adjacency.get(id) || []).slice(0, DEFAULT_RELATED_LIMIT);
    directNeighbors.forEach((neighbor) => visibleIds.add(neighbor));
    // Expand means "show the next hop" for the active focus. First-hop is already visible,
    // so this adds bounded second-hop context without allowing unrelated islands.
    if (id === center.id || id === selectedId) {
      directNeighbors.forEach((neighbor) => {
        Array.from(adjacency.get(neighbor) || []).slice(0, 12).forEach((secondHop) => visibleIds.add(secondHop));
      });
    }
  });

  if (mode === "full") {
    nodes.slice(0, FULL_GRAPH_LIMIT).forEach((node) => visibleIds.add(node.id));
  }

  const queryMatch = query.trim() ? findNodeByQuery(nodes, query) : null;
  if (queryMatch) {
    visibleIds.add(queryMatch.id);
    const path = shortestPath(center.id, queryMatch.id, adjacency);
    path.forEach((id) => visibleIds.add(id));
  }

  const visibleNodes = nodes.filter((node) => visibleIds.has(node.id));
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
  const visibleEdges = edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target));
  const pathIds = queryMatch ? shortestPath(center.id, queryMatch.id, adjacency) : new Set<string>([center.id]);
  const positions = radialPositions(visibleNodes, center.id);

  const flowNodes = visibleNodes.map((node): Node => {
    const active = node.id === center.id || node.id === selectedId;
    const related = active || pathIds.has(node.id) || Boolean(adjacency.get(selectedId)?.has(node.id));
    return makeFlowNode(node, manualPositions[node.id] || positions[node.id], {
      central: node.id === center.id,
      active,
      dimmed: Boolean(selectedId && !related && mode !== "full"),
      highlighted: pathIds.has(node.id) || (query.trim() ? nodeMatchesQuery(node, query) : false),
      showLabel: showLabels && zoom > 0.38,
    });
  });

  const flowEdges = visibleEdges.map((edge) => {
    const active = edge.source === selectedId || edge.target === selectedId || (pathIds.has(edge.source) && pathIds.has(edge.target));
    return makeFlowEdge(edge, active, active);
  });

  return {
    nodes: flowNodes,
    edges: flowEdges,
    visibleCount: flowNodes.length,
    moreClusters,
    layoutKey: `${mode}:${center.id}:${flowNodes.map((node) => node.id).join("|")}:${flowEdges.length}:${showLabels}`,
  };
}

function buildOverviewGraph(
  nodes: ExplorerNode[],
  edges: ExplorerEdge[],
  expandedIds: Set<string>,
  clusterLimits: Record<string, number>,
  manualPositions: Record<string, { x: number; y: number }>,
  showLabels: boolean,
  zoom: number,
) {
  const aggregateNodes = buildOverviewNodes(nodes, edges);
  const center = aggregateNodes[0];
  const aggregateById = new Map(aggregateNodes.map((node) => [node.id, node]));
  const expandedChildren: ExplorerNode[] = [];
  const childEdges: Edge[] = [];
  const moreClusters: Array<{ id: string; label: string; hidden: number }> = [];
  const grouped = new Map<string, ExplorerNode[]>();
  nodes.forEach((node) => {
    const clusterType = overviewCluster(node);
    const clusterId = `overview:${clusterType}`;
    if (!grouped.has(clusterId)) grouped.set(clusterId, []);
    grouped.get(clusterId)?.push(node);
  });
  grouped.forEach((items, clusterId) => {
    const aggregate = aggregateById.get(clusterId);
    if (!aggregate) return;
    const limit = clusterLimits[clusterId] || DEFAULT_CLUSTER_LIMIT;
    const hidden = Math.max(0, items.length - limit);
    if (hidden > 0) moreClusters.push({ id: clusterId, label: aggregate.label, hidden });
    if (!expandedIds.has(clusterId)) return;
    items.slice(0, limit).forEach((item) => {
      expandedChildren.push(item);
      childEdges.push({
        id: `overview-child:${clusterId}->${item.id}`,
        source: clusterId,
        target: item.id,
        type: "smoothstep",
        markerEnd: { type: MarkerType.ArrowClosed, color: entityColor(item.type, item.kind) },
        style: { stroke: entityColor(item.type, item.kind), strokeWidth: 1.35, opacity: 0.45 },
      });
    });
  });
  const visibleNodes = [...aggregateNodes, ...expandedChildren];
  const positions = overviewPositions(aggregateNodes, expandedChildren, center.id, expandedIds);
  const flowNodes = visibleNodes.map((node) => makeFlowNode(node, manualPositions[node.id] || positions[node.id], {
    central: node.id === center.id,
    active: expandedIds.has(node.id),
    dimmed: false,
    highlighted: expandedIds.has(node.id),
    showLabel: showLabels && zoom > 0.25,
  }));
  const flowEdges = aggregateNodes.slice(1).map((node): Edge => ({
    id: `overview:${center.id}->${node.id}`,
    source: center.id,
    target: node.id,
    type: "smoothstep",
    markerEnd: { type: MarkerType.ArrowClosed, color: entityColor(node.type, node.kind) },
    style: { stroke: entityColor(node.type, node.kind), strokeWidth: 2, opacity: 0.58 },
  }));
  return {
    nodes: flowNodes,
    edges: [...flowEdges, ...childEdges],
    visibleCount: flowNodes.length,
    moreClusters,
    layoutKey: `overview:${nodes.length}:${edges.length}:${Array.from(expandedIds).join(",")}:${JSON.stringify(clusterLimits)}:${showLabels}`,
  };
}

function overviewPositions(
  aggregateNodes: ExplorerNode[],
  expandedChildren: ExplorerNode[],
  centerId: string,
  expandedIds: Set<string>,
): Record<string, { x: number; y: number }> {
  const positions = radialPositions(aggregateNodes, centerId, 330);
  const aggregatesByType = new Map(aggregateNodes.map((node) => [node.aggregateType || node.type, node]));
  const childrenByType = new Map<string, ExplorerNode[]>();
  expandedChildren.forEach((node) => {
    const type = overviewCluster(node);
    if (!childrenByType.has(type)) childrenByType.set(type, []);
    childrenByType.get(type)?.push(node);
  });
  childrenByType.forEach((children, type) => {
    const parent = aggregatesByType.get(type);
    const parentPos = parent ? positions[parent.id] : undefined;
    if (!parentPos) return;
    const columns = Math.max(2, Math.ceil(Math.sqrt(children.length)));
    const parentIsExpanded = expandedIds.has(parent?.id || "");
    const startX = parentPos.x + NODE_WIDTH + 95;
    const startY = parentPos.y + (parentIsExpanded ? 18 : 0) - Math.min(220, Math.floor(children.length / columns) * 48);
    children.forEach((child, index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      positions[child.id] = {
        x: Math.round(startX + col * 285),
        y: Math.round(startY + row * 124),
      };
    });
  });
  return positions;
}

function buildOverviewNodes(nodes: ExplorerNode[], edges: ExplorerEdge[]): ExplorerNode[] {
  const center: ExplorerNode = {
    id: "overview:platform",
    kind: "overview",
    type: "platform",
    label: "SOC Knowledge Graph",
    value: `${nodes.length} entities / ${edges.length} relationships`,
    severity: maxSeverity(nodes.map((node) => node.severity)),
    sources: ["Platform"],
    aggregate: true,
    count: nodes.length,
  };
  const clusters = new Map<string, ExplorerNode[]>();
  nodes.forEach((node) => {
    const key = overviewCluster(node);
    if (!clusters.has(key)) clusters.set(key, []);
    clusters.get(key)?.push(node);
  });
  return [
    center,
    ...Array.from(clusters.entries()).map(([key, items]) => ({
      id: `overview:${key}`,
      kind: "cluster",
      type: key,
      label: typeLabel(key),
      value: `${items.length} entities`,
      severity: maxSeverity(items.map((item) => item.severity)),
      sources: unique(items.flatMap((item) => item.sources)).slice(0, 4),
      aggregate: true,
      aggregateType: key,
      count: items.length,
      hiddenCount: Math.max(0, items.length - DEFAULT_CLUSTER_LIMIT),
      summary: `Aggregated ${typeLabel(key)} entities. Select a specific case or search an indicator to explore relationships progressively.`,
    })),
  ];
}

function makeFlowNode(node: ExplorerNode, position: { x: number; y: number }, state: { central: boolean; active: boolean; dimmed: boolean; highlighted: boolean; showLabel: boolean }): Node {
  const color = entityColor(node.type, node.kind);
  const severity = severityColor(node.severity);
  const short = state.showLabel ? truncate(node.label || node.value, state.central ? 44 : 32) : typeLabel(node.type);
  const subtitle = state.showLabel ? truncate(node.value || node.label, state.central ? 52 : 34) : "";
  return {
    id: node.id,
    type: "default",
    position,
    data: {
      raw: node,
      color,
      label: (
        <div title={node.value || node.label} style={{ display: "grid", gap: 7 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
            <span style={{ ...nodeIconStyle, color, borderColor: `${color}77` }}>{nodeIcon(node)}</span>
            <div style={{ minWidth: 0 }}>
              <div style={nodeTitleStyle}>{short}</div>
              {subtitle ? <div style={nodeSubtitleStyle}>{subtitle}</div> : null}
            </div>
          </div>
          <span style={{ ...severityPillStyle, color: severity, borderColor: `${severity}66`, background: `${severity}18` }}>
            {node.aggregate ? `${node.count || 0}` : String(node.severity || "medium").toUpperCase()}
          </span>
        </div>
      ),
    },
    style: {
      width: state.central ? 290 : node.aggregate ? 250 : 230,
      minHeight: state.central ? 104 : node.aggregate ? 92 : 78,
      borderRadius: 10,
      border: state.active || state.central ? "2px solid #67e8f9" : `1px solid ${severity}`,
      borderLeft: `5px solid ${color}`,
      background: node.aggregate ? "rgba(15,23,42,0.98)" : "rgba(10,18,34,0.96)",
      color: "var(--text-primary)",
      opacity: state.dimmed ? 0.25 : 1,
      boxShadow: state.highlighted || state.central ? "0 0 0 2px rgba(103,232,249,0.55), 0 22px 46px rgba(103,232,249,0.16)" : `0 0 0 4px ${severity}16, 0 18px 40px rgba(0,0,0,0.24)`,
    },
    zIndex: state.central ? 40 : state.active || state.highlighted ? 35 : node.aggregate ? 24 : 8,
  };
}

function makeFlowEdge(edge: ExplorerEdge, active: boolean, showLabel: boolean): Edge {
  const color = severityColor(edge.severity);
  return {
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: "smoothstep",
    label: showLabel ? relationshipLabel(edge.label) : undefined,
    markerEnd: { type: MarkerType.ArrowClosed, color },
    style: {
      stroke: color,
      strokeWidth: active ? 2.8 : edge.dashed ? 1 : 1.35,
      strokeDasharray: edge.dashed ? "7 7" : undefined,
      opacity: active ? 0.95 : 0.28,
    },
    labelStyle: { fill: "var(--text-secondary)", fontSize: 10, fontWeight: 800 },
    labelBgStyle: { fill: "rgba(8,15,29,0.94)", fillOpacity: 0.94 },
  };
}

function radialPositions(nodes: ExplorerNode[], centerId: string, radiusBase = 360): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};
  const center = nodes.find((node) => node.id === centerId) || nodes[0];
  if (!center) return positions;
  positions[center.id] = { x: 0, y: 0 };
  const grouped = new Map<string, ExplorerNode[]>();
  nodes.filter((node) => node.id !== center.id).forEach((node) => {
    const key = node.aggregate ? node.type : overviewCluster(node);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)?.push(node);
  });
  const groups = Array.from(grouped.entries());
  groups.forEach(([_, items], groupIndex) => {
    const angle = (Math.PI * 2 * groupIndex) / Math.max(groups.length, 1) - Math.PI / 2;
    const clusterRadius = radiusBase + Math.min(260, items.length * 9);
    const cx = Math.cos(angle) * clusterRadius;
    const cy = Math.sin(angle) * clusterRadius;
    const columns = Math.max(1, Math.ceil(Math.sqrt(items.length)));
    items.forEach((node, index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      positions[node.id] = {
        x: Math.round(cx + (col - (columns - 1) / 2) * 285),
        y: Math.round(cy + (row - Math.floor(items.length / columns) / 2) * 120),
      };
    });
  });
  return positions;
}

function ExplorerInspector({
  node,
  allNodes,
  allEdges,
  mode,
  copyStatus,
  onCopy,
  onExpand,
  onCollapse,
  onFocus,
  onOpenCase,
}: {
  node: ExplorerNode | null;
  allNodes: ExplorerNode[];
  allEdges: ExplorerEdge[];
  mode: GraphMode;
  copyStatus: string;
  onCopy: (value: string) => void;
  onExpand: (id: string) => void;
  onCollapse: (id: string) => void;
  onFocus: (id: string, mode?: GraphMode) => void;
  onOpenCase: (node: ExplorerNode) => void;
}) {
  if (!node) {
    return (
      <aside style={inspectorStyle}>
        <Empty label="Select an entity to inspect linked cases, relationships, and evidence." />
      </aside>
    );
  }
  const byId = new Map(allNodes.map((item) => [item.id, item]));
  const relatedEdges = allEdges.filter((edge) => edge.source === node.id || edge.target === node.id);
  const linked = relatedEdges.map((edge) => byId.get(edge.source === node.id ? edge.target : edge.source)).filter(Boolean) as ExplorerNode[];
  const linkedCases = linked.filter((item) => item.kind === "assistant");
  const linkedInvestigations = linked.filter((item) => item.kind === "investigation");
  const relatedIndicators = linked.filter((item) => item.kind === "indicator");
  const color = severityColor(node.severity);
  const nodeUrl = openableNodeUrl(node);
  return (
    <div style={inspectorCardStyle}>
      <div style={{ ...smallPillStyle, color, borderColor: `${color}66`, background: `${color}16` }}>
        {node.aggregate ? "CLUSTER" : String(node.kind || "entity").toUpperCase()}
      </div>
      <h2 style={inspectorTitleStyle}>{node.label || node.value}</h2>
      <div style={inspectorValueStyle}>{node.value || node.label}</div>
      <div style={inspectorGridStyle}>
        <InspectorStat label="Mode" value={mode} />
        <InspectorStat label="Type" value={node.type || node.kind} />
        <InspectorStat label="Severity" value={node.severity || "medium"} />
        <InspectorStat label="Risk" value={node.risk_score ?? "-"} />
      </div>
      <Detail label="Sources" value={node.sources?.join(", ") || node.kind} />
      <Detail label="First seen" value={formatDate(node.first_seen)} />
      <Detail label="Last seen" value={formatDate(node.last_seen)} />
      <Detail label="Status" value={node.status || "-"} />
      <p style={paragraphStyle}>{node.summary || "No summary is available for this node."}</p>

      <RelationshipSection title="Linked cases" nodes={linkedCases} onSelect={(id) => onFocus(id, "investigation")} onOpen={onOpenCase} />
      <RelationshipSection title="Linked investigations" nodes={linkedInvestigations} onSelect={(id) => onFocus(id, "investigation")} onOpen={onOpenCase} />
      <RelationshipSection title="Related indicators" nodes={relatedIndicators} onSelect={(id) => onFocus(id, "indicator")} />

      <div style={relationshipEvidenceStyle}>
        <strong>Relationship evidence</strong>
        {relatedEdges.slice(0, 8).map((edge) => <code key={edge.id}>{relationshipLabel(edge.label)}</code>)}
        {!relatedEdges.length ? <span>No direct relationships in the current filtered graph.</span> : null}
      </div>

      <div style={actionGridStyle}>
        <button type="button" onClick={() => onCopy(node.value || node.label)} style={actionButtonStyle}>Copy value</button>
        <button type="button" onClick={() => onExpand(node.id)} style={actionButtonStyle}>Expand node</button>
        <button type="button" onClick={() => onCollapse(node.id)} style={actionButtonStyle}>Collapse node</button>
        <button type="button" onClick={() => onFocus(node.id, node.kind === "indicator" ? "indicator" : "investigation")} style={actionButtonStyle}>Focus graph</button>
        {nodeUrl ? <button type="button" onClick={() => onOpenCase(node)} style={actionButtonStyle}>{node.kind === "investigation" ? "Open investigation" : "Open case"}</button> : null}
      </div>
      {copyStatus ? <div style={copyStatusStyle}>{copyStatus}</div> : null}
    </div>
  );
}

function RelationshipSection({
  title,
  nodes,
  onSelect,
  onOpen,
}: {
  title: string;
  nodes: ExplorerNode[];
  onSelect: (id: string) => void;
  onOpen?: (node: ExplorerNode) => void;
}) {
  if (!nodes.length) return null;
  return (
    <div style={relationshipListStyle}>
      <strong>{title}</strong>
      {nodes.slice(0, 8).map((node) => (
        <div key={node.id} style={relationshipRowStyle}>
          <button type="button" onClick={() => onSelect(node.id)} style={relationshipButtonStyle} title="Focus this entity in the graph">
            {truncate(node.label || node.value, 36)}
          </button>
          {openableNodeUrl(node) && onOpen ? (
            <button type="button" onClick={() => onOpen(node)} style={relationshipOpenButtonStyle} title="Open related case or investigation">
              Open
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function Legend({ nodes, edges }: { nodes: ExplorerNode[]; edges: ExplorerEdge[] }) {
  const types = unique(nodes.map((node) => node.type)).slice(0, 12);
  const relationships = unique(edges.map((edge) => edge.label)).slice(0, 8);
  return (
    <div style={inspectorCardStyle}>
      <h3 style={panelTitleStyle}>Legend</h3>
      <div style={legendGridStyle}>
        {types.map((type) => <span key={type}><i style={{ background: entityColor(type, type) }}>{nodeIcon({ type })}</i>{typeLabel(type)}</span>)}
      </div>
      <div style={relationshipEvidenceStyle}>
        <strong>Relationships</strong>
        {relationships.map((item) => <code key={item}>{relationshipLabel(item)}</code>)}
      </div>
    </div>
  );
}

function normalizeNodes(nodes: any): ExplorerNode[] {
  return (Array.isArray(nodes) ? nodes : []).map((node: any) => {
    const normalized: ExplorerNode = {
      id: String(node.id),
      kind: String(node.kind || "indicator"),
      type: String(node.type || node.kind || "indicator"),
      label: String(node.label || node.value || node.id),
      value: String(node.value || node.label || node.id),
      severity: String(node.severity || "medium").toLowerCase(),
      confidence: node.confidence,
      sources: Array.isArray(node.sources) ? node.sources.map(String) : node.sources ? [String(node.sources)] : [String(node.kind || "platform")],
      occurrences: Number(node.occurrences || 1),
      first_seen: node.first_seen,
      last_seen: node.last_seen,
      risk_score: node.risk_score,
      status: node.status || node.state,
      url: node.url ? String(node.url) : "",
      summary: node.summary,
    };
    normalized.url = normalized.url || defaultOpenUrl(normalized);
    return normalized;
  });
}

function openableNodeUrl(node: ExplorerNode | null | undefined) {
  if (!node || node.aggregate) return "";
  return node.url || defaultOpenUrl(node);
}

function defaultOpenUrl(node: Pick<ExplorerNode, "id" | "kind">) {
  const id = String(node.id || "");
  const [, rawId = id] = id.match(/^[^:]+:(.+)$/) || [];
  if (node.kind === "assistant") return `/assistant?session=${encodeURIComponent(rawId)}`;
  if (node.kind === "investigation") return `/investigations/${encodeURIComponent(rawId)}`;
  return "";
}

function normalizeEdges(edges: any): ExplorerEdge[] {
  return (Array.isArray(edges) ? edges : []).map((edge: any) => ({
    id: String(edge.id || `${edge.source}->${edge.target}:${edge.label}`),
    source: String(edge.source),
    target: String(edge.target),
    label: String(edge.label || "associated"),
    severity: String(edge.severity || "medium").toLowerCase(),
    dashed: Boolean(edge.dashed),
  }));
}

function applyFilters(nodes: ExplorerNode[], edges: ExplorerEdge[], filters: ExplorerFilters) {
  const start = filters.startDate ? new Date(filters.startDate).getTime() : null;
  const end = filters.endDate ? new Date(`${filters.endDate}T23:59:59`).getTime() : null;
  const keptNodes = nodes.filter((node) => {
    if (filters.severity !== "all" && node.severity !== filters.severity) return false;
    if (filters.entityType !== "all" && node.type !== filters.entityType && node.kind !== filters.entityType) return false;
    if (filters.source !== "all" && !node.sources.includes(filters.source)) return false;
    if (filters.status !== "all" && node.status !== filters.status) return false;
    const seen = node.last_seen || node.first_seen;
    if ((start || end) && seen) {
      const t = new Date(seen).getTime();
      if (start && t < start) return false;
      if (end && t > end) return false;
    }
    return true;
  });
  const ids = new Set(keptNodes.map((node) => node.id));
  const keptEdges = edges.filter((edge) => {
    if (!ids.has(edge.source) || !ids.has(edge.target)) return false;
    if (filters.relationshipType !== "all" && relationshipKey(edge.label) !== filters.relationshipType) return false;
    return true;
  });
  return { nodes: keptNodes, edges: keptEdges };
}

function buildFilterOptions(nodes: ExplorerNode[], edges: ExplorerEdge[]) {
  return {
    entityTypes: unique([...nodes.map((node) => node.kind), ...nodes.map((node) => node.type)]),
    relationshipTypes: unique(edges.map((edge) => relationshipKey(edge.label))),
    sources: unique(nodes.flatMap((node) => node.sources)),
    statuses: unique(nodes.map((node) => node.status || "").filter(Boolean)),
  };
}

function buildAdjacency(edges: ExplorerEdge[]) {
  const map = new Map<string, Set<string>>();
  edges.forEach((edge) => {
    if (!map.has(edge.source)) map.set(edge.source, new Set());
    if (!map.has(edge.target)) map.set(edge.target, new Set());
    map.get(edge.source)?.add(edge.target);
    map.get(edge.target)?.add(edge.source);
  });
  return map;
}

function groupNodeIds(ids: string[], nodes: ExplorerNode[]) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  return ids.reduce<Record<string, string[]>>((acc, id) => {
    const node = byId.get(id);
    if (!node) return acc;
    const key = overviewCluster(node);
    acc[key] = acc[key] || [];
    acc[key].push(id);
    return acc;
  }, {});
}

function shortestPath(start: string, end: string, adjacency: Map<string, Set<string>>) {
  if (!start || !end || start === end) return new Set([start, end].filter(Boolean));
  const queue = [start];
  const prev = new Map<string, string | null>([[start, null]]);
  while (queue.length) {
    const current = queue.shift()!;
    for (const next of Array.from(adjacency.get(current) || [])) {
      if (prev.has(next)) continue;
      prev.set(next, current);
      if (next === end) {
        const path = new Set<string>();
        let cursor: string | null = end;
        while (cursor) {
          path.add(cursor);
          cursor = prev.get(cursor) || null;
        }
        return path;
      }
      queue.push(next);
    }
  }
  return new Set([start, end]);
}

function chooseModeCenter(mode: GraphMode, selected: ExplorerNode | null, nodes: ExplorerNode[], query: string) {
  if (query.trim()) {
    return findNodeByQuery(nodes, query)?.id || "";
  }
  if (mode === "indicator") {
    if (selected?.kind === "indicator") return selected.id;
    return nodes.find((node) => node.kind === "indicator")?.id || selected?.id || "";
  }
  if (mode === "investigation") {
    if (selected && ["assistant", "investigation"].includes(selected.kind)) return selected.id;
    return nodes.find((node) => ["assistant", "investigation"].includes(node.kind))?.id || selected?.id || "";
  }
  if (mode === "full") return selected?.id || pickInitialSelection(nodes);
  return selected?.id || pickInitialSelection(nodes);
}

function pickInitialSelection(nodes: ExplorerNode[]) {
  return nodes.find((node) => node.kind === "assistant")?.id || nodes.find((node) => node.kind === "investigation")?.id || nodes[0]?.id || "";
}

function findNodeByQuery(nodes: ExplorerNode[], query: string) {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  return nodes
    .map((node, index) => ({ node, index, score: searchScore(node, q) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || a.index - b.index)[0]?.node || null;
}

function nodeMatchesQuery(node: ExplorerNode, query: string) {
  return searchScore(node, query) > 0;
}

function searchScore(node: ExplorerNode, query: string) {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const fields = [
    node.value,
    node.label,
    node.id,
    node.type,
    node.kind,
    ...(node.sources || []),
  ].map((value) => String(value || "").toLowerCase()).filter(Boolean);
  if (fields.some((field) => field === q)) return 1000;
  const normalizedQuery = normalizeSearchText(q);
  if (fields.some((field) => normalizeSearchText(field) === normalizedQuery)) return 940;
  const tokens = fields.flatMap((field) => field.split(/[^a-z0-9@._:-]+/).filter(Boolean));
  if (tokens.some((token) => token === q)) return 860;
  if (tokens.some((token) => normalizeSearchText(token) === normalizedQuery)) return 820;
  if (fields.some((field) => field.startsWith(q))) return 720;
  if (tokens.some((token) => token.startsWith(q))) return 640;
  if (fields.some((field) => field.includes(q))) return 420;
  if (fields.some((field) => normalizeSearchText(field).includes(normalizedQuery))) return 360;
  return 0;
}

function normalizeSearchText(value: string) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function overviewCluster(node: ExplorerNode) {
  if (node.kind === "assistant") return "assistant";
  if (node.kind === "investigation") return "investigation";
  const type = node.type.toLowerCase();
  if (["ip", "domain", "url", "email", "account", "host", "hash", "file", "user"].includes(type)) return type;
  return "indicator";
}

function relationshipKey(label: string) {
  return String(label || "associated").toLowerCase().replace(/\s+/g, "_");
}

function relationshipLabel(label: string) {
  return String(label || "associated").replace(/_/g, " ");
}

function maxSeverity(values: string[]) {
  const order = ["critical", "high", "medium", "low"];
  return order.find((item) => values.includes(item)) || "medium";
}

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function fallbackCopy(value: string) {
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!ok) throw new Error("Copy command failed");
}

function nodeIcon(node: any): string {
  const type = String(node.type || node.kind || "").toLowerCase();
  if (node.kind === "overview" || type === "platform") return "SOC";
  if (node.kind === "assistant" || type === "assistant") return "AI";
  if (node.kind === "investigation" || type === "investigation") return "CASE";
  if (type === "ip") return "IP";
  if (type === "email" || type === "account" || type === "user") return "@";
  if (type === "url") return "/";
  if (type === "domain") return "D";
  if (type === "host") return "H";
  if (type === "file") return "F";
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

function entityColor(type: string, kind: string): string {
  if (kind === "overview" || type === "platform") return "#67e8f9";
  if (kind === "assistant" || type === "assistant") return "#67e8f9";
  if (kind === "investigation" || type === "investigation") return "#a78bfa";
  if (type === "ip") return "#38bdf8";
  if (type === "domain") return "#22c55e";
  if (type === "url") return "#2dd4bf";
  if (type === "email" || type === "account" || type === "user") return "#facc15";
  if (type === "host") return "#f59e0b";
  if (type === "file" || type === "hash") return "#c084fc";
  return "#94a3b8";
}

function typeLabel(value: string) {
  const labels: Record<string, string> = {
    assistant: "Assistant Cases",
    investigation: "Investigations",
    ip: "IPs",
    domain: "Domains",
    url: "URLs",
    email: "Emails",
    account: "Users",
    host: "Hosts",
    hash: "Files / Hashes",
    file: "Files",
    indicator: "Indicators",
    platform: "Platform Overview",
  };
  return labels[value] || value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function makeNavigationPoint(mode: GraphMode, selectedId: string, node: ExplorerNode | null): NavigationPoint {
  return {
    mode,
    selectedId,
    label: node?.label || typeLabel(mode),
  };
}

function modeHint(mode: GraphMode) {
  if (mode === "overview") return "Click a cluster to expand it here. Use Show More for larger clusters.";
  if (mode === "investigation") return "The selected case is centered. Click an indicator to pivot, or Back to return.";
  if (mode === "indicator") return "The selected indicator is centered. Linked cases and co-observed entities appear around it.";
  return "Full graph is intentionally dense. Use filters, search, and Fit to keep it readable.";
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
  return <div style={{ ...emptyStyle, color: danger ? "var(--red)" : "var(--text-muted)" }}>{label}</div>;
}

const pageStyle: React.CSSProperties = { display: "grid", gap: 16, padding: "18px clamp(14px, 2vw, 28px) 28px", minHeight: "calc(100vh - 72px)" };
const headerStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(260px, 1fr) minmax(320px, 0.7fr)", gap: 18, alignItems: "end" };
const titleStyle: React.CSSProperties = { margin: 0, color: "var(--text-strong)", fontSize: 28, fontWeight: 900 };
const subtitleStyle: React.CSSProperties = { margin: "6px 0 0", color: "var(--text-secondary)", lineHeight: 1.55, fontSize: 13 };
const toolbarStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(180px, 1fr) 86px", gap: 10 };
const searchStyle: React.CSSProperties = { height: 38, border: "1px solid var(--border-dim)", borderRadius: 8, background: "rgba(2,6,23,0.52)", color: "var(--text-primary)", padding: "0 12px", minWidth: 0 };
const selectStyle: React.CSSProperties = { ...searchStyle, textTransform: "capitalize" };
const buttonStyle: React.CSSProperties = { height: 38, border: "1px solid rgba(102,168,255,0.32)", borderRadius: 8, background: "rgba(102,168,255,0.14)", color: "var(--text-primary)", fontWeight: 800, cursor: "pointer" };
const summaryGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 10 };
const metricStyle: React.CSSProperties = { minHeight: 78, border: "1px solid var(--border-dim)", borderRadius: 8, background: "rgba(15,23,42,0.42)", padding: 14, display: "grid", alignContent: "center", gap: 8 };
const controlSurfaceStyle: React.CSSProperties = { display: "grid", gap: 10, border: "1px solid var(--border-dim)", borderRadius: 8, padding: 10, background: "rgba(15,23,42,0.38)" };
const navigationBarStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(82px, max-content)) minmax(240px, 1fr) minmax(260px, 0.9fr)", gap: 8, alignItems: "center" };
const navButtonStyle: React.CSSProperties = { height: 34, border: "1px solid rgba(102,168,255,0.32)", borderRadius: 8, background: "rgba(102,168,255,0.14)", color: "var(--text-primary)", fontWeight: 900, cursor: "pointer" };
const disabledNavButtonStyle: React.CSSProperties = { ...navButtonStyle, opacity: 0.42, cursor: "not-allowed" };
const breadcrumbStyle: React.CSSProperties = { minHeight: 34, display: "flex", alignItems: "center", gap: 8, minWidth: 0, border: "1px solid var(--border-dim)", borderRadius: 8, padding: "0 10px", color: "var(--text-secondary)", background: "rgba(2,6,23,0.26)", fontSize: 12 };
const hintStyle: React.CSSProperties = { minHeight: 34, display: "flex", alignItems: "center", border: "1px solid rgba(103,232,249,0.18)", borderRadius: 8, padding: "0 10px", color: "#cffafe", background: "rgba(103,232,249,0.07)", fontSize: 12, lineHeight: 1.35 };
const modeTabsStyle: React.CSSProperties = { display: "flex", gap: 8, flexWrap: "wrap" };
const tabStyle: React.CSSProperties = { ...buttonStyle, height: 34, background: "rgba(2,6,23,0.42)", borderColor: "var(--border-dim)" };
const activeTabStyle: React.CSSProperties = { ...tabStyle, color: "#cffafe", borderColor: "rgba(103,232,249,0.48)", background: "rgba(103,232,249,0.14)" };
const filterGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(145px, 1fr))", gap: 9 };
const workspaceStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(0, 1fr) 380px", gap: 16, minHeight: 720 };
const graphPanelStyle: React.CSSProperties = { minHeight: 720, border: "1px solid var(--border-dim)", borderRadius: 8, background: "radial-gradient(circle at 30% 20%, rgba(34,211,238,0.08), transparent 30%), rgba(8,15,29,0.72)", overflow: "hidden", position: "relative" };
const graphControlStyle: React.CSSProperties = { position: "absolute", zIndex: 5, top: 10, left: 10, right: 10, display: "flex", gap: 7, flexWrap: "wrap", alignItems: "center", pointerEvents: "none" };
const floatingControlButtonStyle: React.CSSProperties = { height: 30, border: "1px solid rgba(102,168,255,0.28)", borderRadius: 8, background: "rgba(15,23,42,0.86)", color: "var(--text-primary)", padding: "0 10px", cursor: "pointer", pointerEvents: "auto", fontWeight: 800 };
const activeControlButtonStyle: React.CSSProperties = { color: "#cffafe", borderColor: "rgba(103,232,249,0.46)", background: "rgba(103,232,249,0.14)" };
const inspectorStyle: React.CSSProperties = { display: "grid", alignContent: "start", gap: 14, maxHeight: "calc(100vh - 125px)", overflow: "auto", paddingRight: 2 };
const inspectorCardStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 8, background: "rgba(15,23,42,0.58)", padding: 16 };
const nodeIconStyle: React.CSSProperties = { width: 34, height: 34, borderRadius: 9, border: "1px solid", display: "grid", placeItems: "center", background: "rgba(2,6,23,0.46)", fontSize: 10, fontWeight: 900, flex: "0 0 auto" };
const nodeTitleStyle: React.CSSProperties = { color: "var(--text-primary)", fontWeight: 900, fontSize: 13, lineHeight: 1.25, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
const nodeSubtitleStyle: React.CSSProperties = { color: "var(--text-secondary)", fontSize: 11, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
const severityPillStyle: React.CSSProperties = { justifySelf: "start", padding: "3px 8px", borderRadius: 999, border: "1px solid", fontSize: 10, fontWeight: 900 };
const smallPillStyle: React.CSSProperties = { display: "inline-flex", padding: "4px 8px", borderRadius: 999, border: "1px solid", fontSize: 10, fontWeight: 900 };
const inspectorTitleStyle: React.CSSProperties = { margin: "14px 0 6px", color: "var(--text-strong)", fontSize: 20, lineHeight: 1.25, wordBreak: "break-word" };
const inspectorValueStyle: React.CSSProperties = { color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" };
const inspectorGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 16 };
const statStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 8, background: "rgba(2,6,23,0.32)", padding: 10, color: "var(--text-primary)", display: "grid", gap: 6 };
const panelTitleStyle: React.CSSProperties = { margin: 0, color: "var(--text-primary)", fontSize: 15 };
const paragraphStyle: React.CSSProperties = { color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.7 };
const detailStyle: React.CSSProperties = { display: "flex", justifyContent: "space-between", gap: 12, borderTop: "1px solid var(--border-dim)", paddingTop: 10, marginTop: 10, color: "var(--text-secondary)", fontSize: 12 };
const actionGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 12 };
const actionButtonStyle: React.CSSProperties = { border: "1px solid rgba(102,168,255,0.28)", borderRadius: 8, background: "rgba(102,168,255,0.12)", color: "var(--text-primary)", padding: 9, cursor: "pointer", fontWeight: 800, fontSize: 12 };
const copyStatusStyle: React.CSSProperties = { marginTop: 10, border: "1px solid rgba(103,232,249,0.24)", borderRadius: 8, background: "rgba(103,232,249,0.08)", color: "#cffafe", padding: 8, fontSize: 12, fontWeight: 800, textAlign: "center" };
const relationshipListStyle: React.CSSProperties = { display: "grid", gap: 7, marginTop: 12 };
const relationshipRowStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 7 };
const relationshipButtonStyle: React.CSSProperties = { border: "1px solid var(--border-dim)", borderRadius: 8, background: "rgba(2,6,23,0.32)", color: "var(--text-secondary)", padding: 8, textAlign: "left", cursor: "pointer", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" };
const relationshipOpenButtonStyle: React.CSSProperties = { border: "1px solid rgba(103,232,249,0.3)", borderRadius: 8, background: "rgba(103,232,249,0.1)", color: "#cffafe", padding: "8px 10px", cursor: "pointer", fontWeight: 800 };
const relationshipEvidenceStyle: React.CSSProperties = { display: "grid", gap: 7, marginTop: 12, color: "var(--text-secondary)", fontSize: 12 };
const legendGridStyle: React.CSSProperties = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 7, marginTop: 10 };
const emptyStyle: React.CSSProperties = { height: "100%", display: "grid", placeItems: "center", padding: 28, textAlign: "center", fontSize: 13 };
const eyebrowStyle: React.CSSProperties = { color: "var(--text-muted)", fontSize: 10, fontWeight: 900, textTransform: "uppercase" };
