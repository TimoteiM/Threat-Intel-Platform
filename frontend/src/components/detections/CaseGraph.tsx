"use client";

/**
 * One case, drawn as what happened.
 *
 * An analyst reading a case gets a verdict, a paragraph and a table of
 * alerts. None of those show the *shape* of an intrusion — which account, on
 * which device, spawning what, reaching which indicator, in what order.
 *
 * **This is not a BloodHound graph, and it must not be mistaken for one.**
 * BloodHound draws Active Directory entitlements: who can reach Domain Admin
 * through group membership, ACLs and GPO links, collected from the directory.
 * This platform ingests no directory objects, so none of those nodes exist
 * here. This draws the incident — the records we actually hold about what was
 * observed.
 *
 * **Claimed and corroborated are drawn differently, always.** 30,763 of the
 * 30,803 ATT&CK mappings in this estate are `not_corroborated`: the detection
 * asserted a technique and the investigation found nothing bearing on it
 * either way. A graph is far more persuasive than a table, so drawing those
 * the same as the 40 that were confirmed would be the most convincing wrong
 * picture this platform could produce. Claims are dashed, outlined and
 * labelled "claimed"; corroboration is solid and filled. Never colour alone.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from "reactflow";
import dagre from "dagre";
import "reactflow/dist/style.css";

import { getCaseGraph, type CaseGraph as CaseGraphData, type CaseGraphNode } from "@/lib/api";

/** One colour per kind of thing, in a fixed order. Every node also carries a
 *  letter and its full label, so identity never rests on colour alone. */
const KIND = {
  case: { label: "Case", color: "#4387d6", letter: "C" },
  host: { label: "Device", color: "#2e9e6b", letter: "H" },
  account: { label: "Account", color: "#caa63b", letter: "A" },
  alert: { label: "Alert", color: "#e04a33", letter: "!" },
  process: { label: "Process", color: "#9a6ad6", letter: "P" },
  technique: { label: "ATT&CK", color: "#d6714a", letter: "T" },
  indicator: { label: "Indicator", color: "#4aa8b8", letter: "i" },
} as const;

type Kind = keyof typeof KIND;

const EDGE_LABEL: Record<string, string> = {
  contains: "", on: "on", account_on: "", ran_as: "as", names: "", ran: "",
  spawned: "spawned", accessed: "accessed",
  corroborated: "corroborated", claimed: "claimed",
};

function kindOf(node: { kind: string }): Kind {
  return (node.kind in KIND ? node.kind : "alert") as Kind;
}

/* ── layout ──────────────────────────────────────────────────────────────── */

function laidOut(data: CaseGraphData): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  // Left to right, because an attack is read as a sequence and a top-down
  // tree of long labels wastes the width a wide screen has.
  g.setGraph({ rankdir: "LR", nodesep: 26, ranksep: 90, marginx: 16, marginy: 16 });

  const WIDTH = 190;
  const HEIGHT = 46;
  data.nodes.forEach((n) => g.setNode(n.id, { width: WIDTH, height: HEIGHT }));
  data.edges.forEach((e) => {
    // dagre throws on an edge whose endpoints it has not been given.
    if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target);
  });
  dagre.layout(g);

  const nodes: Node[] = data.nodes.map((n) => {
    const point = g.node(n.id);
    return {
      id: n.id,
      type: "entity",
      position: { x: (point?.x ?? 0) - WIDTH / 2, y: (point?.y ?? 0) - HEIGHT / 2 },
      data: n,
    };
  });

  const edges: Edge[] = data.edges.map((e, i) => {
    const claimed = e.kind === "claimed";
    return {
      id: `${e.source}->${e.target}:${e.kind}:${i}`,
      source: e.source,
      target: e.target,
      label: EDGE_LABEL[e.kind] ?? e.kind,
      animated: false,
      // A claim is drawn as a claim: dashed, dimmer, and labelled. The
      // difference between "the rule said so" and "the evidence showed it"
      // is the whole point of the layer.
      style: claimed
        ? { stroke: "var(--text-dim)", strokeWidth: 1.2, strokeDasharray: "5 4" }
        : { stroke: "var(--panel-divider-strong, #555)", strokeWidth: 1.6 },
      labelStyle: { fill: "var(--text-muted)", fontSize: 9.5 },
      labelBgStyle: { fill: "var(--panel-card-bg, #0d0f18)", fillOpacity: 0.85 },
      markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12 },
    };
  });

  return { nodes, edges };
}

/* ── the node ────────────────────────────────────────────────────────────── */

function EntityNode({ data, selected }: NodeProps<CaseGraphNode>) {
  const kind = KIND[kindOf(data)];
  const claimed = data.kind === "technique" && data.status === "claimed";
  return (
    <div
      title={data.label}
      style={{
        display: "flex", alignItems: "center", gap: 8,
        width: 190, height: 46, padding: "0 10px", borderRadius: 9,
        border: `1px ${claimed ? "dashed" : "solid"} ${selected ? "var(--accent)" : kind.color}`,
        background: "var(--panel-card-bg, #0d0f18)",
        opacity: claimed ? 0.72 : 1,
        boxShadow: selected ? "0 0 0 2px var(--accent-subtle, rgba(56,139,253,0.3))" : undefined,
        cursor: "pointer",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <span
        aria-hidden
        style={{
          flex: "0 0 auto", width: 20, height: 20, borderRadius: 5,
          background: kind.color, color: "#0b0d13",
          fontSize: 11, fontWeight: 800, display: "grid", placeItems: "center",
        }}
      >
        {kind.letter}
      </span>
      <span style={{ minWidth: 0 }}>
        <span style={{ display: "block", fontSize: 8.5, letterSpacing: 0.5, textTransform: "uppercase", color: "var(--text-dim)" }}>
          {kind.label}
          {claimed ? " · claimed" : ""}
        </span>
        <span
          style={{
            display: "block", fontSize: 11, color: "var(--text)",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 142,
          }}
        >
          {data.label}
        </span>
      </span>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

/* ── the panel ───────────────────────────────────────────────────────────── */

function Detail({ node, onClose }: { node: CaseGraphNode; onClose: () => void }) {
  const kind = KIND[kindOf(node)];
  const rows: Array<[string, React.ReactNode]> = [];
  if (node.at) rows.push(["When", node.at]);
  if (node.verdict) rows.push(["Verdict", node.verdict]);
  if (node.risk != null) rows.push(["Risk", String(node.risk)]);
  if (node.rule_id) rows.push(["Carrier rule", node.rule_id]);
  if (node.account) rows.push(["Account", node.account]);
  if (node.image) rows.push(["Image", node.image]);
  if (node.command_line) rows.push(["Command line", node.command_line]);
  if (node.tactic) rows.push(["Tactic", node.tactic]);
  if (node.alert_count != null) rows.push(["Alerts", String(node.alert_count)]);

  return (
    <aside
      style={{
        position: "absolute", top: 10, right: 10, width: 300, maxHeight: "calc(100% - 20px)",
        overflow: "auto", zIndex: 5, padding: "12px 14px", borderRadius: 10,
        background: "var(--panel-card-bg, #0d0f18)",
        border: "1px solid var(--panel-divider-strong, var(--border))",
        boxShadow: "0 10px 30px rgba(0,0,0,0.45)",
      }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ ...caption, color: kind.color }}>{kind.label}</span>
        <button type="button" onClick={onClose} style={closeBtn} aria-label="Close">×</button>
      </div>
      <div style={{ fontSize: 13, marginTop: 4, wordBreak: "break-word" }}>{node.label}</div>

      {node.kind === "technique" && (
        <div
          style={{
            marginTop: 8, padding: "7px 9px", borderRadius: 7, fontSize: 11, lineHeight: 1.55,
            border: `1px ${node.status === "claimed" ? "dashed" : "solid"} var(--panel-divider-strong)`,
            color: "var(--text-muted)",
          }}
        >
          <strong style={{ color: node.status === "claimed" ? "var(--status-warning)" : "var(--status-ok, #2e9e6b)" }}>
            {node.status === "claimed" ? "Claimed by the detection" : "Corroborated by evidence"}
          </strong>
          {/* The assessment's own words. The difference between a mapping and
              a finding is exactly what this sentence says. */}
          {node.explanation ? <div style={{ marginTop: 4 }}>{node.explanation}</div> : null}
          {node.evidence_count ? <div style={{ marginTop: 4 }}>{node.evidence_count} piece(s) of evidence</div> : null}
        </div>
      )}

      {rows.length > 0 && (
        <dl style={{ margin: "10px 0 0", display: "grid", gap: 6 }}>
          {rows.map(([label, value]) => (
            <div key={label}>
              <dt style={caption}>{label}</dt>
              <dd style={{ margin: 0, fontSize: 11.5, wordBreak: "break-word", fontFamily: label === "Command line" || label === "Image" ? "var(--font-mono)" : undefined }}>
                {value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {(node.href || node.url) && (
        <a
          href={node.href || node.url || undefined}
          target={node.url && !node.href ? "_blank" : undefined}
          rel="noreferrer"
          style={{ display: "inline-block", marginTop: 10, fontSize: 11.5, color: "var(--accent)" }}
        >
          {node.href ? "Open this →" : "Read it on attack.mitre.org →"}
        </a>
      )}
    </aside>
  );
}

/* ── the graph ───────────────────────────────────────────────────────────── */

export default function CaseGraph({
  caseKey,
  hours,
}: {
  caseKey: string;
  /** The window the case page re-derives over, so the graph draws the same
   *  case the header describes rather than failing to form it. */
  hours?: number;
}) {
  const [data, setData] = useState<CaseGraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<CaseGraphNode | null>(null);
  const [hidden, setHidden] = useState<Set<Kind>>(new Set());

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const graph = await getCaseGraph(caseKey, hours);
        if (!cancelled) setData(graph);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not draw this case.");
      }
    })();
    return () => { cancelled = true; };
  }, [caseKey, hours]);

  const shown = useMemo(() => {
    if (!data) return null;
    if (!hidden.size) return data;
    const keep = new Set(data.nodes.filter((n) => !hidden.has(kindOf(n))).map((n) => n.id));
    return {
      ...data,
      nodes: data.nodes.filter((n) => keep.has(n.id)),
      edges: data.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
    };
  }, [data, hidden]);

  const flow = useMemo(() => (shown ? laidOut(shown) : { nodes: [], edges: [] }), [shown]);

  const toggle = useCallback((kind: Kind) => {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  }, []);

  if (error) return <div style={{ fontSize: 12, color: "var(--status-critical)" }}>{error}</div>;
  if (!data) return <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Drawing…</div>;
  if (!data.nodes.length) {
    // The note carries the reason — most often that the case no longer
    // re-derives over this window. A bare "nothing to draw" reads as "no
    // attack here", which is a different and much worse claim.
    return (
      <div style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 560, lineHeight: 1.5 }}>
        {data.note || "Nothing to draw for this case."}
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 10 }}>
      {/* The legend is always present, and it doubles as the filter. */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {(Object.keys(KIND) as Kind[]).map((kind) => {
          const count = data.counts[kind] || 0;
          const off = hidden.has(kind);
          return (
            <button
              key={kind}
              type="button"
              disabled={!count}
              onClick={() => toggle(kind)}
              aria-pressed={!off}
              style={{
                display: "inline-flex", alignItems: "center", gap: 6,
                padding: "3px 9px", borderRadius: 999, fontSize: 11, cursor: count ? "pointer" : "default",
                border: `1px solid ${off || !count ? "var(--border)" : KIND[kind].color}`,
                background: "transparent",
                color: off || !count ? "var(--text-dim)" : "var(--text)",
                opacity: count ? 1 : 0.4,
              }}
            >
              <span style={{ width: 8, height: 8, borderRadius: 2, background: KIND[kind].color }} />
              {KIND[kind].label} {count}
            </button>
          );
        })}

        {data.attack.claimed > 0 && (
          <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
            {/* Said in the legend, not only in a tooltip: it is the single
                most load-bearing caveat on the page. */}
            {data.attack.corroborated} technique{data.attack.corroborated === 1 ? "" : "s"} corroborated ·{" "}
            <span style={{ color: "var(--status-warning)" }}>
              {data.attack.claimed} claimed by the detection, drawn dashed
            </span>
          </span>
        )}
      </div>

      <div
        style={{
          position: "relative", height: 560, borderRadius: 10,
          border: "1px solid var(--panel-divider, var(--border))", overflow: "hidden",
        }}
      >
        <ReactFlow
          nodes={flow.nodes}
          edges={flow.edges}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.15}
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_, node) => setSelected(node.data as CaseGraphNode)}
          onPaneClick={() => setSelected(null)}
        >
          <Background color="var(--panel-divider)" gap={18} />
          <Controls showInteractive={false} />
        </ReactFlow>
        {selected && <Detail node={selected} onClose={() => setSelected(null)} />}
      </div>

      <p style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6, margin: 0 }}>
        {data.note}
        {data.dropped
          ? ` Too large to draw whole — ${Object.entries(data.dropped)
              .map(([k, n]) => `${n} ${k}`)
              .join(", ")} left out.`
          : ""}
      </p>
    </div>
  );
}

const caption: React.CSSProperties = {
  fontSize: "var(--font-micro, 10px)", fontWeight: 700,
  letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)",
};

const closeBtn: React.CSSProperties = {
  marginLeft: "auto", border: "none", background: "transparent",
  color: "var(--text-muted)", fontSize: 16, lineHeight: 1, cursor: "pointer",
};
