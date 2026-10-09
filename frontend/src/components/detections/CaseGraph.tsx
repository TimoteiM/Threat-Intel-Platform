"use client";

/**
 * The case drawn as what happened.
 *
 * Entities are nodes and alerts are witnesses on them, so the same binary
 * reached by persistence and by credential access is one node with two
 * inbound edges rather than two leaves nobody connects.
 *
 * The one rule this file must never bend: a claim and a finding never look
 * the same. Of the 30,903 ATT&CK mappings in this estate 40 are confirmed,
 * and a graph is far more persuasive than a table — so a dashed edge looking
 * less impressive than a solid one is the point, not a defect to style away.
 *
 * Cytoscape rather than the reactflow used elsewhere in this app: compound
 * nodes give the host bands, and fcose/dagre are layouts reactflow would make
 * us hand-build.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import fcose from "cytoscape-fcose";
import dagre from "cytoscape-dagre";
import {
  getCaseGraph,
  type CaseGraph as CaseGraphData,
  type CaseGraphNode,
} from "@/lib/api";

let registered = false;
function register() {
  if (registered) return;
  cytoscape.use(fcose);
  cytoscape.use(dagre);
  registered = true;
}

type Mode = "narrative" | "topology" | "timeline";

/** ATT&CK tactics in kill-chain order. A node sits in the column of the
 *  earliest technique that touched it, so an attack walks rightward. */
const TACTICS: Array<{ id: string; label: string }> = [
  { id: "initial-access", label: "Initial Access" },
  { id: "execution", label: "Execution" },
  { id: "persistence", label: "Persistence" },
  { id: "privilege-escalation", label: "Privilege Esc." },
  { id: "defense-evasion", label: "Defense Evasion" },
  { id: "credential-access", label: "Credential Access" },
  { id: "discovery", label: "Discovery" },
  { id: "lateral-movement", label: "Lateral Movement" },
  { id: "collection", label: "Collection" },
  { id: "command-and-control", label: "Command & Control" },
  { id: "exfiltration", label: "Exfiltration" },
  { id: "impact", label: "Impact" },
];

/** Technique prefix -> tactic. Enough of ATT&CK to place the techniques this
 *  estate actually fires; anything unmapped lands in its own column rather
 *  than being guessed into one. */
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1566: "initial-access", T1189: "initial-access", T1078: "initial-access",
  T1190: "initial-access", T1204: "execution", T1059: "execution",
  T1106: "execution", T1053: "execution", T1547: "persistence",
  T1543: "persistence", T1136: "persistence", T1098: "persistence",
  T1055: "privilege-escalation", T1068: "privilege-escalation",
  T1562: "defense-evasion", T1070: "defense-evasion", T1112: "defense-evasion",
  T1027: "defense-evasion", T1003: "credential-access", T1110: "credential-access",
  T1555: "credential-access", T1087: "discovery", T1082: "discovery",
  T1016: "discovery", T1018: "discovery", T1057: "discovery", T1083: "discovery",
  T1021: "lateral-movement", T1570: "lateral-movement",
  T1005: "collection", T1113: "collection", T1071: "command-and-control",
  T1105: "command-and-control", T1095: "command-and-control",
  T1041: "exfiltration", T1486: "impact", T1531: "impact", T1489: "impact",
};

function tacticOf(techniqueId: string): string | null {
  const parent = (techniqueId || "").split(".")[0].toUpperCase();
  return TECHNIQUE_TACTIC[parent] || null;
}

/** One glyph per node type, plus the caption that sits under the label. A
 *  colour alone cannot be read by everyone, so the shape and the word carry
 *  the type and colour is never the only channel. */
const KIND: Record<string, { glyph: string; caption: string; shape: string; color: string }> = {
  host: { glyph: "▣", caption: "host", shape: "round-rectangle", color: "#4C6EF5" },
  account: { glyph: "◉", caption: "account", shape: "ellipse", color: "#9775FA" },
  process: { glyph: "▶", caption: "process", shape: "round-rectangle", color: "#12B886" },
  file: { glyph: "▤", caption: "file", shape: "round-rectangle", color: "#15AABF" },
  registry_value: { glyph: "◈", caption: "registry", shape: "diamond", color: "#E8590C" },
  service: { glyph: "⚙", caption: "service", shape: "hexagon", color: "#F08C00" },
  security_control: { glyph: "⛉", caption: "control", shape: "hexagon", color: "#2B8A3E" },
  domain: { glyph: "◍", caption: "domain", shape: "ellipse", color: "#D6336C" },
  ip: { glyph: "◆", caption: "address", shape: "diamond", color: "#C2255C" },
  url: { glyph: "⇢", caption: "url", shape: "round-rectangle", color: "#AE3EC9" },
  technique: { glyph: "✶", caption: "technique", shape: "star", color: "#868E96" },
  // An identifier that failed its type's shape check. Drawn, not dropped:
  // dropping hides the parser bug that produced it, which is how this class
  // keeps recurring.
  unparsed: { glyph: "?", caption: "unparsed", shape: "octagon", color: "#7048E8" },
};

/** The risk arc, from the severity the alert's own source states.
 *
 *  Four states, not three. "Unrated" is its own colour because 892 of 15,255
 *  alerts come from a source that states no severity, and 7,260 of them
 *  previously read 0 on a field whose smallest real value is 5 — so nearly
 *  half the estate was rendering as "least severe" when it had simply never
 *  been scored. That is a fact about our coverage, not about those alerts.
 *
 *  The thresholds here are placeholders on a normalised 0-100 scale and are
 *  deliberately coarse thirds. No severity bands have been agreed: the
 *  distribution of the old score was about twenty reachable values with four
 *  carrying a third of everything, so a band edge near one of them moved
 *  1,244 alerts on a one-point change. */
const UNRATED_ARC = "#7048E8";

function riskColour(severity: number | null | undefined, rated: boolean): string {
  if (!rated || severity == null) return UNRATED_ARC;
  if (severity >= 75) return "#E03131";
  if (severity >= 50) return "#F76707";
  return "#F59F00";
}

function labelOf(node: CaseGraphNode): string {
  const caption = KIND[node.kind]?.caption || node.kind;
  const glyph = KIND[node.kind]?.glyph || "•";
  return `${glyph} ${node.label}\n${caption}`;
}

export default function CaseGraph({
  caseKey,
  hours,
}: {
  caseKey: string;
  hours?: number;
}) {
  const [data, setData] = useState<CaseGraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("narrative");
  const [selected, setSelected] = useState<CaseGraphNode | null>(null);
  const [pathOnly, setPathOnly] = useState(false);
  const container = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    void (async () => {
      try {
        const graph = await getCaseGraph(caseKey, hours);
        if (!cancelled) setData(graph);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not draw this case.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [caseKey, hours]);

  const byId = useMemo(() => {
    const map = new Map<string, CaseGraphNode>();
    (data?.nodes || []).forEach((n) => map.set(n.id, n));
    return map;
  }, [data]);

  /** The earliest tactic that touched each node, walked outward from the
   *  techniques so a process inherits the column of the step it belongs to. */
  const tacticByNode = useMemo(() => {
    const out = new Map<string, string>();
    if (!data) return out;
    const rank = new Map(TACTICS.map((t, i) => [t.id, i]));
    data.nodes
      .filter((n) => n.kind === "technique")
      .forEach((technique) => {
        const tactic = tacticOf(String(technique.attrs?.id || technique.label));
        if (tactic) out.set(technique.id, tactic);
      });
    // One hop back along every edge that reaches a technique.
    data.edges.forEach((edge) => {
      const tactic = out.get(edge.target);
      if (!tactic) return;
      const held = out.get(edge.source);
      if (!held || (rank.get(tactic) ?? 99) < (rank.get(held) ?? 99)) {
        out.set(edge.source, tactic);
      }
    });
    return out;
  }, [data]);

  /** The causal path from the entry node to the highest-value asset touched. */
  const highlighted = useMemo(() => {
    if (!data) return new Set<string>();
    const outgoing = new Map<string, string[]>();
    data.edges.forEach((e) => {
      outgoing.set(e.source, [...(outgoing.get(e.source) || []), e.target]);
    });
    const inbound = new Set(data.edges.map((e) => e.target));
    const entries = data.nodes.filter(
      (n) => !inbound.has(n.id) && (n.kind === "file" || n.kind === "process"),
    );
    // The most valuable thing reached: a confirmed crown jewel first, then a
    // host somebody pivoted to, then the last host in the chain.
    const targets = data.nodes.filter(
      (n) =>
        n.kind === "host" &&
        (n.criticality?.tier === "crown_jewel" || n.criticality?.state === "proposed"),
    );
    const goal = targets[0] || data.nodes.find((n) => n.kind === "host" && n.status === "claimed");
    if (!goal || !entries.length) return new Set<string>();
    for (const entry of entries) {
      const queue: string[][] = [[entry.id]];
      const seen = new Set<string>([entry.id]);
      while (queue.length) {
        const path = queue.shift()!;
        const head = path[path.length - 1];
        if (head === goal.id) return new Set(path);
        for (const next of outgoing.get(head) || []) {
          if (seen.has(next)) continue;
          seen.add(next);
          queue.push([...path, next]);
        }
      }
    }
    return new Set<string>();
  }, [data]);

  const elements = useMemo<ElementDefinition[]>(() => {
    if (!data) return [];
    const out: ElementDefinition[] = [];
    const visible = new Set(
      pathOnly && highlighted.size ? Array.from(highlighted) : data.nodes.map((n) => n.id),
    );

    if (mode === "narrative") {
      // Compound parents: a band per host, plus one for attacker
      // infrastructure, which does not belong to any machine we own.
      const hosts = data.nodes.filter((n) => n.kind === "host");
      hosts.forEach((host) => {
        out.push({
          data: { id: `band:${host.id}`, label: host.label, band: true },
          classes: "band",
        });
      });
      out.push({
        data: { id: "band:external", label: "attacker infrastructure", band: true },
        classes: "band band-external",
      });
    }

    data.nodes.forEach((node) => {
      if (!visible.has(node.id)) return;
      const kind = KIND[node.kind] || KIND.technique;
      const tactic = tacticByNode.get(node.id) || "";
      let parent: string | undefined;
      if (mode === "narrative") {
        if (["domain", "ip", "url"].includes(node.kind)) parent = "band:external";
        else if (node.kind === "host") parent = undefined;
        else {
          const host = node.attrs?.host as string | undefined;
          const hostNode = data.nodes.find(
            (n) => n.kind === "host" && n.label === host,
          );
          if (hostNode) parent = `band:${hostNode.id}`;
        }
      }
      out.push({
        data: {
          id: node.id,
          label: labelOf(node),
          kind: node.kind,
          parent,
          tacticColour: tactic
            ? `hsl(${(TACTICS.findIndex((t) => t.id === tactic) * 29) % 360} 62% 48%)`
            : "#868E96",
          typeColour: kind.color,
          shape: kind.shape,
          risk: riskColour(node.severity, node.severity_rated !== false),
          claimed: node.status === "claimed" ? 1 : 0,
          onPath: highlighted.has(node.id) ? 1 : 0,
          pivots: node.pivot_alerts || 0,
          tactic,
        },
        classes: [
          node.status === "claimed" ? "claimed" : "corroborated",
          highlighted.has(node.id) ? "on-path" : "",
          node.attrs?.group ? "group" : "",
        ]
          .filter(Boolean)
          .join(" "),
      });
    });

    data.edges.forEach((edge, index) => {
      if (!visible.has(edge.source) || !visible.has(edge.target)) return;
      out.push({
        data: {
          id: `e${index}`,
          source: edge.source,
          target: edge.target,
          label: edge.kind.replace(/_/g, " "),
          width: Math.min(6, 1 + Math.log2(Math.max(1, edge.witness_count))),
          onPath:
            highlighted.has(edge.source) && highlighted.has(edge.target) ? 1 : 0,
        },
        classes: [
          edge.status === "claimed" ? "claimed" : "corroborated",
          highlighted.has(edge.source) && highlighted.has(edge.target) ? "on-path" : "",
        ]
          .filter(Boolean)
          .join(" "),
      });
    });
    return out;
  }, [data, mode, tacticByNode, highlighted, pathOnly]);

  useEffect(() => {
    if (!container.current || !data || !elements.length) return;
    register();
    const cy = cytoscape({
      container: container.current,
      elements,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-wrap": "wrap",
            "text-valign": "center",
            "font-size": 10,
            "line-height": 1.25,
            color: "#fff",
            shape: "data(shape)" as never,
            width: 104,
            height: 44,
            // Colour by tactic in Narrative, by entity type elsewhere —
            // never both at once, or the two meanings compete.
            "background-color":
              mode === "narrative" ? "data(tacticColour)" : "data(typeColour)",
            "border-width": 3,
            "border-color": "data(risk)",
          },
        },
        {
          // A claim is visibly provisional: hollow, dimmed, dashed border.
          selector: "node.claimed",
          style: {
            "background-opacity": 0.28,
            "border-style": "dashed",
            color: "#E9ECEF",
            "text-outline-width": 0,
          },
        },
        {
          selector: "node.group",
          style: { "border-style": "double", "font-weight": "bold" },
        },
        {
          selector: "node.band",
          style: {
            label: "data(label)",
            "text-valign": "top",
            "text-halign": "center",
            "font-size": 11,
            "font-weight": "bold",
            color: "#868E96",
            "background-opacity": 0.05,
            "background-color": "#4C6EF5",
            "border-width": 1,
            "border-color": "#495057",
            "border-style": "dotted",
            shape: "round-rectangle",
            // Valid Cytoscape compound-node padding; absent from @types.
            padding: 18,
          } as never,
        },
        {
          selector: "node.band-external",
          style: { "background-color": "#C2255C", "border-color": "#C2255C" },
        },
        {
          selector: "edge",
          style: {
            label: "data(label)",
            "font-size": 8,
            color: "#868E96",
            "text-background-opacity": 0,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            width: "data(width)",
            "line-color": "#495057",
            "target-arrow-color": "#495057",
          },
        },
        {
          // Dashed means claimed. This is the distinction the whole feature
          // rests on and it is not negotiable for visual balance.
          selector: "edge.claimed",
          style: { "line-style": "dashed", opacity: 0.55 },
        },
        {
          selector: ".on-path",
          style: { "line-color": "#FFD43B", "target-arrow-color": "#FFD43B", "z-index": 20 },
        },
        {
          selector: "node.on-path",
          style: { "border-color": "#FFD43B", "border-width": 4 },
        },
      ],
      layout: { name: "preset" },
    });
    cyRef.current = cy;

    const layout =
      mode === "topology"
        ? { name: "fcose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 110 }
        : mode === "narrative"
          ? { name: "dagre", rankDir: "LR", nodeSep: 28, rankSep: 90, animate: false }
          : { name: "preset" };

    if (mode === "timeline") {
      // Wall-clock on x, host band on y.
      const hosts = Array.from(
        new Set(data.nodes.map((n) => String(n.attrs?.host || "—"))),
      );
      const times = data.nodes
        .map((n) => (n.witnesses[0]?.at ? Date.parse(n.witnesses[0].at as string) : NaN))
        .filter((t) => !Number.isNaN(t));
      const lo = Math.min(...times);
      const hi = Math.max(...times);
      const span = Math.max(1, hi - lo);
      cy.nodes().forEach((n) => {
        const node = byId.get(n.id());
        if (!node) return;
        const at = node.witnesses[0]?.at ? Date.parse(node.witnesses[0].at as string) : lo;
        const row = Math.max(0, hosts.indexOf(String(node.attrs?.host || "—")));
        n.position({
          x: 90 + ((at - lo) / span) * 1100,
          y: 80 + row * 130 + (n.id().length % 5) * 16,
        });
      });
      cy.fit(undefined, 40);
    } else {
      cy.layout(layout as never).run();
      cy.fit(undefined, 40);
    }

    cy.on("tap", "node", (event) => {
      const node = byId.get(event.target.id());
      if (node) setSelected(node);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) setSelected(null);
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, mode, data, byId]);

  const exportAs = useCallback(
    (what: "png" | "json") => {
      const cy = cyRef.current;
      if (!cy || !data) return;
      let href: string;
      let name: string;
      if (what === "png") {
        href = cy.png({ full: true, scale: 2, bg: "#101113" });
        name = `case-${data.case_number ?? "graph"}.png`;
      } else {
        href = URL.createObjectURL(
          new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
        );
        name = `case-${data.case_number ?? "graph"}.json`;
      }
      const link = document.createElement("a");
      link.href = href;
      link.download = name;
      link.click();
      if (what === "json") setTimeout(() => URL.revokeObjectURL(href), 2000);
    },
    [data],
  );

  /** The narrative paragraph, built from the highlighted path. Written from
   *  the graph rather than from the model, so it cannot describe a step the
   *  graph does not draw — and it names which links are claims. */
  const narrative = useMemo(() => {
    if (!data || !highlighted.size) return null;
    const ordered = data.nodes.filter((n) => highlighted.has(n.id));
    const steps = ordered.map((n) => `${n.label} (${n.kind.replace(/_/g, " ")})`);
    const claimed = ordered.filter((n) => n.status === "claimed").length;
    return (
      `On this case the chain runs ${steps.join(" → ")}. ` +
      `${ordered.length - claimed} of ${ordered.length} steps are corroborated by ` +
      `sensor telemetry; ${claimed} ${claimed === 1 ? "is a claim" : "are claims"} ` +
      `derived from command-line text or inference and ${claimed === 1 ? "has" : "have"} ` +
      `not been confirmed.`
    );
  }, [data, highlighted]);

  if (error) {
    return <div style={{ fontSize: 12, color: "var(--status-critical)" }}>{error}</div>;
  }
  if (!data) {
    return <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Drawing…</div>;
  }
  if (!data.nodes.length) {
    const went = data.supersession;
    return (
      <div style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 620, lineHeight: 1.6 }}>
        {data.note || "Nothing to draw for this case."}
        {went?.continues_as ? (
          <div style={{ marginTop: 10 }}>
            This incident continues as{" "}
            <a
              href={`/detections/cases/${went.continues_as.case_key}?hours=${hours || 720}`}
              style={{ color: "var(--accent)", fontWeight: 600 }}
            >
              case #{went.continues_as.case_number}
            </a>
            , which is where its graph is drawn.
          </div>
        ) : null}
        {went?.chains_through ? (
          <div style={{ marginTop: 10 }}>
            It was merged into case #{went.chains_through.case_number}, whose key does
            not derive either — the trail continues through that row.
          </div>
        ) : null}
        {went?.candidates?.length ? (
          <div style={{ marginTop: 10 }}>
            Possible continuations, none of them certain enough to follow
            automatically:{" "}
            {went.candidates.map((c, i) => (
              <React.Fragment key={c.case_key}>
                {i ? ", " : ""}
                <a
                  href={`/detections/cases/${c.case_key}?hours=${hours || 720}`}
                  style={{ color: "var(--accent)" }}
                >
                  #{c.case_number}
                </a>
              </React.Fragment>
            ))}
          </div>
        ) : null}
        {went?.this_row?.has_analysis ? (
          <div style={{ marginTop: 10, color: "var(--text-subtle)" }}>
            This row's own analysis is kept
            {went.this_row.closed_at
              ? `, recorded ${went.this_row.closed_at.slice(0, 10)}`
              : ""}
            {went.this_row.resolution
              ? `, concluding ${went.this_row.resolution.replace(/_/g, " ")}`
              : ""}
            .
          </div>
        ) : null}
        {data.sources?.unmapped?.length ? (
          <div style={{ marginTop: 8, color: "var(--text-subtle)" }}>
            Sources in this case:{" "}
            {data.sources.by_source
              .map((s) => `${s.source} (${s.alerts} alert${s.alerts === 1 ? "" : "s"})`)
              .join(", ")}
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <Banners data={data} />

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {(["narrative", "topology", "timeline"] as Mode[]).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              ...chip,
              background: mode === m ? "var(--accent)" : "transparent",
              color: mode === m ? "#fff" : "var(--text-muted)",
              textTransform: "capitalize",
            }}
          >
            {m}
          </button>
        ))}
        <span style={{ width: 12 }} />
        <button
          onClick={() => setPathOnly((v) => !v)}
          disabled={!highlighted.size}
          style={{
            ...chip,
            opacity: highlighted.size ? 1 : 0.45,
            background: pathOnly ? "#FFD43B" : "transparent",
            color: pathOnly ? "#000" : "var(--text-muted)",
          }}
          title={
            highlighted.size
              ? "Show only the causal path to the highest-value asset touched"
              : "No path to a classified asset was found in this case"
          }
        >
          path only {highlighted.size ? `(${highlighted.size})` : ""}
        </button>
        <span style={{ flex: 1 }} />
        <button onClick={() => exportAs("png")} style={chip}>
          PNG
        </button>
        <button onClick={() => exportAs("json")} style={chip}>
          JSON
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: selected ? "1fr 320px" : "1fr", gap: 10 }}>
        <div
          ref={container}
          style={{
            height: 560,
            border: "1px solid var(--border)",
            borderRadius: 8,
            background: "var(--surface-sunken, #101113)",
          }}
        />
        {selected ? <Detail node={selected} onClose={() => setSelected(null)} /> : null}
      </div>

      <Legend counts={data.counts} mode={mode} />

      {narrative ? (
        <div
          style={{
            fontSize: 12,
            lineHeight: 1.6,
            color: "var(--text-muted)",
            borderLeft: "3px solid #FFD43B",
            paddingLeft: 10,
          }}
        >
          {narrative}
        </div>
      ) : null}
    </div>
  );
}

const chip: React.CSSProperties = {
  fontSize: 11,
  padding: "4px 10px",
  borderRadius: 999,
  border: "1px solid var(--border)",
  cursor: "pointer",
};

function Banners({ data }: { data: CaseGraphData }) {
  const rows: Array<{ tone: string; text: string }> = [];
  const unmapped = data.sources?.by_source?.filter((s) => !s.mapped) || [];
  if (unmapped.length) {
    const alerts = unmapped.reduce((n, s) => n + s.alerts, 0);
    rows.push({
      tone: "#F59F00",
      text:
        `${alerts} alert${alerts === 1 ? "" : "s"} in this case come from ` +
        `${unmapped.map((s) => s.source).join(", ")}, which this platform has no ` +
        `field map for. Nothing from ${alerts === 1 ? "it" : "them"} is drawn here.`,
    });
  }
  if (data.coverage?.note) rows.push({ tone: "#F59F00", text: data.coverage.note });
  if (data.over_cap) {
    rows.push({
      tone: "#F59F00",
      text: `${data.nodes.length} nodes is past the point this stays readable; use path only, or Topology.`,
    });
  }
  if (data.duplicate_keys) {
    rows.push({ tone: "#868E96", text: data.duplicate_keys.note });
  }
  (data.earlier_keys || []).forEach((earlier) => {
    // Attributed and dated, and deliberately not folded into this case's own
    // verdict: a conclusion recorded under one key is a judgement about that
    // key's alerts.
    rows.push({ tone: "#4C6EF5", text: earlier.attribution });
  });
  const claimedShare = data.integrity
    ? (data.integrity.edges_claimed || 0) /
      Math.max(1, (data.integrity.edges_claimed || 0) + (data.integrity.edges_corroborated || 0))
    : 0;
  if (claimedShare > 0.5) {
    rows.push({
      tone: "#868E96",
      text:
        `${Math.round(claimedShare * 100)}% of the relationships drawn here are claims — ` +
        `parsed from command-line text or inferred, not observed. They are dashed.`,
    });
  }
  if (!rows.length) return null;
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {rows.map((row, i) => (
        <div
          key={i}
          style={{
            fontSize: 11,
            lineHeight: 1.5,
            color: "var(--text-muted)",
            borderLeft: `3px solid ${row.tone}`,
            paddingLeft: 8,
          }}
        >
          {row.text}
        </div>
      ))}
    </div>
  );
}

function Legend({ counts, mode }: { counts: Record<string, number>; mode: Mode }) {
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", fontSize: 11, alignItems: "center" }}>
      {Object.entries(KIND)
        .filter(([kind]) => counts[kind])
        .map(([kind, spec]) => (
          <span key={kind} style={{ color: "var(--text-muted)" }}>
            <span style={{ color: mode === "narrative" ? "var(--text-muted)" : spec.color }}>
              {spec.glyph}
            </span>{" "}
            {spec.caption} {counts[kind]}
          </span>
        ))}
      <span style={{ flex: 1 }} />
      <span style={{ color: "var(--text-muted)" }}>— solid: corroborated</span>
      <span style={{ color: "var(--text-muted)" }}>
        <span style={{ letterSpacing: 2 }}>┄</span> dashed: claimed
      </span>
      {mode === "narrative" ? (
        <span style={{ color: "var(--text-subtle)" }}>colour = tactic</span>
      ) : (
        <span style={{ color: "var(--text-subtle)" }}>colour = entity type</span>
      )}
      <span style={{ color: UNRATED_ARC }} title="The alert's source states no severity. That is a gap in our coverage, not a quiet alert.">
        ◯ unrated severity
      </span>
    </div>
  );
}

function Detail({ node, onClose }: { node: CaseGraphNode; onClose: () => void }) {
  const attrs = Object.entries(node.attrs || {}).filter(
    ([k, v]) => v != null && v !== "" && k !== "members",
  );
  const members = (node.attrs?.members as string[] | undefined) || [];
  return (
    <aside
      style={{
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: 12,
        fontSize: 12,
        maxHeight: 560,
        overflow: "auto",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
        <strong style={{ wordBreak: "break-all" }}>{node.label}</strong>
        <button onClick={onClose} style={{ ...chip, padding: "0 8px" }}>
          ✕
        </button>
      </div>
      <div style={{ color: "var(--text-muted)", marginTop: 2 }}>
        {KIND[node.kind]?.caption || node.kind} ·{" "}
        <span style={{ color: node.status === "claimed" ? "#F59F00" : "#2B8A3E" }}>
          {node.status}
        </span>{" "}
        <span style={{ color: "var(--text-subtle)" }}>({node.basis})</span>
      </div>

      {node.kind === "unparsed" ? (
        <div style={{ marginTop: 8, lineHeight: 1.55 }}>
          <div style={{ color: "#7048E8" }}>
            This value failed its type's shape check and is shown as it was
            stored, rather than being dropped.
          </div>
          <div style={{ marginTop: 6, color: "var(--text-muted)" }}>
            {String(node.attrs?.why || "")}
          </div>
        </div>
      ) : null}

      <div style={{ marginTop: 8, color: "var(--text-muted)" }}>
        severity:{" "}
        {node.severity_rated === false || node.severity == null ? (
          <span
            style={{ color: UNRATED_ARC }}
            title="No alert touching this entity came from a source that states a severity."
          >
            unrated
          </span>
        ) : (
          <>
            {node.severity}/100{" "}
            <span style={{ color: "var(--text-subtle)" }}>
              (as the alert's own source states it)
            </span>
          </>
        )}
        {node.indicator_risk_score != null ? (
          <div style={{ color: "var(--text-subtle)", marginTop: 2 }}>
            worst indicator reputation: {node.indicator_risk_score}/100 — a
            score over the alert's indicators, not a severity
          </div>
        ) : null}
      </div>

      {node.kind === "host" ? (
        <div style={{ marginTop: 8, color: "var(--text-muted)" }}>
          criticality:{" "}
          {node.criticality?.state === "unknown" || !node.criticality?.tier ? (
            <span title="Nobody has classified this machine. That is not the same as saying it does not matter.">
              unknown
            </span>
          ) : (
            <>
              {node.criticality.tier} <em>({node.criticality.state})</em>
            </>
          )}
        </div>
      ) : null}

      {node.pivot_alerts ? (
        <div style={{ marginTop: 8, color: "var(--accent)" }}>
          seen in {node.pivot_alerts} alert{node.pivot_alerts === 1 ? "" : "s"} outside this case
        </div>
      ) : null}

      {node.absorbed?.length ? (
        <div style={{ marginTop: 8, color: "var(--text-subtle)", lineHeight: 1.5 }}>
          Merged from {node.absorbed.length} other observation
          {node.absorbed.length === 1 ? "" : "s"} of the same thing.
          {node.attrs?.merged_without_pid
            ? " At least one of them named no process id, so the merge itself is an inference."
            : ""}
        </div>
      ) : null}

      {attrs.length ? (
        <dl style={{ marginTop: 10, display: "grid", gridTemplateColumns: "auto 1fr", gap: "2px 8px" }}>
          {attrs.map(([key, value]) => (
            <React.Fragment key={key}>
              <dt style={{ color: "var(--text-subtle)" }}>{key.replace(/_/g, " ")}</dt>
              <dd style={{ margin: 0, wordBreak: "break-all" }}>{String(value)}</dd>
            </React.Fragment>
          ))}
        </dl>
      ) : null}

      {members.length ? (
        <details style={{ marginTop: 10 }}>
          <summary style={{ cursor: "pointer", color: "var(--text-muted)" }}>
            {members.length} folded into this node
          </summary>
          <ul style={{ margin: "6px 0 0", paddingLeft: 16, color: "var(--text-muted)" }}>
            {members.slice(0, 60).map((m) => (
              <li key={m} style={{ wordBreak: "break-all" }}>
                {m}
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      <div style={{ marginTop: 10 }}>
        <div style={{ color: "var(--text-subtle)" }}>
          witnessed by {node.witness_count} alert{node.witness_count === 1 ? "" : "s"}
        </div>
        <ul style={{ margin: "4px 0 0", paddingLeft: 16, color: "var(--text-muted)" }}>
          {node.witnesses.slice(0, 12).map((w) => (
            <li key={w.run_id}>
              <a
                href={`/alert-investigations/${w.run_id}`}
                style={{ color: "var(--accent)" }}
              >
                {w.detection || w.rule_id || w.run_id.slice(0, 8)}
              </a>
              {w.at ? ` · ${w.at.slice(11, 19)}` : ""}
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
