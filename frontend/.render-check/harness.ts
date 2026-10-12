/* Render check harness. Imports the REAL labelOf and the REAL fitter — a copy
 * would diverge, which is the defect class this whole day has been about.
 * Renders every technique label this estate can produce, measures each
 * rendered label against the node box, and reports overflow as a verdict
 * rather than leaving it to be eyeballed. */
import cytoscape from "cytoscape";
import { labelOf } from "../src/components/detections/CaseGraph";
import { LABEL_MAX_PX, approximateMeasurer, canvasMeasurer } from "../src/components/detections/nodeLabel";

declare const TECHNIQUES: Array<Record<string, unknown>>;

const NODE_W = 104;
const NODE_H = 44;

const measure = canvasMeasurer("10px sans-serif") || approximateMeasurer();

const elements = TECHNIQUES.map((t, i) => ({
  data: {
    id: `n${i}`,
    label: labelOf(
      { id: `n${i}`, kind: "technique", label: String(t.id), attrs: t } as never,
      measure,
    ),
    retired: t.retired === true ? 1 : 0,
  },
  position: { x: 140 + (i % 10) * 150, y: 90 + Math.floor(i / 10) * 110 },
}));

const cy = cytoscape({
  container: document.getElementById("cy"),
  elements,
  layout: { name: "preset" },
  style: [
    { selector: "node[retired = 1]", style: { "border-style": "dashed" } },
    {
      selector: "node",
      style: {
        label: "data(label)",
        "text-wrap": "wrap",
        "text-max-width": `${LABEL_MAX_PX}px`,
        "text-valign": "center",
        "font-size": 10,
        "line-height": 1.25,
        color: "#fff",
        shape: "round-rectangle",
        width: NODE_W,
        height: NODE_H,
        "background-color": "#2b3140",
        "border-width": 3,
        "border-color": "#F59F00",
      },
    },
  ],
});

// Isolate the LABEL. Comparing a bounding box that includes the node and its
// 3px border against the bare node width reported all 75 as overflowing at
// exactly 109.0px — a uniform result, which is the tell that the instrument
// is wrong rather than the thing measured. A real truncation bug would hit
// some names and not others.
const over: string[] = [];
let widestLabel = 0;
cy.nodes().forEach((n) => {
  const withLabel = n.boundingBox({ includeLabels: true });
  const withoutLabel = n.boundingBox({ includeLabels: false });
  const label = String(n.data("label") || "");
  const head = label.split("\n")[0];
  const lines = label.split("\n").length;
  const spill = withLabel.w - withoutLabel.w;
  widestLabel = Math.max(widestLabel, withLabel.w);
  if (spill > 1) over.push(`${head} label spills ${spill.toFixed(1)}px`);
  if (withLabel.h - withoutLabel.h > 1) {
    over.push(`${head} label taller than node by ${(withLabel.h - withoutLabel.h).toFixed(1)}px`);
  }
  if (lines > 3) over.push(`${head} ${lines} lines`);
});

const verdict = {
  nodes: cy.nodes().length,
  nodeBox: `${NODE_W}x${NODE_H}`,
  overflowing: over.length,
  offenders: over.slice(0, 6),
  widestLabelBox: Number(widestLabel.toFixed(1)),
  retiredDrawn: cy.nodes().filter((n) => n.data("retired") === 1).length,
  threeLineLabels: cy.nodes().filter(
    (n) => String(n.data("label") || "").split("\n").length === 3,
  ).length,
  truncated: cy.nodes().filter(
    (n) => String(n.data("label") || "").indexOf("\u2026") >= 0,
  ).length,
  measurerIsReal: canvasMeasurer("10px sans-serif") !== null,
};
document.getElementById("verdict")!.textContent = JSON.stringify(verdict, null, 1);
console.log("VERDICT " + JSON.stringify(verdict));
