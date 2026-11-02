import type { CaseGraphNode } from "@/lib/api";

/**
 * Which band each node belongs in, and which bands are worth drawing.
 *
 * Extracted from `CaseGraph` so it can be tested. A band is a Cytoscape
 * compound parent and Cytoscape sizes a parent to its children, so a node
 * drawn *beside* a band rather than inside it is a node that was never made
 * its child. Measured by rendering the real component in headless Chromium on
 * eight cases: 11 nodes sat outside the band named after them, and seven of
 * the eight cases drew at least one empty band, which renders as a bare
 * node-sized rectangle on top of whatever the layout put there.
 *
 * Three rules, and the third is the one that keeps it honest:
 *
 *   1. The host node sits in its own band. It is the band's subject, not its
 *      neighbour.
 *   2. Addresses, domains and URLs go to `external` — attacker infrastructure
 *      belongs to no machine we own.
 *   3. Everything else joins a band ONLY on the host it names. Never inferred
 *      from a neighbour: a domain account and a technique belong to no one
 *      machine, and guessing would put them somewhere false rather than
 *      nowhere true.
 */

export const EXTERNAL_BAND = "band:external";

/** Kinds that are never host-local, whatever else an alert says about them. */
const EXTERNAL_KINDS = ["domain", "ip", "url"];

export type BandPlan = {
  /** node id -> band id. A node absent from this map sits outside every band. */
  parentOf: Map<string, string>;
  /** Band ids that have at least one member, in draw order. */
  drawn: string[];
  /** Host-band id -> the label to render on it. */
  labelOf: Map<string, string>;
};

export function planBands(
  nodes: Pick<CaseGraphNode, "id" | "kind" | "label" | "attrs">[],
  visible: Set<string>,
): BandPlan {
  const parentOf = new Map<string, string>();
  const labelOf = new Map<string, string>();

  const hostBand = new Map<string, string>();
  nodes.forEach((node) => {
    if (node.kind === "host") hostBand.set(node.label, `band:${node.id}`);
  });

  nodes.forEach((node) => {
    if (!visible.has(node.id)) return;
    if (EXTERNAL_KINDS.includes(node.kind)) {
      parentOf.set(node.id, EXTERNAL_BAND);
      return;
    }
    if (node.kind === "host") {
      parentOf.set(node.id, `band:${node.id}`);
      return;
    }
    const band = hostBand.get(node.attrs?.host as string);
    if (band) parentOf.set(node.id, band);
  });

  // A band with no children is not a band.
  const used = new Set(parentOf.values());
  const drawn: string[] = [];
  nodes.forEach((node) => {
    if (node.kind !== "host") return;
    const id = `band:${node.id}`;
    if (!used.has(id)) return;
    drawn.push(id);
    labelOf.set(id, node.label);
  });
  if (used.has(EXTERNAL_BAND)) {
    drawn.push(EXTERNAL_BAND);
    labelOf.set(EXTERNAL_BAND, "attacker infrastructure");
  }
  return { parentOf, drawn, labelOf };
}
