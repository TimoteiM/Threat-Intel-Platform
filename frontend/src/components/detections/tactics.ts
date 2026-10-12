/**
 * Which tactic columns the Narrative layout draws, and why each one is there.
 *
 * The columns used to be a hand-written list of twelve in `CaseGraph.tsx`,
 * beside a hand-written map of 38 technique prefixes. Both were written
 * against a pre-19 ATT&CK and neither could say it had gone stale: ATT&CK 19
 * split Defense Evasion into Stealth and Defense Impairment, so three of the
 * mappings pointed at a tactic that no longer exists, and 6,290 technique
 * nodes in this estate — 18.6% of all of them — resolve to Stealth, which had
 * no column at all. The tactic now arrives on each node and the order arrives
 * as `attack.tactic_order`, both from the bundled catalogue.
 *
 * Three absences, which look identical if the column logic does not separate
 * them:
 *
 *   EMPTY        The tactic exists in this ATT&CK and this case has nothing in
 *                it. Drawn, empty. "Nothing in Exfiltration" is a statement
 *                about the incident and one an analyst reads — a graph that
 *                silently omits it says instead that nobody looked.
 *
 *   RETIRED_TACTIC
 *                The tactic does not exist in the ATT&CK being resolved
 *                against. Not drawn. There is nothing to say about
 *                `defense-evasion` in 19.2 except that it is not a tactic any
 *                more, and a column for it would invite someone to wonder why
 *                it is empty.
 *
 *   UNPLACED     A node whose technique id this platform cannot name, so it
 *                has no tactic. Drawn as its own column, never folded into a
 *                real one. An id in our data that ATT&CK does not have is a
 *                finding, and guessing it into Execution would hide it.
 *
 * The first two are both "no nodes here". The difference is whether the
 * absence is about the incident or about the catalogue, and only one of them
 * is worth a reader's attention.
 */

export const EMPTY = "empty";
export const POPULATED = "populated";
export const UNPLACED = "unplaced";

/** Why a tactic was left out rather than drawn empty. */
export const RETIRED_TACTIC = "retired_tactic";

export type ColumnState = typeof EMPTY | typeof POPULATED | typeof UNPLACED;

export interface TacticColumn {
  /** The tactic's display name, or the unplaced column's label. */
  readonly label: string;
  /** Stable id for keys and for the node's column assignment. */
  readonly id: string;
  readonly state: ColumnState;
  readonly count: number;
}

export interface OmittedTactic {
  readonly label: string;
  readonly reason: typeof RETIRED_TACTIC;
}

export interface TacticPlan {
  readonly columns: readonly TacticColumn[];
  /** Tactics the nodes claim that this ATT&CK release does not have. */
  readonly omitted: readonly OmittedTactic[];
  /** The ATT&CK release the columns came from, for the caption. */
  readonly attackVersion: string | null;
}

export const UNPLACED_LABEL = "Not in ATT&CK";

export function slugOf(label: string): string {
  return String(label ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

interface PlanInput {
  /** One entry per technique node: its tactic, or null when unnameable. */
  readonly tactics: readonly (string | null | undefined)[];
  /** `attack.tactic_order` — the tactics this ATT&CK release has, in order. */
  readonly order: readonly string[];
  readonly attackVersion?: string | null;
}

/**
 * Plan the columns.
 *
 * Every tactic in `order` gets a column whether or not this case has nodes in
 * it. A tactic claimed by a node but absent from `order` is reported in
 * `omitted` rather than drawn — and reported rather than dropped silently,
 * because it means the data and the catalogue disagree about what a tactic is,
 * which is worth knowing even though it is not worth a column.
 *
 * With an empty `order` — an older graph payload that carries no tactic
 * order — this returns the populated columns only, in first-seen order, and
 * no empty ones. It cannot do better: without knowing which tactics exist it
 * cannot tell "this case has nothing in Exfiltration" from "Exfiltration is
 * not a tactic any more", and inventing the distinction would be worse than
 * declining to draw it.
 */
export function planTactics(input: PlanInput): TacticPlan {
  const order = input.order ?? [];
  const counts = new Map<string, number>();
  let unplaced = 0;

  for (const raw of input.tactics ?? []) {
    const tactic = typeof raw === "string" ? raw.trim() : "";
    if (!tactic) {
      unplaced += 1;
      continue;
    }
    counts.set(tactic, (counts.get(tactic) ?? 0) + 1);
  }

  const known = new Set(order);
  const columns: TacticColumn[] = [];

  if (order.length === 0) {
    for (const [label, count] of counts) {
      columns.push({ label, id: slugOf(label), state: POPULATED, count });
    }
  } else {
    for (const label of order) {
      const count = counts.get(label) ?? 0;
      columns.push({
        label,
        id: slugOf(label),
        state: count > 0 ? POPULATED : EMPTY,
        count,
      });
    }
  }

  const omitted: OmittedTactic[] = [...counts.keys()]
    .filter((label) => order.length > 0 && !known.has(label))
    .map((label) => ({ label, reason: RETIRED_TACTIC }));

  if (unplaced > 0) {
    columns.push({
      label: UNPLACED_LABEL,
      id: UNPLACED,
      state: UNPLACED,
      count: unplaced,
    });
  }

  return { columns, omitted, attackVersion: input.attackVersion ?? null };
}

/**
 * The column a node belongs in.
 *
 * Returns the unplaced column for a node with no resolvable tactic, and for
 * one whose tactic this release does not have — in both cases because putting
 * it in a real column would assert something the catalogue does not support.
 */
export function columnFor(
  tactic: string | null | undefined,
  plan: TacticPlan,
): string {
  const label = typeof tactic === "string" ? tactic.trim() : "";
  if (!label) return UNPLACED;
  const match = plan.columns.find(
    (column) => column.state !== UNPLACED && column.label === label,
  );
  return match ? match.id : UNPLACED;
}
