import type { CaseGraphNode } from "@/lib/api";

/**
 * Where each node sits on a time axis, and what the axis says.
 *
 * The Timeline was degenerate: every node landed on one coordinate with no
 * axis drawn, because a one-host case whose alerts are seconds apart has
 * nothing to spread along an x of raw timestamps. Measured on real cases, the
 * spans this has to cover differ by four orders of magnitude —
 *
 *     #1440   36 nodes, 3 hosts, 17 minutes
 *     #1106   19 nodes, 1 host,  1 hour
 *     #1849    3 nodes, 1 host,  4 hours
 *     #71     23 nodes, 2 hosts, 3 days
 *
 * — so one fixed scale cannot serve them, and a case whose whole story happens
 * inside a minute is not a time series at all. Below `ORDINAL_BELOW_MS` the
 * axis becomes an ordered sequence and says so, because pretending to resolve
 * milliseconds is a precision claim the data does not support.
 *
 * Pure, and separate from the renderer, so the decisions can be tested without
 * a browser: which lane, which x, what the ticks read, and what happens to a
 * node nothing timed.
 */

/** Under this span, wall-clock positions are noise — use a sequence axis. */
export const ORDINAL_BELOW_MS = 2 * 60 * 1000;

/** Nodes closer than this on screen are stacked rather than overlapped.
 *
 *  Sized against the drawing, not guessed: a node box renders about 90px wide
 *  with its label, so a 26px threshold — the first value here — declared two
 *  nodes 40px apart to be clear of each other and they overlapped anyway. On
 *  #1440 that left a pile of eight in one lane. */
export const COLLISION_PX = 96;

export const GUTTER_WIDTH = 96;

export type Frame = { width: number; height: number };
export type Placed = { id: string; x: number; y: number; stacked: boolean };
export type Tick = { x: number; label: string };
export type Lane = { key: string; label: string; y: number };

export type TimelinePlan = {
  scale: "time" | "sequence";
  /** Why this scale, in words an analyst reads. */
  scaleNote: string;
  ticks: Tick[];
  lanes: Lane[];
  placed: Placed[];
  /** Nodes nothing timed, parked outside the plotted range and labelled. */
  untimed: string[];
  gutterX: number;
  plotLeft: number;
  plotRight: number;
};

type Node = Pick<CaseGraphNode, "id" | "kind" | "label" | "attrs" | "witnesses">;

/** A node's time is its earliest witnessing alert — when it was first seen. */
export function timeOf(node: Node): number | null {
  const times = (node.witnesses || [])
    .map((w) => (w?.at ? Date.parse(String(w.at)) : NaN))
    .filter((t) => !Number.isNaN(t));
  return times.length ? Math.min(...times) : null;
}

/** Roughly how many ticks an axis should carry, whatever its span.
 *
 *  Fixed bands produced one tick for #1440's 17 minutes — a 10-minute step
 *  across a 17-minute case — which is an axis with nothing to read against.
 *  The step is now chosen to land near this count from a ladder of sensible
 *  human intervals. */
const TARGET_TICKS = 7;

function tickEvery(spanMs: number): { step: number; fmt: (d: Date) => string } {
  const S = 1000, M = 60 * S, H = 60 * M, D = 24 * H;
  const hhmm = (d: Date) =>
    `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
  const hhmmss = (d: Date) => `${hhmm(d)}:${String(d.getUTCSeconds()).padStart(2, "0")}`;
  const dayHour = (d: Date) =>
    `${d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" })} ${hhmm(d)}`;
  const day = (d: Date) =>
    d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" });

  // A ladder of intervals a person reads naturally. The step is the smallest
  // one that keeps the tick count at or under the target, so a short case gets
  // seconds and a three-day case gets half-days — without either ending up
  // with one tick or forty.
  const ladder: { step: number; fmt: (d: Date) => string }[] = [
    { step: 10 * S, fmt: hhmmss }, { step: 30 * S, fmt: hhmmss },
    { step: M, fmt: hhmmss }, { step: 2 * M, fmt: hhmm },
    { step: 5 * M, fmt: hhmm }, { step: 10 * M, fmt: hhmm },
    { step: 30 * M, fmt: hhmm }, { step: H, fmt: hhmm },
    { step: 3 * H, fmt: dayHour }, { step: 6 * H, fmt: dayHour },
    { step: 12 * H, fmt: dayHour }, { step: D, fmt: day },
    { step: 2 * D, fmt: day }, { step: 7 * D, fmt: day },
    { step: 14 * D, fmt: day }, { step: 28 * D, fmt: day },
  ];
  for (const rung of ladder) {
    if (spanMs / rung.step <= TARGET_TICKS) return rung;
  }
  return ladder[ladder.length - 1];
}

/**
 * Lanes: one per host, and when there is only one host, one per entity kind.
 *
 * A single-host case on a single lane is a row of dots, which is what the old
 * Timeline drew. The host is not the discriminator there — what kind of thing
 * each node is, is.
 */
function laneKeyOf(node: Node, singleHost: boolean): string {
  if (!singleHost) return String(node.attrs?.host || "—");
  return node.kind;
}

export function planTimeline(nodes: Node[], frame: Frame): TimelinePlan {
  const plotLeft = GUTTER_WIDTH + 70;
  const plotRight = Math.max(plotLeft + 120, frame.width - 48);

  const timed = nodes.filter((n) => timeOf(n) !== null);
  const untimed = nodes.filter((n) => timeOf(n) === null).map((n) => n.id);

  const hosts = new Set(timed.map((n) => String(n.attrs?.host || "—")));
  const singleHost = hosts.size <= 1;

  const laneKeys: string[] = [];
  timed.forEach((n) => {
    const key = laneKeyOf(n, singleHost);
    if (!laneKeys.includes(key)) laneKeys.push(key);
  });
  laneKeys.sort();
  const laneHeight = Math.max(
    64, Math.floor((frame.height - 120) / Math.max(1, laneKeys.length)),
  );
  const lanes: Lane[] = laneKeys.map((key, i) => ({
    key,
    label: singleHost ? key.replace(/_/g, " ") : key,
    y: 90 + i * laneHeight,
  }));
  const laneY = new Map(lanes.map((l) => [l.key, l.y]));

  const times = timed.map((n) => timeOf(n) as number);
  const lo = times.length ? Math.min(...times) : 0;
  const hi = times.length ? Math.max(...times) : 0;
  const span = hi - lo;
  const sequence = span < ORDINAL_BELOW_MS;

  const ticks: Tick[] = [];
  if (!sequence && span > 0) {
    const { step, fmt } = tickEvery(span);
    const first = Math.ceil(lo / step) * step;
    for (let t = first; t <= hi; t += step) {
      ticks.push({
        x: plotLeft + ((t - lo) / span) * (plotRight - plotLeft),
        label: fmt(new Date(t)),
      });
    }
  }

  // Sequence order is by time, ties broken by id so a redraw is stable.
  const order = [...timed].sort((a, b) => {
    const d = (timeOf(a) as number) - (timeOf(b) as number);
    return d !== 0 ? d : a.id.localeCompare(b.id);
  });
  const rank = new Map(order.map((n, i) => [n.id, i]));

  // Two passes, because how far a tier may drop depends on how many tiers the
  // busiest cluster in that lane needs — and that is not known until every
  // node is placed. One pass with a fixed 30px step stacked #1440's opening
  // cluster twelve deep and ran it through the lane below, which reads as
  // nodes in the wrong lane rather than as a stack.
  const xOf = (node: Node) =>
    sequence
      ? plotLeft +
        (order.length <= 1
          ? 0
          : ((rank.get(node.id) as number) / (order.length - 1)) * (plotRight - plotLeft))
      : plotLeft +
        (span === 0 ? 0 : (((timeOf(node) as number) - lo) / span) * (plotRight - plotLeft));

  const tierOf = new Map<string, number>();
  const seenInLane = new Map<string, number[]>();
  const maxTier = new Map<string, number>();
  order.forEach((node) => {
    const key = laneKeyOf(node, singleHost);
    const x = xOf(node);
    const taken = seenInLane.get(key) || [];
    const tier = taken.filter((placedX) => Math.abs(placedX - x) < COLLISION_PX).length;
    taken.push(x);
    seenInLane.set(key, taken);
    tierOf.set(node.id, tier);
    maxTier.set(key, Math.max(maxTier.get(key) || 0, tier));
  });

  const placed: Placed[] = order.map((node) => {
    const key = laneKeyOf(node, singleHost);
    const tiers = maxTier.get(key) || 0;
    // Never past the lane. A stack that overflows into the next lane is worse
    // than a tight one, because the lane is the claim about which host or kind
    // the node belongs to.
    const step = tiers > 0 ? Math.min(30, (laneHeight - 28) / tiers) : 0;
    const tier = tierOf.get(node.id) as number;
    return {
      id: node.id,
      x: xOf(node),
      y: (laneY.get(key) as number) + tier * step,
      stacked: tier > 0,
    };
  });

  // Untimed nodes sit in a labelled gutter at the left, outside the plotted
  // range — never at the start of it, which would assert they happened first.
  untimed.forEach((id, i) => {
    placed.push({ id, x: GUTTER_WIDTH / 2, y: 90 + i * 34, stacked: false });
  });

  return {
    scale: sequence ? "sequence" : "time",
    scaleNote: sequence
      ? span > 0
        ? `Everything here happens within ${Math.round(span / 1000)} seconds, so the ` +
          "axis shows the order events were first seen rather than the clock."
        : "Every node was first seen at the same instant, so the axis shows order, not time."
      : "Position on the axis is when each thing was first seen.",
    ticks,
    lanes,
    placed,
    untimed,
    gutterX: GUTTER_WIDTH / 2,
    plotLeft,
    plotRight,
  };
}
