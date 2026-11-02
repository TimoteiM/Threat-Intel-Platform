import { describe, expect, it } from "vitest";

import {
  COLLISION_PX,
  GUTTER_WIDTH,
  ORDINAL_BELOW_MS,
  planTimeline,
  timeOf,
} from "./timeline";

/**
 * The Timeline was degenerate: every node on one coordinate with no axis. The
 * spans it has to cover differ by four orders of magnitude — #1440 is 36 nodes
 * over 17 minutes, #71 is 23 nodes over 3 days — so one fixed scale cannot
 * serve them.
 */

const FRAME = { width: 1440, height: 900 };
const T0 = Date.parse("2026-08-16T09:00:00.000Z");

type N = Parameters<typeof planTimeline>[0][number];

const at = (ms: number | null) => (ms === null ? [] : [{ at: new Date(ms).toISOString() }]);

const node = (id: string, ms: number | null, over: Partial<N> = {}): N =>
  ({ id, kind: "process", label: id, attrs: { host: "h1" }, witnesses: at(ms), ...over }) as N;

describe("when a node happened", () => {
  it("is the earliest witnessing alert, not the latest", () => {
    const n = node("a", null, {
      witnesses: [
        { at: new Date(T0 + 5000).toISOString() },
        { at: new Date(T0).toISOString() },
      ],
    } as Partial<N>);
    expect(timeOf(n)).toBe(T0);
  });

  it("is null when nothing timed it, rather than zero", () => {
    expect(timeOf(node("a", null))).toBeNull();
    expect(timeOf(node("b", null, { witnesses: [{ at: null }] } as Partial<N>))).toBeNull();
  });
});

describe("the axis adapts to the span", () => {
  it("draws a real time axis with labelled ticks over minutes", () => {
    // #1440's shape: 17 minutes.
    const nodes = [node("a", T0), node("b", T0 + 17 * 60_000)];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.scale).toBe("time");
    expect(plan.ticks.length).toBeGreaterThan(1);
    expect(plan.ticks[0].label).toMatch(/^\d{2}:\d{2}/);
  });

  it("becomes a sequence axis when everything happens inside two minutes", () => {
    // Pretending to resolve milliseconds is a precision claim the data does
    // not support — and a row of dots is what the old Timeline drew.
    const nodes = [node("a", T0), node("b", T0 + 400), node("c", T0 + 900)];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.scale).toBe("sequence");
    expect(plan.ticks).toEqual([]);
    expect(plan.scaleNote).toMatch(/order/);
  });

  it("spreads a sequence axis evenly rather than piling up", () => {
    const nodes = [node("a", T0), node("b", T0 + 1), node("c", T0 + 2)];
    const xs = planTimeline(nodes, FRAME).placed.map((p) => p.x);
    expect(new Set(xs).size).toBe(3);
    expect(Math.max(...xs) - Math.min(...xs)).toBeGreaterThan(400);
  });

  it("says why the axis is what it is", () => {
    expect(planTimeline([node("a", T0), node("b", T0 + 1000)], FRAME).scaleNote)
      .toMatch(/within \d+ seconds/);
    expect(planTimeline([node("a", T0), node("b", T0 + 3 * 3600_000)], FRAME).scaleNote)
      .toMatch(/when each thing was first seen/);
  });

  it("uses coarser ticks over days than over minutes", () => {
    // The property, not the format. Asserting an exact format tied this test
    // to the fixed bands that produced one tick for a seventeen-minute case,
    // so it failed when they were replaced by a step chosen for tick count.
    const seconds = planTimeline([node("a", T0), node("b", T0 + 150_000)], FRAME);
    const minutes = planTimeline([node("a", T0), node("b", T0 + 9 * 60_000)], FRAME);
    const days = planTimeline([node("a", T0), node("b", T0 + 3 * 86_400_000)], FRAME);

    // A two-and-a-half-minute case resolves to seconds; nine minutes does not
    // need them; three days carries a date.
    expect(seconds.ticks[0].label).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(minutes.ticks[0].label).toMatch(/^\d{2}:\d{2}$/);
    expect(days.ticks[0].label).toMatch(/\d{2} \w{3}/);
  });

  it("does not try to draw ticks when every node shares one instant", () => {
    const plan = planTimeline([node("a", T0), node("b", T0)], FRAME);
    expect(plan.ticks).toEqual([]);
    expect(plan.scaleNote).toMatch(/same instant/);
  });
});

describe("lanes", () => {
  it("gives each host its own lane", () => {
    const nodes = [
      node("a", T0, { attrs: { host: "exp-fin-034" } }),
      node("b", T0 + 60_000, { attrs: { host: "exp-dc-01" } }),
    ];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.lanes.map((l) => l.key).sort()).toEqual(["exp-dc-01", "exp-fin-034"]);
    const ys = plan.placed.map((p) => p.y);
    expect(new Set(ys).size).toBe(2);
  });

  it("falls back to entity kind when there is only one host", () => {
    // #1106 and #1849 are single-host. The host is not the discriminator
    // there — what kind of thing each node is, is.
    const nodes = [
      node("p", T0, { kind: "process" }),
      node("f", T0 + 60_000, { kind: "file" }),
      node("d", T0 + 120_000, { kind: "domain" }),
    ];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.lanes.map((l) => l.key).sort()).toEqual(["domain", "file", "process"]);
  });

  it("labels a kind lane readably", () => {
    const plan = planTimeline([node("r", T0, { kind: "registry_value" })], FRAME);
    expect(plan.lanes[0].label).toBe("registry value");
  });
});

describe("collisions", () => {
  it("stacks nodes that would overlap instead of hiding one behind another", () => {
    // Time mode, so the x positions are real: three things within a tenth of
    // a second, and a fourth ten minutes later to make the span wide enough
    // that the axis stays a clock. Under two minutes the axis becomes a
    // sequence and spreads them, which is a different behaviour with its own
    // test — the first version of this case was really testing that.
    const nodes = [
      node("a", T0), node("b", T0 + 50), node("c", T0 + 90),
      node("far", T0 + 10 * 60_000),
    ];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.scale).toBe("time");
    const close = plan.placed.filter((p) => ["a", "b", "c"].includes(p.id));
    expect(new Set(close.map((p) => p.y)).size).toBe(3);
    expect(close.filter((p) => p.stacked).length).toBe(2);
    expect(plan.placed.find((p) => p.id === "far")?.stacked).toBe(false);
  });

  it("does not stack nodes that are far enough apart", () => {
    const nodes = [node("a", T0), node("b", T0 + 30 * 60_000)];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.placed.every((p) => !p.stacked)).toBe(true);
    expect(Math.abs(plan.placed[0].x - plan.placed[1].x)).toBeGreaterThan(COLLISION_PX);
  });
});

describe("nodes nothing timed", () => {
  it("parks them in a gutter outside the plotted range", () => {
    // Never at the start of the axis: that would assert they happened first.
    const nodes = [node("timed", T0), node("untimed", null)];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.untimed).toEqual(["untimed"]);
    const parked = plan.placed.find((p) => p.id === "untimed");
    expect(parked?.x).toBeLessThan(plan.plotLeft);
    expect(parked?.x).toBeLessThanOrEqual(GUTTER_WIDTH);
  });

  it("keeps untimed nodes out of the lane and tick calculations", () => {
    const nodes = [node("a", T0), node("b", T0 + 5 * 60_000), node("u", null)];
    const plan = planTimeline(nodes, FRAME);
    expect(plan.scale).toBe("time");
    expect(plan.lanes.length).toBe(1);
  });

  it("handles a case where nothing is timed at all", () => {
    const plan = planTimeline([node("a", null), node("b", null)], FRAME);
    expect(plan.untimed).toEqual(["a", "b"]);
    expect(plan.ticks).toEqual([]);
    expect(plan.placed).toHaveLength(2);
  });

  it("copes with no nodes", () => {
    const plan = planTimeline([], FRAME);
    expect(plan.placed).toEqual([]);
    expect(plan.lanes).toEqual([]);
  });
});

describe("the ordinal boundary", () => {
  it("is two minutes", () => {
    expect(ORDINAL_BELOW_MS).toBe(120_000);
    const under = planTimeline([node("a", T0), node("b", T0 + 119_000)], FRAME);
    const over = planTimeline([node("a", T0), node("b", T0 + 121_000)], FRAME);
    expect(under.scale).toBe("sequence");
    expect(over.scale).toBe("time");
  });
});

describe("tick density, which the first version got wrong", () => {
  const ticksFor = (spanMs: number) =>
    planTimeline(
      [node("a", T0), node("b", T0 + spanMs)],
      { width: 1440, height: 900 },
    ).ticks;

  it("gives a seventeen-minute case more than one tick", () => {
    // #1440. Fixed bands chose a 10-minute step for a 17-minute span and drew
    // a single tick — an axis with nothing to read against.
    expect(ticksFor(17 * 60_000).length).toBeGreaterThanOrEqual(4);
  });

  it.each([
    ["three minutes", 3 * 60_000],
    ["seventeen minutes", 17 * 60_000],
    ["one hour", 3_600_000],
    ["four hours", 4 * 3_600_000],
    ["three days", 3 * 86_400_000],
    ["three weeks", 21 * 86_400_000],
  ])("keeps %s readable: between 2 and 10 ticks", (_name, span) => {
    const n = ticksFor(span).length;
    expect(n).toBeGreaterThanOrEqual(2);
    expect(n).toBeLessThanOrEqual(10);
  });

  it("every tick falls inside the plotted range", () => {
    const plan = planTimeline(
      [node("a", T0), node("b", T0 + 3 * 86_400_000)], { width: 1440, height: 900 },
    );
    plan.ticks.forEach((t) => {
      expect(t.x).toBeGreaterThanOrEqual(plan.plotLeft);
      expect(t.x).toBeLessThanOrEqual(plan.plotRight);
    });
  });
});

describe("collision width is sized against the drawing", () => {
  it("is wide enough for a node box", () => {
    // A node renders about 90px with its label; 26px declared two nodes 40px
    // apart to be clear of each other and they overlapped anyway.
    expect(COLLISION_PX).toBeGreaterThanOrEqual(80);
  });

  it("stacks a dense cluster into distinct rows", () => {
    const nodes = [
      ...Array.from({ length: 6 }, (_, i) => node(`n${i}`, T0 + i * 200)),
      node("far", T0 + 20 * 60_000),
    ];
    const plan = planTimeline(nodes, { width: 1440, height: 900 });
    const cluster = plan.placed.filter((p) => p.id.startsWith("n"));
    expect(new Set(cluster.map((p) => p.y)).size).toBe(6);
  });
});

describe("a stack stays inside its lane", () => {
  it("does not run a dense cluster into the lane below", () => {
    // #1440's opening cluster stacked twelve deep at a fixed 30px step and
    // ran through the next lane, which reads as nodes in the wrong lane
    // rather than as a stack.
    const cluster = Array.from({ length: 12 }, (_, i) =>
      node(`c${i}`, T0 + i * 100, { attrs: { host: "h1" } }));
    const other = [
      node("far", T0 + 30 * 60_000, { attrs: { host: "h1" } }),
      node("b1", T0 + 60_000, { attrs: { host: "h2" } }),
    ];
    const plan = planTimeline([...cluster, ...other], { width: 1440, height: 900 });
    const lanes = new Map(plan.lanes.map((l) => [l.key, l.y]));
    const laneGap = Math.abs((lanes.get("h1") as number) - (lanes.get("h2") as number));

    const stacked = plan.placed.filter((p) => p.id.startsWith("c"));
    const lowest = Math.max(...stacked.map((p) => p.y));
    expect(lowest - (lanes.get("h1") as number)).toBeLessThan(laneGap);
  });

  it("still separates every node in the cluster", () => {
    const cluster = Array.from({ length: 8 }, (_, i) => node(`c${i}`, T0 + i * 100));
    const plan = planTimeline(
      [...cluster, node("far", T0 + 30 * 60_000)], { width: 1440, height: 900 },
    );
    const ys = plan.placed.filter((p) => p.id.startsWith("c")).map((p) => p.y);
    expect(new Set(ys).size).toBe(8);
  });

  it("does not spread a lone node away from its lane line", () => {
    const plan = planTimeline([node("only", T0)], { width: 1440, height: 900 });
    expect(plan.placed[0].y).toBe(plan.lanes[0].y);
    expect(plan.placed[0].stacked).toBe(false);
  });
});
