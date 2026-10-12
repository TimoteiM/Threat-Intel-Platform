import { describe, expect, it } from "vitest";

import { centreOf, panToCentre, recentre } from "./viewport";

/**
 * The regression this restores: v1 had zoom and fit-to-view and the move to
 * Cytoscape dropped the controls. The subtler half is that entering
 * fullscreen, leaving it, or opening the side panel changes the frame without
 * changing the graph — and Cytoscape notices a window resize but not its
 * container changing size, so the drawing jumped.
 */

describe("keeping the analyst's place across a resize", () => {
  it("keeps the same model point under the centre", () => {
    const before = { width: 800, height: 600 };
    const after = { width: 1600, height: 900 };
    const zoom = 2;
    const pan = { x: -100, y: -50 };

    const was = centreOf(before, zoom, pan);
    const moved = recentre(before, after, zoom, pan);
    expect(centreOf(after, zoom, moved)).toEqual(was);
  });

  it("does not change zoom, so a bigger frame shows more rather than larger", () => {
    // Fitting is a separate, explicit action — the whole point of keeping
    // `fit` on its own button.
    const pan = recentre(
      { width: 800, height: 600 }, { width: 1600, height: 1200 }, 1.5, { x: 10, y: 20 },
    );
    // The pan moved by exactly half the growth, which is what "same scale,
    // more visible" means.
    expect(pan).toEqual({ x: 10 + 400, y: 20 + 300 });
  });

  it("is a no-op when the frame did not change", () => {
    const size = { width: 1024, height: 768 };
    const pan = { x: -33, y: 71 };
    expect(recentre(size, size, 1.25, pan)).toEqual(pan);
  });

  it("survives a frame shrinking as well as growing", () => {
    const big = { width: 1920, height: 1080 };
    const small = { width: 640, height: 480 };
    const zoom = 0.75;
    const pan = { x: 5, y: -5 };
    const there = recentre(big, small, zoom, pan);
    // And back again returns to where it started.
    expect(recentre(small, big, zoom, there)).toEqual(pan);
  });

  it("round-trips through the centre at any zoom", () => {
    const size = { width: 1280, height: 720 };
    for (const zoom of [0.1, 0.5, 1, 2.5, 10]) {
      const pan = { x: 123, y: -456 };
      expect(panToCentre(size, zoom, centreOf(size, zoom, pan))).toEqual(pan);
    }
  });
});
