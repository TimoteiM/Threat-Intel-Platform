import { describe, expect, it } from "vitest";

import {
  ELLIPSIS,
  LABEL_MAX_PX,
  approximateMeasurer,
  canvasMeasurer,
  fitToWidth,
} from "./nodeLabel";

/**
 * A deliberately proportional measurer: 'W' is wide, 'i' is narrow, everything
 * else is in between. Character-count truncation cannot pass these.
 */
const WIDTHS: Record<string, number> = { W: 12, M: 11, i: 2, l: 2, ".": 3, " ": 3 };
const proportional = (text: string) =>
  [...text].reduce((sum, ch) => sum + (WIDTHS[ch] ?? 6), 0);

describe("fitToWidth", () => {
  it("leaves a name that fits completely alone, with no ellipsis", () => {
    const fitted = fitToWidth("PowerShell", 96, proportional);
    expect(fitted).toBe("PowerShell");
    expect(fitted).not.toContain(ELLIPSIS);
  });

  it("marks a truncation so a cut name is never read as the whole name", () => {
    const fitted = fitToWidth(
      "Match Legitimate Resource Name or Location",
      96,
      proportional,
    );
    expect(fitted.endsWith(ELLIPSIS)).toBe(true);
    expect(proportional(fitted)).toBeLessThanOrEqual(96);
  });

  it("cuts wide characters earlier than narrow ones at the same budget", () => {
    // The whole point. Both strings are 18 characters.
    const wide = fitToWidth("W".repeat(18), 96, proportional);
    const narrow = fitToWidth("i".repeat(18), 96, proportional);
    expect(narrow).toBe("i".repeat(18));             // 36px — fits whole
    expect(wide.endsWith(ELLIPSIS)).toBe(true);      // 216px — cut hard
    expect([...wide].filter((c) => c === "W").length).toBeLessThan(18);
  });

  it("never returns something wider than the budget", () => {
    const names = [
      "Match Legitimate Resource Name or Location",
      "Image File Execution Options Injection",
      "Deobfuscate/Decode Files or Information",
      "System Network Configuration Discovery",
      "Dynamic-link Library Injection",
      "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWW",
      "PowerShell",
      "",
    ];
    for (const name of names) {
      expect(proportional(fitToWidth(name, LABEL_MAX_PX, proportional)))
        .toBeLessThanOrEqual(LABEL_MAX_PX);
    }
  });

  it("returns an ellipsis alone rather than overflowing when nothing fits", () => {
    expect(fitToWidth("WWWW", 4, proportional)).toBe(ELLIPSIS);
  });

  it("does not leave a trailing space before the ellipsis", () => {
    const fitted = fitToWidth("Disable or Modify Tools", 60, proportional);
    expect(fitted).not.toContain(` ${ELLIPSIS}`);
  });

  it("handles an empty or missing name without throwing", () => {
    expect(fitToWidth("", 96, proportional)).toBe("");
    expect(fitToWidth(undefined as unknown as string, 96, proportional)).toBe("");
  });

  it("does not split a surrogate pair", () => {
    // Four astral characters at 6px each under a 14px budget.
    const fitted = fitToWidth("\u{1F600}\u{1F600}\u{1F600}", 14, proportional);
    expect(fitted).not.toContain("�");
    expect([...fitted].every((ch) => ch === "\u{1F600}" || ch === ELLIPSIS)).toBe(true);
  });

  it("is monotonic: a bigger budget never yields a shorter label", () => {
    const name = "System Network Configuration Discovery";
    let previous = 0;
    for (const budget of [20, 40, 60, 80, 100, 140, 400]) {
      const length = fitToWidth(name, budget, proportional).length;
      expect(length).toBeGreaterThanOrEqual(previous);
      previous = length;
    }
  });
});

describe("the measurers", () => {
  it("reports no real measurement available under jsdom", () => {
    // jsdom has no 2D text metrics. The point of the probe is that this
    // returns null instead of a measurer that says everything is 0px wide and
    // therefore that every label fits.
    expect(canvasMeasurer("10px sans-serif")).toBeNull();
  });

  it("the fallback is pessimistic rather than optimistic", () => {
    // 6px an character is wider than most lower-case glyphs, so a fallback
    // label gets cut short rather than overflowing its node.
    const approximate = approximateMeasurer();
    expect(approximate("iiiiiiiiii")).toBeGreaterThan(proportional("iiiiiiiiii"));
  });

  it("the fallback still bounds the label", () => {
    const approximate = approximateMeasurer();
    const fitted = fitToWidth(
      "Match Legitimate Resource Name or Location",
      LABEL_MAX_PX,
      approximate,
    );
    expect(approximate(fitted)).toBeLessThanOrEqual(LABEL_MAX_PX);
    expect(fitted.endsWith(ELLIPSIS)).toBe(true);
  });
});
