import { describe, expect, it } from "vitest";

import {
  EMPTY,
  POPULATED,
  RETIRED_TACTIC,
  UNPLACED,
  UNPLACED_LABEL,
  columnFor,
  planTactics,
} from "./tactics";

/** ATT&CK 19.2's own matrix order, as `attack.tactic_order` delivers it. */
const ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Stealth", "Defense Impairment",
  "Credential Access", "Discovery", "Lateral Movement", "Collection",
  "Command and Control", "Exfiltration", "Impact",
];

const plan = (tactics: (string | null)[], order = ORDER) =>
  planTactics({ tactics, order, attackVersion: "19.2" });

describe("the three absences, kept apart", () => {
  it("draws a tactic this case has nothing in — that is information", () => {
    // "Nothing in Exfiltration" is a statement about the incident. A graph
    // that omits the column says instead that nobody looked.
    const result = plan(["Execution", "Execution", "Discovery"]);
    const exfiltration = result.columns.find((c) => c.label === "Exfiltration");
    expect(exfiltration).toBeDefined();
    expect(exfiltration!.state).toBe(EMPTY);
    expect(exfiltration!.count).toBe(0);
  });

  it("does not draw a tactic this ATT&CK release no longer has", () => {
    // 19 split Defense Evasion. There is nothing to say about it except that
    // it is not a tactic, and an empty column would invite someone to ask why.
    const result = plan(["Defense Evasion", "Execution"]);
    expect(result.columns.map((c) => c.label)).not.toContain("Defense Evasion");
    expect(result.omitted).toEqual([
      { label: "Defense Evasion", reason: RETIRED_TACTIC },
    ]);
  });

  it("gives a node with no nameable technique its own column", () => {
    const result = plan(["Execution", null, null]);
    const unplaced = result.columns.find((c) => c.id === UNPLACED);
    expect(unplaced).toBeDefined();
    expect(unplaced!.label).toBe(UNPLACED_LABEL);
    expect(unplaced!.count).toBe(2);
  });

  it("never folds an unplaceable node into a real tactic", () => {
    // Guessing it into Execution would hide a finding about the data.
    const result = plan([null]);
    const execution = result.columns.find((c) => c.label === "Execution");
    expect(execution!.count).toBe(0);
    expect(execution!.state).toBe(EMPTY);
  });

  it("distinguishes an empty column from an omitted tactic", () => {
    // The two states this module exists to separate. Both are "no nodes
    // here"; only one is about the incident.
    const result = plan(["Defense Evasion"]);
    const empties = result.columns.filter((c) => c.state === EMPTY);
    expect(empties.length).toBe(ORDER.length);
    expect(result.omitted.map((o) => o.label)).toEqual(["Defense Evasion"]);
  });

  it("has no unplaced column when nothing is unplaceable", () => {
    const result = plan(["Execution"]);
    expect(result.columns.some((c) => c.id === UNPLACED)).toBe(false);
  });
});

describe("the columns themselves", () => {
  it("draws every tactic the release has, in the matrix order", () => {
    const result = plan(["Stealth"]);
    expect(result.columns.filter((c) => c.state !== UNPLACED).map((c) => c.label))
      .toEqual(ORDER);
  });

  it("places Stealth, which 18.6% of this estate's nodes resolve to", () => {
    // The regression this module prevents: swapping to catalogue tactics
    // without updating the columns dropped a fifth of technique nodes into
    // the gutter, and it would have presented as a layout bug.
    const result = plan(Array(6290).fill("Stealth"));
    const stealth = result.columns.find((c) => c.label === "Stealth");
    expect(stealth!.state).toBe(POPULATED);
    expect(stealth!.count).toBe(6290);
    expect(result.columns.find((c) => c.id === UNPLACED)).toBeUndefined();
  });

  it("counts nodes per tactic", () => {
    const result = plan(["Execution", "Execution", "Discovery"]);
    expect(result.columns.find((c) => c.label === "Execution")!.count).toBe(2);
    expect(result.columns.find((c) => c.label === "Discovery")!.count).toBe(1);
  });

  it("carries the ATT&CK version for the caption", () => {
    expect(plan(["Execution"]).attackVersion).toBe("19.2");
  });

  it("treats blank and whitespace tactics as unplaceable, not as a tactic", () => {
    const result = planTactics({ tactics: ["", "   ", undefined], order: ORDER });
    expect(result.columns.find((c) => c.id === UNPLACED)!.count).toBe(3);
    expect(result.omitted).toEqual([]);
  });
});

describe("a payload with no tactic order", () => {
  it("draws only what it can place, and invents no empties", () => {
    // Without knowing which tactics exist it cannot tell "nothing in
    // Exfiltration" from "Exfiltration is not a tactic any more". Declining
    // to draw the distinction beats inventing it.
    const result = planTactics({ tactics: ["Execution", "Discovery"], order: [] });
    expect(result.columns.map((c) => c.label)).toEqual(["Execution", "Discovery"]);
    expect(result.columns.every((c) => c.state === POPULATED)).toBe(true);
    expect(result.omitted).toEqual([]);
  });

  it("still separates the unplaceable nodes", () => {
    const result = planTactics({ tactics: ["Execution", null], order: [] });
    expect(result.columns.find((c) => c.id === UNPLACED)!.count).toBe(1);
  });

  it("does not report every tactic as retired when the order is missing", () => {
    // The dangerous failure: an older payload would otherwise omit every
    // column and report the whole matrix as retired.
    const result = planTactics({ tactics: ["Stealth", "Execution"], order: [] });
    expect(result.omitted).toEqual([]);
    expect(result.columns.length).toBe(2);
  });
});

describe("columnFor", () => {
  it("places a node in its tactic's column", () => {
    const result = plan(["Stealth"]);
    expect(columnFor("Stealth", result)).toBe("stealth");
    expect(columnFor("Command and Control", result)).toBe("command-and-control");
  });

  it("sends an unnameable node to the unplaced column", () => {
    const result = plan([null]);
    expect(columnFor(null, result)).toBe(UNPLACED);
    expect(columnFor("", result)).toBe(UNPLACED);
    expect(columnFor(undefined, result)).toBe(UNPLACED);
  });

  it("sends a node whose tactic this release lacks to the unplaced column", () => {
    // Not into a real column: that would assert a placement the catalogue
    // does not support.
    const result = plan(["Defense Evasion"]);
    expect(columnFor("Defense Evasion", result)).toBe(UNPLACED);
  });

  it("never returns a column that is not in the plan", () => {
    const result = plan(["Execution", null, "Defense Evasion"]);
    const ids = new Set(result.columns.map((c) => c.id));
    for (const tactic of ["Execution", "Stealth", "Defense Evasion", null, ""]) {
      expect(ids.has(columnFor(tactic, result))).toBe(true);
    }
  });
});
