import { describe, expect, it } from "vitest";

import { EXTERNAL_BAND, planBands } from "./bands";

/**
 * The band rules, which shipped proven by a scratch Chromium harness and
 * therefore proven to nobody. Measured on the real component across eight
 * cases: 11 nodes sat outside the band named after them, and seven of the
 * eight drew at least one empty band — a bare node-sized rectangle on top of
 * whatever the layout had put there.
 */

type N = Parameters<typeof planBands>[0][number];

const node = (over: Partial<N> & Pick<N, "id" | "kind">): N => ({
  label: over.id,
  attrs: {},
  ...over,
}) as N;

const all = (...ids: string[]) => new Set(ids);

describe("which band a node belongs in", () => {
  it("puts the host node inside the band named after it", () => {
    // The first defect: the host sat beside its own band, never its child.
    const nodes = [node({ id: "h1", kind: "host", label: "exp-fin-034" })];
    const { parentOf, drawn } = planBands(nodes, all("h1"));
    expect(parentOf.get("h1")).toBe("band:h1");
    expect(drawn).toEqual(["band:h1"]);
  });

  it("joins a node to a band only on the host it names", () => {
    const nodes = [
      node({ id: "h1", kind: "host", label: "exp-fin-034" }),
      node({ id: "p1", kind: "process", attrs: { host: "exp-fin-034" } }),
    ];
    const { parentOf } = planBands(nodes, all("h1", "p1"));
    expect(parentOf.get("p1")).toBe("band:h1");
  });

  it("leaves a node outside every band when it names no host", () => {
    // Never inferred from a neighbour. A domain account and a technique
    // belong to no one machine, and guessing puts them somewhere false
    // rather than nowhere true.
    const nodes = [
      node({ id: "h1", kind: "host", label: "exp-fin-034" }),
      node({ id: "a1", kind: "account", label: "CORP\\jdoe" }),
      node({ id: "t1", kind: "technique", label: "T1055" }),
    ];
    const { parentOf } = planBands(nodes, all("h1", "a1", "t1"));
    expect(parentOf.has("a1")).toBe(false);
    expect(parentOf.has("t1")).toBe(false);
  });

  it("does not match a host by a near-miss name", () => {
    const nodes = [
      node({ id: "h1", kind: "host", label: "exp-fin-034" }),
      node({ id: "p1", kind: "process", attrs: { host: "exp-fin-0341" } }),
    ];
    expect(planBands(nodes, all("h1", "p1")).parentOf.has("p1")).toBe(false);
  });

  it.each(["domain", "ip", "url"])(
    "sends %s to attacker infrastructure, not to a machine we own",
    (kind) => {
      const nodes = [
        node({ id: "h1", kind: "host", label: "exp-fin-034" }),
        node({ id: "x", kind, attrs: { host: "exp-fin-034" } }),
      ];
      // Even when the alert names a host for it: an address is not host-local.
      expect(planBands(nodes, all("h1", "x")).parentOf.get("x")).toBe(EXTERNAL_BAND);
    },
  );
});

describe("which bands are drawn", () => {
  it("does not draw a band with no members", () => {
    // Seven of eight sampled cases drew one of these.
    const nodes = [
      node({ id: "h1", kind: "host", label: "exp-fin-034" }),
      node({ id: "h2", kind: "host", label: "exp-dc-01" }),
    ];
    // Only h1 is visible, so h2's band has nobody in it.
    const { drawn } = planBands(nodes, all("h1"));
    expect(drawn).toEqual(["band:h1"]);
  });

  it("draws the external band only when something is in it", () => {
    const nodes = [node({ id: "h1", kind: "host", label: "h" })];
    expect(planBands(nodes, all("h1")).drawn).not.toContain(EXTERNAL_BAND);

    const withIp = [...nodes, node({ id: "i1", kind: "ip", label: "1.2.3.4" })];
    expect(planBands(withIp, all("h1", "i1")).drawn).toContain(EXTERNAL_BAND);
  });

  it("every drawn band has at least one child", () => {
    // The invariant the whole module exists for, asserted directly.
    const nodes = [
      node({ id: "h1", kind: "host", label: "a" }),
      node({ id: "h2", kind: "host", label: "b" }),
      node({ id: "p1", kind: "process", attrs: { host: "a" } }),
      node({ id: "i1", kind: "ip", label: "8.8.8.8" }),
      node({ id: "t1", kind: "technique", label: "T1055" }),
    ];
    const visible = all("h1", "h2", "p1", "i1", "t1");
    const { parentOf, drawn } = planBands(nodes, visible);
    const members = new Set(parentOf.values());
    drawn.forEach((band) => expect(members.has(band)).toBe(true));
  });

  it("names each band after its host", () => {
    const nodes = [node({ id: "h1", kind: "host", label: "exp-fin-034" })];
    const { labelOf } = planBands(nodes, all("h1"));
    expect(labelOf.get("band:h1")).toBe("exp-fin-034");
    expect(labelOf.get(EXTERNAL_BAND)).toBeUndefined();
  });

  it("ignores nodes that are not visible", () => {
    // `pathOnly` hides everything off the selected path; a band must not be
    // drawn for a host whose children are all hidden.
    const nodes = [
      node({ id: "h1", kind: "host", label: "a" }),
      node({ id: "p1", kind: "process", attrs: { host: "a" } }),
    ];
    expect(planBands(nodes, all("p1")).drawn).toEqual(["band:h1"]);
    expect(planBands(nodes, new Set<string>()).drawn).toEqual([]);
  });
});
