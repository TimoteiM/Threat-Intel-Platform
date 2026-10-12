import { describe, expect, it } from "vitest";

import { stampLines } from "./exportStamp";

describe("the PNG caption", () => {
  it("names the ATT&CK release the technique names came from", () => {
    const lines = stampLines({ caseNumber: 1440, attackVersion: "19.2" });
    expect(lines[0]).toContain("Case #1440");
    expect(lines[0]).toContain("MITRE ATT&CK Enterprise 19.2");
  });

  it("says the release is not stated rather than inventing one", () => {
    // Not "unknown": a name with no release behind it cannot be checked
    // against anything, and that is the thing worth saying.
    const lines = stampLines({ caseNumber: 71, attackVersion: null });
    expect(lines[0]).toContain("ATT&CK release not stated");
    expect(lines[0]).not.toContain("unknown");
  });

  it("carries the retired count into the picture", () => {
    // An analyst reading the image should not have to open the JSON to find
    // out that some ids on it are retired.
    const lines = stampLines({ attackVersion: "19.2", retiredDrawn: 1 });
    expect(lines[1]).toContain("1 id retired in this release");
    expect(lines[1]).toContain("current equivalent");
  });

  it("carries the unnameable count, which is a finding about the data", () => {
    const lines = stampLines({ attackVersion: "19.2", unnameableDrawn: 2 });
    expect(lines[1]).toContain("2 ids not in the catalogue");
    expect(lines[1]).toContain("shown unnamed");
  });

  it("states both counts together when both apply", () => {
    const lines = stampLines({
      attackVersion: "19.2", retiredDrawn: 4, unnameableDrawn: 2,
    });
    expect(lines[1]).toContain("4 ids retired");
    expect(lines[1]).toContain("2 ids not in the catalogue");
  });

  it("says nothing about counts that are zero", () => {
    const lines = stampLines({
      caseNumber: 1440, attackVersion: "19.2", retiredDrawn: 0, unnameableDrawn: 0,
    });
    expect(lines.length).toBe(1);
  });

  it("singularises one and pluralises more", () => {
    expect(stampLines({ retiredDrawn: 1 })[1]).toContain("1 id retired");
    expect(stampLines({ retiredDrawn: 4 })[1]).toContain("4 ids retired");
  });

  it("carries the export time when given one, and never invents it", () => {
    expect(stampLines({ attackVersion: "19.2" }).join(" ")).not.toContain("exported");
    const lines = stampLines({ attackVersion: "19.2", exportedAt: "2026-10-12 15:40 UTC" });
    expect(lines[lines.length - 1]).toBe("exported 2026-10-12 15:40 UTC");
  });

  it("still names the graph when there is no case number", () => {
    expect(stampLines({ attackVersion: "19.2" })[0]).toContain("Case graph");
  });
});
