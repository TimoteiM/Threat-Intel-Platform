import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { TECHNIQUE_PANEL_KEYS, TechniquePanel } from "./TechniquePanel";

/**
 * Payloads taken verbatim from `technique_naming_service.name_technique` on
 * the live catalogue, not hand-written. A hand-written fixture would drift
 * from what the server actually sends, which is the divergence this project
 * has paid for twice.
 */
const POWERSHELL = {
  id: "T1059.001",
  name: "Command and Scripting Interpreter: PowerShell",
  short_name: "PowerShell",
  tactic: "Execution",
  tactics: ["Execution"],
  url: "https://attack.mitre.org/techniques/T1059/001",
  evidenceable: true,
  retired: false,
  revoked: false,
  deprecated_without_replacement: false,
  revoked_by: null,
  current_equivalent: null,
  attack_version: "19.2",
  named_by: "rule_only",
};

const RETIRED = {
  id: "T1562.001",
  name: "Impair Defenses: Disable or Modify Tools",
  short_name: "Disable or Modify Tools",
  tactic: "Stealth",
  tactics: ["Stealth"],
  url: "https://attack.mitre.org/techniques/T1562/001",
  evidenceable: false,
  retired: true,
  revoked: true,
  deprecated_without_replacement: false,
  revoked_by: "T1685",
  current_equivalent: "T1685",
  attack_version: "19.2",
  retirement:
    "Retired in ATT&CK 19.2. Current equivalent T1685 (Disable or Modify " +
    "Tools). A detection that mapped to this id mapped correctly for the " +
    "ATT&CK of its day.",
  named_by: "model_only",
};

const UNNAMEABLE = {
  id: "T9999",
  attack_version: "19.2",
  named_by: "rule_only",
  name: {
    absent: true,
    kind: "unrecognised_absence",
    raw: "T9999",
    reason:
      "This id is not in the bundled ATT&CK catalogue (Enterprise 19.2), so " +
      "this platform cannot say what it is. The id is shown as it was " +
      "recorded rather than guessed at or hidden: an id in our data that " +
      "ATT&CK does not have is a finding about the data.",
  },
};

describe("naming a technique", () => {
  it("shows the full ATT&CK name the node had no room for", () => {
    const { getByTestId } = render(<TechniquePanel attrs={POWERSHELL} />);
    expect(getByTestId("technique-panel").textContent).toContain(
      "Command and Scripting Interpreter: PowerShell",
    );
  });

  it("shows the tactic, from the catalogue rather than a local map", () => {
    const { getByTestId } = render(<TechniquePanel attrs={RETIRED} />);
    // 19 split Defense Evasion; the frontend's old map said defense-evasion.
    expect(getByTestId("technique-panel").textContent).toContain("Stealth");
  });

  it("states which ATT&CK release the name came from", () => {
    const { getByTestId } = render(<TechniquePanel attrs={POWERSHELL} />);
    expect(getByTestId("technique-panel").textContent).toContain("19.2");
  });
});

describe("who named it", () => {
  it("says the rule claimed it when only the rule did", () => {
    const { container } = render(<TechniquePanel attrs={POWERSHELL} />);
    const cell = container.querySelector('[data-named-by="rule_only"]');
    expect(cell!.textContent).toContain("the detection rule");
  });

  it("says our analysis found it when no rule claimed it", () => {
    const { container } = render(<TechniquePanel attrs={RETIRED} />);
    const cell = container.querySelector('[data-named-by="model_only"]');
    expect(cell!.textContent).toContain("our analysis");
  });

  it("keeps a claim and a finding as different statements", () => {
    // 29,570 rule_only against 4,308 model_only. Collapsing them into one
    // word would merge what a rule asserted with what the telemetry showed.
    const rule = render(<TechniquePanel attrs={POWERSHELL} />).container;
    const model = render(<TechniquePanel attrs={RETIRED} />).container;
    expect(rule.querySelector('[data-named-by="rule_only"]')!.textContent).not.toBe(
      model.querySelector('[data-named-by="model_only"]')!.textContent,
    );
  });
});

describe("a retired id", () => {
  it("says it is retired and names what to search instead", () => {
    const { getByTestId } = render(<TechniquePanel attrs={RETIRED} />);
    const text = getByTestId("technique-retired").textContent || "";
    expect(text).toContain("Retired in ATT&CK 19.2");
    expect(text).toContain("T1685");
    expect(text).toContain("Search current ATT&CK for");
  });

  it("does not read as a judgement on the detection", () => {
    // 273 nodes on one case carry this id. A reader who sees "retired" 273
    // times and concludes their ruleset is broken has been misled by us.
    const { getByTestId } = render(<TechniquePanel attrs={RETIRED} />);
    const text = (getByTestId("technique-retired").textContent || "").toLowerCase();
    expect(text).toContain("mapped correctly for the att&ck of its day");
    for (const blame of ["wrong", "incorrect", "mistake", "error", "invalid"]) {
      expect(text).not.toContain(blame);
    }
  });

  it("still shows the id's own name, not the successor's", () => {
    const { getByTestId } = render(<TechniquePanel attrs={RETIRED} />);
    expect(getByTestId("technique-panel").textContent).toContain(
      "Impair Defenses: Disable or Modify Tools",
    );
  });

  it("shows no retirement block for a current technique", () => {
    const { queryByTestId } = render(<TechniquePanel attrs={POWERSHELL} />);
    expect(queryByTestId("technique-retired")).toBeNull();
  });
});

describe("an id ATT&CK does not have", () => {
  it("renders the absence rather than a blank or a guess", () => {
    const { container, getByTestId } = render(<TechniquePanel attrs={UNNAMEABLE} />);
    expect(container.querySelector('[data-absent="unrecognised_absence"]')).not.toBeNull();
    const text = getByTestId("technique-panel").textContent || "";
    expect(text).toContain("not in the bundled ATT&CK catalogue");
    expect(text).toContain("19.2");
  });

  it("invents no name, tactic or retirement for it", () => {
    const { getByTestId, queryByTestId } = render(<TechniquePanel attrs={UNNAMEABLE} />);
    const text = getByTestId("technique-panel").textContent || "";
    expect(text).not.toContain("tactic");
    expect(queryByTestId("technique-retired")).toBeNull();
  });
});

describe("the key list the attribute dump uses", () => {
  it("covers every field the panel presents, so none is shown twice", () => {
    for (const key of Object.keys({ ...POWERSHELL, ...RETIRED, ...UNNAMEABLE })) {
      if (key === "id") continue; // the heading shows the id
      expect(TECHNIQUE_PANEL_KEYS.has(key)).toBe(true);
    }
  });

  it("does not swallow attributes that belong in the dump", () => {
    // `named_by` is presented here, but severity and risk are not — they
    // belong to the generic rows and must keep showing.
    expect(TECHNIQUE_PANEL_KEYS.has("source_severity")).toBe(false);
    expect(TECHNIQUE_PANEL_KEYS.has("indicator_risk_score")).toBe(false);
  });
});
