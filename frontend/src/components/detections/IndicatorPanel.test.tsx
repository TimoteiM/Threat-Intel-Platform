import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IndicatorPanel, isAbsent } from "./IndicatorPanel";

/**
 * The payloads below are what `graph_for_runs` actually returns for case
 * #1440, copied from `app.cli.case_graph 1440 --json`. Measured, not invented:
 * the URL reads malicious while the domain it sits on reads benign, the
 * address carries an abuse score of 100 with ThreatFox never having answered,
 * and all three were answered 38 days ago.
 */

const ADDRESS = {
  value: "185.220.101.47",
  kind: "ip",
  abuse_score: 100,
  isp: "Example Hosting",
  country_code: "DE",
  threatfox: {
    absent: true,
    kind: "check_failed",
    reason:
      "ThreatFox has not been reachable for this lookup, so nothing was " +
      "checked against it. The stored count reads 0 for every address in this " +
      "estate and means 'not asked', not 'no hits'.",
  },
  investigated: {
    absent: true,
    kind: "never_observed",
    reason:
      "Addresses are not investigated by this platform: of 2,488 " +
      "investigations, none has an `ip` observable type. This is how the " +
      "pipeline is built, not a missing record.",
  },
  queried_at: "2026-09-03T11:21:48.908521+00:00",
  age_days: 38,
  stale: true,
};

const URL_MALICIOUS = {
  value: "http://185.220.101.47/a",
  kind: "url",
  classification: "malicious",
  confidence: 0.92,
  risk_score: 88,
  recommended_action: "block",
  queried_at: "2026-09-03T11:24:26.599528+00:00",
  age_days: 38,
  stale: true,
};

const DOMAIN_BENIGN = { ...URL_MALICIOUS, classification: "benign", risk_score: 17 };

const NEVER_INVESTIGATED = {
  value: "odsvc.exe",
  kind: "file",
  investigated: {
    absent: true,
    kind: "unclassified",
    reason:
      "No investigation has been run on this indicator. Coverage is 83.4% of " +
      "URLs and 35.9% of domains, so an absence here is ordinary and is not " +
      "evidence that it is harmless.",
  },
};

describe("an absence is shown as its reason", () => {
  it("never renders a failed ThreatFox check as a count", () => {
    // This node carries two absences — the broken feed and the pipeline that
    // does not cover addresses — so the query names which one it means.
    const { container } = render(<IndicatorPanel data={ADDRESS} />);
    const feed = container.querySelector('[data-absent="check_failed"]');
    expect(feed?.textContent).toMatch(/not known/i);
    expect(feed?.textContent).toMatch(/ThreatFox has not been reachable/);
    expect(screen.queryByText("0")).toBeNull();
  });

  it("names which kind of absence it is, so the reasons stay distinct", () => {
    const { container } = render(<IndicatorPanel data={ADDRESS} />);
    const kinds = Array.from(container.querySelectorAll("[data-absent]")).map(
      (n) => n.getAttribute("data-absent"));
    // A feed that broke and a pipeline that never covers addresses are
    // different facts, and an analyst acts differently on each.
    expect(kinds).toContain("check_failed");
    expect(kinds).toContain("never_observed");
  });

  it("does not read an uninvestigated indicator as harmless", () => {
    const { container } = render(<IndicatorPanel data={NEVER_INVESTIGATED} />);
    const shown = container.querySelector('[data-absent="unclassified"]');
    expect(shown?.textContent).toMatch(/No investigation has been run/);
  });

  it("recognises the wire shape", () => {
    expect(isAbsent({ absent: true, kind: "x", reason: "y" })).toBe(true);
    expect(isAbsent(0)).toBe(false);
    expect(isAbsent(null)).toBe(false);
    expect(isAbsent({ kind: "x" })).toBe(false);
  });
});

describe("an answer's age is part of the answer", () => {
  it("shows the timestamp verbatim and marks it stale past 30 days", () => {
    render(<IndicatorPanel data={ADDRESS} />);
    const age = screen.getByTestId("answer-age");
    expect(age.textContent).toContain("2026-09-03 11:21:48");
    expect(age.textContent).toContain("38 days ago");
    expect(age.textContent).toMatch(/worth re-checking/);
  });

  it("does not nag about a fresh answer", () => {
    render(<IndicatorPanel data={{ ...ADDRESS, age_days: 3, stale: false }} />);
    expect(screen.getByTestId("answer-age").textContent).not.toMatch(/re-checking/);
  });

  it("says nothing about age when nothing was answered", () => {
    render(<IndicatorPanel data={NEVER_INVESTIGATED} />);
    expect(screen.queryByTestId("answer-age")).toBeNull();
  });
});

describe("verdict is its own channel", () => {
  it("shows a malicious verdict and a benign one as what they are", () => {
    const { unmount } = render(<IndicatorPanel data={URL_MALICIOUS} />);
    expect(screen.getByText("malicious")).toBeTruthy();
    unmount();
    render(<IndicatorPanel data={DOMAIN_BENIGN} />);
    expect(screen.getByText("benign")).toBeTruthy();
  });

  it("keeps the score beside the verdict rather than instead of it", () => {
    // On #1440 the URL is malicious at 88 and the domain benign at 17.
    // Collapsing either pair into one badge loses half the statement.
    render(<IndicatorPanel data={URL_MALICIOUS} />);
    expect(screen.getByText("malicious")).toBeTruthy();
    expect(screen.getByText("88")).toBeTruthy();
    expect(screen.getByText("block")).toBeTruthy();
  });

  it("shows an abuse score of zero as a real result", () => {
    // AbuseIPDB stores NULL when it fails, so 0 means "not abusive" — and
    // 3,117 rows say it. Unlike ThreatFox, this zero is a measurement.
    render(<IndicatorPanel data={{ ...ADDRESS, abuse_score: 0 }} />);
    expect(screen.getByText("0")).toBeTruthy();
  });
});

describe("an absence that cannot be resolved by looking", () => {
  // 1,040 of the 1,173 ip nodes drawn in case graphs are private or reserved.
  // The panel used to tell an analyst a missing lookup on 10.x was "unusual
  // rather than normal", which is an instruction to go and find a record that
  // no feed has ever held.
  const privateAddress = {
    value: "10.1.1.4",
    kind: "ip",
    looked_up: {
      absent: true,
      kind: "out_of_scope",
      reason:
        "This is a private or reserved address, so no reputation service " +
        "has an opinion about it and none was asked. Its meaning comes " +
        "from which host it is, not from a feed.",
      raw: null,
    },
  };

  it("opens with 'not applicable', not 'not known'", () => {
    const { container } = render(<IndicatorPanel data={privateAddress} />);
    const cell = container.querySelector('[data-absent="out_of_scope"]');
    expect(cell).not.toBeNull();
    expect(cell!.textContent).toContain("not applicable");
    expect(cell!.textContent).not.toContain("not known");
  });

  it("still says 'not known' for a kind it has no opinion about", () => {
    const { container } = render(
      <IndicatorPanel
        data={{
          value: "8.8.8.8",
          kind: "ip",
          looked_up: {
            absent: true,
            kind: "some_kind_added_later",
            reason: "Something else happened.",
            raw: null,
          },
        }}
      />,
    );
    const cell = container.querySelector('[data-absent="some_kind_added_later"]');
    expect(cell!.textContent).toContain("not known");
  });
});
