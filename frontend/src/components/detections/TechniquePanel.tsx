import React from "react";

import { Absence, isAbsent } from "./IndicatorPanel";

/**
 * What a technique node is, for the side panel.
 *
 * The node itself has room for the id, a truncated name and one word of
 * status. Everything that needs a sentence lives here: the full ATT&CK name,
 * who named the technique, and — when ATT&CK has retired the id — what to
 * search for instead.
 *
 * Three things this panel is careful about.
 *
 * **Retirement is a fact about the id, not a verdict on the detection.** 273
 * nodes on one case carry T1562.001. A reader who sees "retired" 273 times
 * and concludes their ruleset is broken has been misled by us. The wording
 * comes from the server (`attrs.retirement`) so one sentence is used
 * everywhere, and it ends by saying the detection mapped correctly for the
 * ATT&CK of its day.
 *
 * **Who named it is never collapsed.** A rule asserting a technique and our
 * analysis supporting one are different claims: 29,570 nodes are the rule's
 * alone, 4,308 are ours alone, and 12 are both. Showing a single "technique"
 * would merge a claim with a finding.
 *
 * **An id ATT&CK does not have is shown, not hidden.** `name` itself carries
 * an absence typed `unrecognised_absence` with the raw value — the same shape
 * as `abuse_score` on an indicator — and renders through the same `Absence`
 * component as every other absence in this UI.
 */

const line: React.CSSProperties = { display: "flex", gap: 8, marginTop: 3 };
const key: React.CSSProperties = { color: "var(--text-muted)", minWidth: 96 };

/** Who put this technique on the graph. Two namers, never merged into one. */
const NAMED_BY: Record<string, { label: string; detail: string }> = {
  rule_only: {
    label: "the detection rule",
    detail:
      "The rule's author mapped it in advance. This platform has not " +
      "corroborated it from the telemetry.",
  },
  model_only: {
    label: "our analysis",
    detail:
      "The telemetry supports this technique and no rule claimed it. A " +
      "finding, not a corroboration.",
  },
  both: {
    label: "rule and telemetry",
    detail:
      "The rule claimed it and the telemetry supports it. 12 technique " +
      "nodes in this estate are in this state.",
  },
};

export function TechniquePanel({ attrs }: { attrs: Record<string, unknown> }) {
  const naming = attrs.name;
  const version = typeof attrs.attack_version === "string" ? attrs.attack_version : null;

  // The id could not be named. Everything below depends on a name, so this is
  // the whole panel: the absence, and the version it was looked up against.
  if (isAbsent(naming)) {
    return (
      <div data-testid="technique-panel" style={{ marginTop: 10 }}>
        <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>ATT&amp;CK</div>
        <Absence value={naming} />
        {version ? (
          <div style={{ ...line, color: "var(--text-subtle)", marginTop: 6 }}>
            looked up against ATT&amp;CK {version}
          </div>
        ) : null}
      </div>
    );
  }

  const name = typeof attrs.name === "string" ? attrs.name : null;
  const tactic = typeof attrs.tactic === "string" ? attrs.tactic : null;
  const url = typeof attrs.url === "string" ? attrs.url : null;
  const namedBy = typeof attrs.named_by === "string" ? NAMED_BY[attrs.named_by] : undefined;
  const retired = attrs.retired === true;
  const retirement = typeof attrs.retirement === "string" ? attrs.retirement : null;
  const equivalent =
    typeof attrs.current_equivalent === "string" ? attrs.current_equivalent : null;
  const equivalentName =
    typeof attrs.current_equivalent_name === "string" ? attrs.current_equivalent_name : null;
  const equivalentUrl =
    typeof attrs.current_equivalent_url === "string" ? attrs.current_equivalent_url : null;

  return (
    <div data-testid="technique-panel" style={{ marginTop: 10 }}>
      <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>ATT&amp;CK</div>

      {name ? (
        <div style={line}>
          <span style={key}>name</span>
          <span style={{ wordBreak: "break-word" }}>{name}</span>
        </div>
      ) : null}

      {tactic ? (
        <div style={line}>
          <span style={key}>tactic</span>
          <span>{tactic}</span>
        </div>
      ) : null}

      {namedBy ? (
        <div style={line}>
          <span style={key}>named by</span>
          <span title={namedBy.detail} data-named-by={String(attrs.named_by)}>
            {namedBy.label}
          </span>
        </div>
      ) : null}

      {retired ? (
        <div
          data-testid="technique-retired"
          style={{
            marginTop: 8,
            padding: 8,
            borderLeft: "3px solid var(--text-subtle)",
            color: "var(--text-muted)",
          }}
        >
          {/* Server-supplied, so the node, the panel, the CLI and the
              outbound document all say the same thing about the same id. */}
          {retirement}
          {equivalent ? (
            <div style={{ marginTop: 6 }} data-testid="technique-equivalent">
              {/* Named, not just numbered. Where every technique on a case is
                  retired — 8 of the 11 affected cases — this line is the only
                  valid ATT&CK framing left on the page, and a bare id would
                  send the analyst off to look it up, which is the complaint
                  this whole thread started from. */}
              Current guidance:{" "}
              {equivalentUrl ? (
                <a href={equivalentUrl} target="_blank" rel="noreferrer" style={{ color: "inherit" }}>
                  <strong>{equivalent}</strong>
                  {equivalentName ? ` — ${equivalentName}` : null}
                </a>
              ) : (
                <>
                  <strong>{equivalent}</strong>
                  {equivalentName ? ` — ${equivalentName}` : null}
                </>
              )}
            </div>
          ) : null}
        </div>
      ) : null}

      <div style={{ ...line, color: "var(--text-subtle)", marginTop: 8 }}>
        <span>
          {version ? `ATT&CK ${version}` : "ATT&CK"}
          {url ? (
            <>
              {" · "}
              <a href={url} target="_blank" rel="noreferrer" style={{ color: "inherit" }}>
                attack.mitre.org
              </a>
            </>
          ) : null}
        </span>
      </div>
    </div>
  );
}

/**
 * Keys `TechniquePanel` presents properly, so the generic attribute dump below
 * it does not repeat them as raw rows. Declared rather than inferred, so
 * adding a resolved field is a decision about where it is shown.
 */
export const TECHNIQUE_PANEL_KEYS = new Set([
  "name",
  "short_name",
  "tactic",
  "tactics",
  "url",
  "retired",
  "revoked",
  "revoked_by",
  "current_equivalent",
  "current_equivalent_name",
  "current_equivalent_url",
  "deprecated_without_replacement",
  "retirement",
  "attack_version",
  "named_by",
  "evidenceable",
]);
