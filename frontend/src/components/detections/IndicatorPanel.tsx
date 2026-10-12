import React from "react";

import type { AbsentValue } from "@/lib/api";

/**
 * What is known about one indicator, and what only looks known.
 *
 * Three rules, each paid for:
 *
 *  1. An absence renders as its reason, never as a blank or a zero.
 *     `threatfox_count` reads 0 for every address in this estate while that
 *     feed has not answered once — 6,371 of 6,371 lookups record
 *     `ThreatFox: HTTPError`. A zero there would be a measurement nobody made.
 *
 *  2. An answer's age is part of the answer. 63.9% of stored reputation
 *     lookups are more than 30 days old and the oldest is from March, so the
 *     timestamp is shown verbatim: "about a month ago" is a rounding of the
 *     thing that decides whether to re-check.
 *
 *  3. Verdict and corroboration are separate channels. The graph already says
 *     "claimed" with a dashed edge; a verdict is a different claim and gets
 *     its own line. On case #1440 the URL reads malicious while the domain it
 *     sits on reads benign, and collapsing those into one badge would lose the
 *     disagreement.
 */

export const isAbsent = (value: unknown): value is AbsentValue =>
  !!value && typeof value === "object" &&
  (value as { absent?: boolean }).absent === true;

/**
 * How an absence opens. "not known" is right for a question that was asked
 * and came back empty, and wrong for one that cannot be asked: a private
 * address has no reputation to be unknown, and telling an analyst it is "not
 * known" invites them to go and find it.
 *
 * Unlisted kinds fall back to "not known", which is the safe direction —
 * a kind this file has not heard of is one nobody can claim is inapplicable.
 */
const OPENING: Record<string, string> = {
  out_of_scope: "not applicable",
};

export function Absence({ value }: { value: AbsentValue }) {
  return (
    <span title={value.reason} style={{ color: "var(--text-subtle)" }} data-absent={value.kind}>
      {OPENING[value.kind] ?? "not known"} — {value.reason.split(". ")[0]}.
    </span>
  );
}

const ROWS: Array<[string, string]> = [
  ["verdict", "classification"],
  ["confidence", "confidence"],
  ["risk score", "risk_score"],
  ["recommended", "recommended_action"],
  ["abuse score", "abuse_score"],
  ["ThreatFox", "threatfox"],
  ["ISP", "isp"],
  ["country", "country_code"],
  ["investigated", "investigated"],
  ["looked up", "looked_up"],
];

export function IndicatorPanel({ data }: { data: Record<string, unknown> }) {
  const stale = data.stale === true;
  return (
    <div
      data-testid="indicator-panel"
      style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 8 }}
    >
      <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>what is known</div>
      {ROWS.map(([label, key]) => {
        const value = data[key];
        if (value === undefined) return null;
        return (
          <div key={key} style={{ display: "flex", gap: 8, marginTop: 3 }}>
            <span style={{ color: "var(--text-muted)", minWidth: 96 }}>{label}</span>
            <span style={{ wordBreak: "break-all" }}>
              {isAbsent(value) ? (
                <Absence value={value} />
              ) : Array.isArray(value) ? (
                value.length ? `${value.length} hit(s)` : "no hits"
              ) : (
                String(value ?? "—")
              )}
            </span>
          </div>
        );
      })}
      {data.queried_at ? (
        <div
          data-testid="answer-age"
          style={{ marginTop: 6, color: stale ? "#F59F00" : "var(--text-muted)" }}
        >
          answered {String(data.queried_at).replace("T", " ").slice(0, 19)} UTC
          {typeof data.age_days === "number" ? ` · ${data.age_days} days ago` : ""}
          {stale ? " · older than 30 days, worth re-checking" : ""}
        </div>
      ) : null}
    </div>
  );
}
