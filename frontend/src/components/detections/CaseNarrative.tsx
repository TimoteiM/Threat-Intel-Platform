"use client";

/**
 * What happened, across the whole case.
 *
 * Every alert in a case already carries its own resolution, and the analyst can
 * still open each one — those are not replaced. What was missing was the single
 * account of the intrusion: eight verdicts about eight fragments left the
 * assembly work to the reader, which is the work the correlation was supposed
 * to have done.
 *
 * The verdict and the opening paragraph are shown without asking, because an
 * analyst scanning a list of cases needs the conclusion at a glance. The full
 * report is one click away rather than always expanded, so a page of cases
 * stays scannable.
 */

import React, { useMemo, useState } from "react";
import type { CorrelatedCase } from "@/lib/types";

const MONO: React.CSSProperties = {
  fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)",
};

function verdictTone(verdict: string): string {
  const value = verdict.toLowerCase();
  if (value.includes("malicious")) return "var(--status-danger)";
  if (value.includes("suspicious")) return "var(--status-warning)";
  if (value.includes("benign") || value.includes("false positive")) return "var(--status-success)";
  return "var(--text-secondary)";
}

/** The verdict line and the opening prose, pulled out of the report. */
function lead(markdown: string): { verdict: string | null; summary: string } {
  const verdictMatch = markdown.match(/\*\*\s*Verdict\s*:\s*([^*\n]+)\*\*/i);
  const verdict = verdictMatch ? verdictMatch[1].trim() : null;

  const body = markdown
    .replace(/^#+\s.*$/gm, "")
    .replace(/\*\*\s*Verdict\s*:\s*[^*\n]+\*\*/i, "")
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter((block) => block && !block.startsWith("|") && !block.startsWith("```"));

  return { verdict, summary: body.slice(0, 2).join("\n\n") };
}

export default function CaseNarrative({ item }: { item: CorrelatedCase }) {
  const [open, setOpen] = useState(false);
  const narrative = item.narrative;
  const parsed = useMemo(
    () => (narrative?.markdown ? lead(narrative.markdown) : null),
    [narrative?.markdown],
  );

  if (!narrative) return null;

  // No report yet. Said plainly rather than left blank: the case, its timeline
  // and every per-alert resolution are already correct without this.
  if (!narrative.markdown) {
    const failed = narrative.status === "failed";
    return (
      <div
        style={{
          fontSize: 11, color: failed ? "var(--status-warning)" : "var(--text-muted)",
          padding: "6px 0",
        }}
      >
        {failed
          ? `Case analysis could not be written (${narrative.error || "unknown error"}). The alerts below are unaffected.`
          : "Case analysis is being written — the alerts below are already complete."}
      </div>
    );
  }

  return (
    <div
      style={{
        border: "1px solid var(--panel-divider)",
        borderLeft: `3px solid ${parsed?.verdict ? verdictTone(parsed.verdict) : "var(--accent)"}`,
        borderRadius: 9,
        background: "var(--panel-card-bg)",
        padding: "12px 14px",
        display: "grid",
        gap: 9,
      }}
    >
      <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: 10.5, letterSpacing: 0.5, color: "var(--text-muted)",
          }}
        >
          CASE ANALYSIS
        </span>
        {parsed?.verdict && (
          <strong
            style={{
              ...MONO, fontSize: 11.5, color: verdictTone(parsed.verdict),
              textTransform: "uppercase", letterSpacing: 0.3,
            }}
          >
            {parsed.verdict}
          </strong>
        )}
        {narrative.status === "stale" && (
          <span style={{ fontSize: 10.5, color: "var(--status-warning)" }}>
            new alerts have joined since this was written
          </span>
        )}
        <span style={{ marginLeft: "auto", display: "flex", gap: 10 }}>
          {narrative.assistant_session_id && (
            <a
              href={`/assistant?session=${narrative.assistant_session_id}`}
              target="_blank"
              rel="noreferrer"
              style={{ fontSize: 10.5, color: "var(--accent)", textDecoration: "none" }}
            >
              open in assistant
            </a>
          )}
          <button
            type="button"
            onClick={() => setOpen((current) => !current)}
            style={{
              background: "none", border: "none", padding: 0, cursor: "pointer",
              fontSize: 10.5, color: "var(--accent)", fontFamily: "inherit",
            }}
          >
            {open ? "collapse" : "read the full analysis"}
          </button>
        </span>
      </div>

      {!open && parsed?.summary && (
        <p
          style={{
            margin: 0, fontSize: 12, lineHeight: 1.6, color: "var(--text-secondary)",
            whiteSpace: "pre-wrap",
          }}
        >
          {parsed.summary}
        </p>
      )}

      {open && (
        <pre
          style={{
            margin: 0, fontSize: 11.5, lineHeight: 1.65, whiteSpace: "pre-wrap",
            wordBreak: "break-word", color: "var(--text-secondary)",
            fontFamily: "inherit", maxHeight: 620, overflowY: "auto",
          }}
        >
          {narrative.markdown}
        </pre>
      )}
    </div>
  );
}
