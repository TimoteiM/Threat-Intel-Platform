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

import React, { useState } from "react";
import * as api from "@/lib/api";
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

export default function CaseNarrative({ item }: { item: CorrelatedCase }) {
  const [open, setOpen] = useState(false);
  const [full, setFull] = useState<string | null>(null);
  const [loadingFull, setLoadingFull] = useState(false);
  const narrative = item.narrative;

  if (!narrative) return null;

  // The list carries the verdict and the opening paragraph; the rest is fetched
  // only when someone asks for it. Shipping every report to every row made the
  // response 63% text nobody had opened, on a list that refreshes every 30s.
  const expand = () => {
    setOpen(true);
    if (full || loadingFull) return;
    setLoadingFull(true);
    api
      .getCaseNarrative(item.case_key)
      .then((detail) => setFull(detail.markdown || ""))
      .catch(() => setFull("Could not load the full analysis."))
      .finally(() => setLoadingFull(false));
  };

  // No report yet. Said plainly rather than left blank: the case, its timeline
  // and every per-alert resolution are already correct without this.
  if (!narrative.has_full) {
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
        borderLeft: `3px solid ${narrative.verdict ? verdictTone(narrative.verdict) : "var(--accent)"}`,
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
        {narrative.verdict && (
          <strong
            style={{
              ...MONO, fontSize: 11.5, color: verdictTone(narrative.verdict),
              textTransform: "uppercase", letterSpacing: 0.3,
            }}
          >
            {narrative.verdict}
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
            onClick={() => (open ? setOpen(false) : expand())}
            style={{
              background: "none", border: "none", padding: 0, cursor: "pointer",
              fontSize: 10.5, color: "var(--accent)", fontFamily: "inherit",
            }}
          >
            {open ? "collapse" : "read the full analysis"}
          </button>
        </span>
      </div>

      {!open && narrative.lead && (
        <p
          style={{
            margin: 0, fontSize: 12, lineHeight: 1.6, color: "var(--text-secondary)",
            whiteSpace: "pre-wrap",
          }}
        >
          {narrative.lead}
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
          {loadingFull && !full ? "Loading the full analysis…" : full}
        </pre>
      )}
    </div>
  );
}
