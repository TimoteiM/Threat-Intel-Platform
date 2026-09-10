"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { getCorrelatedCases } from "@/lib/api";
import type { CorrelatedCase } from "@/lib/types";

/**
 * Cases the analyst has not read yet, said where they cannot miss it.
 *
 * A case forms when several independent detections land on one entity inside a
 * window. Nobody watches for that by opening alerts one at a time, which is
 * exactly why chains go unseen — so the count lives in the top bar and follows
 * you between pages.
 *
 * The badge counts what is *new*, not what exists. A number that never changes
 * as you work is a number you stop reading: it said "8 correlated" whether you
 * had looked at all eight or none of them. Opening the panel marks what it
 * lists as read, so the count falls to zero and rises again only when something
 * actually arrives.
 *
 * "Read" is remembered per browser, in localStorage. There is no account model
 * here, so it cannot be per analyst — two people at two machines each clear
 * their own. That is the honest limit of storing it client-side, and it is
 * better than a count that is permanently wrong for everyone.
 */

// How far back "now" reaches. Two days is the window an analyst is on shift for.
const WINDOW_HOURS = 48;
// Below this a case is two quiet rules agreeing, which is not worth interrupting
// anyone. The scores this produces run 45-95, so the bar sits just under the
// lowest real case rather than being a round number for its own sake.
const NOTIFY_ABOVE = 40;
// A case forms within a second of its second alert and is fully scored in
// about 90 seconds. A 60s poll meant the badge could be a minute behind an
// intrusion that had already finished correlating.
const POLL_MS = 30_000;
// Case keys already read, per browser. Keyed on case_key, which is derived from
// the session's first event time and survives a change of query window — so a
// case stays read tomorrow rather than reappearing as new.
const SEEN_KEY = "threat-analyzer.cases.seen";
// Enough to cover far more cases than a window ever holds, and bounded so the
// entry cannot grow without limit on a long-lived browser profile.
const SEEN_LIMIT = 500;

function readSeen(): string[] {
  try {
    const raw = window.localStorage.getItem(SEEN_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((k) => typeof k === "string") : [];
  } catch {
    // Private windows and blocked site data throw on access. A badge that
    // counts everything as new is worse than one that counts nothing as read,
    // so this fails towards showing the cases.
    return [];
  }
}

function writeSeen(keys: string[]): void {
  try {
    window.localStorage.setItem(SEEN_KEY, JSON.stringify(keys.slice(-SEEN_LIMIT)));
  } catch {
    // Nothing to do — the count simply stays as it was for this session.
  }
}

export default function CorrelationAlerts() {
  const [cases, setCases] = useState<CorrelatedCase[]>([]);
  const [seen, setSeen] = useState<string[]>([]);
  // Which were new at the moment the panel was opened. Kept so the markers stay
  // on screen while it is open, rather than vanishing under the cursor.
  const [newlyOpened, setNewlyOpened] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const [failed, setFailed] = useState(false);
  const panel = useRef<HTMLDivElement | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getCorrelatedCases({
        hours: WINDOW_HOURS,
        min_score: NOTIFY_ABOVE,
      });
      setCases(data.cases);
      setFailed(false);
    } catch {
      // A correlation outage must not break the header. Silence here is not the
      // same as "nothing is happening", so the panel says which it is.
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    // Read once on mount: localStorage does not exist during server rendering.
    setSeen(readSeen());
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const away = (event: MouseEvent) => {
      if (panel.current && !panel.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const seenSet = new Set(seen);
  const unread = cases.filter((item) => !seenSet.has(item.case_key));
  const count = unread.length;
  // The colour follows what is new, not what exists — a red badge above a list
  // of cases you have already read is the boy who cried wolf.
  const worst = unread.reduce((max, item) => Math.max(max, item.score), 0);

  const openPanel = () => {
    if (open) {
      setOpen(false);
      return;
    }
    // Opening is reading. Snapshot what was new so the markers survive the
    // panel being open, then record every listed case as read.
    setNewlyOpened(unread.map((item) => item.case_key));
    const merged = [...seen.filter((key) => !cases.some((c) => c.case_key === key)),
                    ...cases.map((item) => item.case_key)];
    setSeen(merged);
    writeSeen(merged);
    setOpen(true);
  };
  const tone = worst >= 70 ? "var(--status-danger)" : "var(--status-warning)";
  const toneBg = worst >= 70 ? "rgba(240, 112, 80, 0.1)" : "rgba(240, 160, 80, 0.1)";

  return (
    <div ref={panel} style={{ position: "relative" }}>
      <button
        type="button"
        onClick={openPanel}
        aria-label={
          count
            ? `${count} new case${count === 1 ? "" : "s"} in the last ${WINDOW_HOURS} hours`
            : "No new cases"
        }
        aria-expanded={open}
        title={
          count
            ? `${count} case${count === 1 ? "" : "s"} you have not read yet, from the last ${WINDOW_HOURS}h. Opening this marks them read.`
            : cases.length
              ? `All ${cases.length} case(s) in the last ${WINDOW_HOURS}h have been read`
              : `Nothing correlated in the last ${WINDOW_HOURS} hours`
        }
        style={{
          position: "relative",
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "4px 10px",
          borderRadius: 8,
          border: `1px solid ${count ? tone : "var(--panel-divider)"}`,
          background: count ? toneBg : "transparent",
          color: count ? tone : "var(--text-muted)",
          fontSize: 11.5,
          fontWeight: count ? 700 : 500,
          cursor: "pointer",
        }}
      >
        <span aria-hidden>◆</span>
        {count > 0 ? `${count} new` : cases.length ? "No new cases" : "No cases"}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="New correlated cases"
          style={{
            position: "absolute",
            right: 0,
            top: "calc(100% + 8px)",
            zIndex: 70,
            width: "min(430px, 88vw)",
            maxHeight: "62vh",
            overflowY: "auto",
            padding: 14,
            borderRadius: 12,
            border: "1px solid var(--panel-divider-strong)",
            background: "var(--panel-card-bg)",
            boxShadow: "var(--panel-shadow-card)",
            display: "grid",
            gap: 10,
          }}
        >
          <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
            Entities with several independent detections in the last {WINDOW_HOURS} hours. One rule
            firing repeatedly is not a case. Opening this list marks these as read.
          </div>

          {failed && (
            <div style={{ fontSize: 12, color: "var(--status-warning)" }}>
              Correlation could not be read just now — this is not a statement that nothing is
              happening.
            </div>
          )}

          {/* Keyed on how many cases exist, not on how many are unread — a list
              of cases you have already read is not an empty list. */}
          {!failed && cases.length === 0 && (
            <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
              Nothing correlated in this window.{" "}
              <a href="/detections" style={{ color: "var(--accent)" }}>
                Open Detections
              </a>{" "}
              to look further back.
            </div>
          )}

          {cases.map((item) => (
            <a
              // Keyed on the case. A host can hold several sessions, so
              // source:client:host collided and React kept stale rows.
              key={item.case_key}
              // To the case, not to one of its alerts. The panel exists to say
              // "these belong together"; sending the reader to a single member
              // is the view they already had.
              href={`/detections/cases/${item.case_key}`}
              style={{
                display: "grid",
                gap: 4,
                padding: "9px 11px",
                borderRadius: 9,
                border: "1px solid var(--panel-divider)",
                background: "var(--bg-elevated)",
                textDecoration: "none",
              }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                <strong style={{ color: "var(--text)", fontSize: 12.5 }}>{item.entity_host}</strong>
                {newlyOpened.includes(item.case_key) && (
                  <span
                    title="Not read before you opened this panel"
                    style={{
                      fontSize: 9.5, fontWeight: 700, letterSpacing: 0.4,
                      color: "var(--status-warning)",
                      border: "1px solid var(--status-warning)",
                      borderRadius: 4, padding: "0 4px",
                    }}
                  >
                    NEW
                  </span>
                )}
                <span
                  style={{
                    marginLeft: "auto",
                    color: item.score >= 70 ? "var(--status-danger)" : "var(--status-warning)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 11.5,
                  }}
                >
                  {item.score}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {item.alert_count} alerts · {item.distinct_rules} independent detections ·{" "}
                {item.source}
                {item.client && item.client !== "unknown" ? ` / ${item.client}` : ""}
              </div>
              {item.reasons[0] && (
                <div style={{ fontSize: 11, color: "var(--text-dim)" }}>{item.reasons[0]}</div>
              )}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
