"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { getCorrelatedCases } from "@/lib/api";
import type { CorrelatedCase } from "@/lib/types";

/**
 * What a single alert cannot tell you, said where you cannot miss it.
 *
 * A case forms when several independent detections land on one entity inside a
 * window. Nobody watches for that by opening alerts one at a time, which is
 * exactly why chains go unseen — so the count lives in the top bar and follows
 * you between pages.
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

export default function CorrelationAlerts() {
  const [cases, setCases] = useState<CorrelatedCase[]>([]);
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

  const count = cases.length;
  const worst = cases.reduce((max, item) => Math.max(max, item.score), 0);
  const tone = worst >= 70 ? "var(--status-danger)" : "var(--status-warning)";

  return (
    <div ref={panel} style={{ position: "relative" }}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-label={
          count
            ? `${count} correlated case${count === 1 ? "" : "s"} in the last ${WINDOW_HOURS} hours`
            : "No correlated cases"
        }
        aria-expanded={open}
        title={
          count
            ? `${count} entity/entities with several independent detections in ${WINDOW_HOURS}h`
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
          background: count ? "rgba(251, 191, 36, 0.10)" : "transparent",
          color: count ? tone : "var(--text-muted)",
          fontSize: 11.5,
          fontWeight: count ? 700 : 500,
          cursor: "pointer",
        }}
      >
        <span aria-hidden>◆</span>
        {count > 0 ? `${count} correlated` : "No cases"}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Correlated cases"
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
            firing repeatedly is not a case.
          </div>

          {failed && (
            <div style={{ fontSize: 12, color: "var(--status-warning)" }}>
              Correlation could not be read just now — this is not a statement that nothing is
              happening.
            </div>
          )}

          {!failed && count === 0 && (
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
              key={`${item.source}:${item.client}:${item.entity_host}`}
              href={`/alert-investigations/${item.alerts[item.alerts.length - 1]?.run_id ?? ""}`}
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
