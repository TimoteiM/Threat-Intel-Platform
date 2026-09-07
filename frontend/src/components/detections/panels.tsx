"use client";

/**
 * The panels a machine's story is told in, shared by the device window and the
 * case page.
 *
 * Extracted rather than copied: the two surfaces answer different questions —
 * "what is this machine" and "what happened in this case" — but they draw the
 * same evidence, and a second copy of a timeline or a counted list is a second
 * place for them to start disagreeing about what the numbers mean.
 */

import React, { useMemo } from "react";
import type { EntityProfile } from "@/lib/types";

export const MONO: React.CSSProperties = {
  fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)",
};

/** Risk to colour, used identically everywhere so one hue always means one thing. */
export function riskColor(risk: number): string {
  if (risk >= 70) return "var(--status-danger)";
  if (risk >= 40) return "var(--status-warning)";
  return "var(--text-muted)";
}

export function verdictColor(verdict: string | null): string {
  const value = (verdict || "").toLowerCase();
  if (value === "malicious") return "var(--status-danger)";
  if (value === "suspicious") return "var(--status-warning)";
  if (value === "benign") return "var(--status-success)";
  return "var(--text-muted)";
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString(undefined, {
        month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
      });
}

/* ─── The shape of what happened, on the axis it happened on ─── */

/**
 * Alerts placed on event time, in lanes by tactic.
 *
 * Drawn rather than tabulated because the three things the case score measures
 * — where sessions break, whether behaviour advances through tactics, and
 * whether it arrived as a burst or a slow drip — are shapes. A table of the
 * same rows makes all three invisible.
 */
export function Timeline({ profile }: { profile: EntityProfile }) {
  const events = (profile.timeline || []).filter((item) => item.event_time);
  const lanes = useMemo(() => {
    const names = new Set<string>();
    for (const item of events) {
      if (item.tactics.length === 0) names.add("(no tactic evidenced)");
      for (const tactic of item.tactics) names.add(tactic);
    }
    return Array.from(names).slice(0, 9);
  }, [events]);

  if (events.length === 0) {
    return (
      <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
        No alert on this host carries an event time, so there is nothing to place
        on a time axis.
      </div>
    );
  }

  const times = events.map((item) => new Date(item.event_time as string).getTime());
  const min = Math.min(...times);
  const max = Math.max(...times);
  const span = Math.max(1, max - min);

  const width = 1000;
  const laneHeight = 26;
  const padLeft = 150;
  const padTop = 14;
  const padBottom = 26;
  const height = padTop + lanes.length * laneHeight + padBottom;
  const plotWidth = width - padLeft - 24;

  const x = (iso: string) =>
    padLeft + ((new Date(iso).getTime() - min) / span) * plotWidth;

  // Four ticks, enough to read the span without crowding the axis.
  const ticks = [0, 1, 2, 3].map((index) => {
    const at = min + (span * index) / 3;
    return { at, left: padLeft + (plotWidth * index) / 3 };
  });

  return (
    <div style={{ overflowX: "auto" }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", minWidth: 560, height: "auto", display: "block" }}
        role="img"
        aria-label={`Alerts on ${profile.host} over time, grouped by ATT&CK tactic`}
      >
        {/* Session bands: where this platform considers one stretch of activity
            to have started and stopped. Drawn behind the alerts so the
            boundaries read as context rather than as data points. */}
        {(profile.sessions || []).map((session) => {
          if (!session.started_at || !session.last_activity_at) return null;
          const left = x(session.started_at);
          const right = Math.max(left + 2, x(session.last_activity_at));
          return (
            <rect
              key={session.case_key}
              x={left}
              y={padTop - 6}
              width={right - left}
              height={lanes.length * laneHeight + 8}
              fill="var(--accent)"
              opacity={0.07}
            />
          );
        })}

        {lanes.map((lane, index) => {
          const y = padTop + index * laneHeight + laneHeight / 2;
          return (
            <g key={lane}>
              <line
                x1={padLeft} y1={y} x2={width - 24} y2={y}
                stroke="var(--panel-divider)" strokeWidth={1} opacity={0.5}
              />
              <text
                x={padLeft - 10} y={y + 3.5} textAnchor="end"
                fontSize={10.5} fill="var(--text-secondary)"
              >
                {lane.length > 22 ? `${lane.slice(0, 21)}…` : lane}
              </text>
            </g>
          );
        })}

        {events.map((item) => {
          const laneNames = item.tactics.length ? item.tactics : ["(no tactic evidenced)"];
          return laneNames.map((lane) => {
            const index = lanes.indexOf(lane);
            if (index < 0) return null;
            return (
              <circle
                key={`${item.run_id}:${lane}`}
                cx={x(item.event_time as string)}
                cy={padTop + index * laneHeight + laneHeight / 2}
                r={item.risk >= 70 ? 4 : 3}
                fill={verdictColor(item.verdict)}
                opacity={0.75}
              >
                <title>
                  {`${item.rule}\n${shortDate(item.event_time)}\n${item.verdict || "no verdict"} · risk ${item.risk}`}
                </title>
              </circle>
            );
          });
        })}

        {ticks.map((tick) => (
          <text
            key={tick.at}
            x={tick.left}
            y={height - 8}
            textAnchor="middle"
            fontSize={9.5}
            fill="var(--text-muted)"
          >
            {shortDate(new Date(tick.at).toISOString())}
          </text>
        ))}
      </svg>
    </div>
  );
}

/* ─── A counted list with the count drawn, not just written ─── */

export function CountedRows({
  rows,
  emptyLabel,
}: {
  rows: Array<{ label: string; count: number; risk?: number; hint?: string }>;
  emptyLabel: string;
}) {
  if (rows.length === 0) {
    return <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{emptyLabel}</div>;
  }
  const most = Math.max(...rows.map((row) => row.count));
  return (
    <div style={{ display: "grid", gap: 5 }}>
      {rows.map((row) => (
        <div key={row.label} style={{ display: "grid", gap: 3 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
            <span
              style={{
                fontSize: 11.5, color: "var(--text-secondary)", flex: 1,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}
              title={row.hint || row.label}
            >
              {row.label}
            </span>
            <span
              style={{
                ...MONO, fontSize: 11,
                color: row.risk !== undefined ? riskColor(row.risk) : "var(--text)",
              }}
            >
              {row.count}
            </span>
          </div>
          <div style={{ height: 3, background: "var(--panel-divider)", borderRadius: 2 }}>
            <div
              style={{
                width: `${Math.max(2, (row.count / most) * 100)}%`,
                height: "100%", borderRadius: 2,
                background: row.risk !== undefined ? riskColor(row.risk) : "var(--accent)",
                opacity: 0.7,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export function Panel({ title, hint, children }: {
  title: string; hint?: string; children: React.ReactNode;
}) {
  return (
    <div
      style={{
        background: "var(--panel-card-bg)", border: "1px solid var(--panel-divider)",
        borderRadius: 10, padding: "12px 14px", display: "grid", gap: 8,
      }}
    >
      <div style={{ display: "grid", gap: 2 }}>
        <strong style={{ fontSize: 11.5, color: "var(--text)", letterSpacing: 0.3 }}>
          {title}
        </strong>
        {hint && (
          <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{hint}</span>
        )}
      </div>
      {children}
    </div>
  );
}

