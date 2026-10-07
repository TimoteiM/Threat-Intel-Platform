"use client";

/**
 * One time-window control, for every page that has a window.
 *
 * Presets for the common question, and an explicit range for the precise one.
 * The range inputs are `datetime-local`, not `date`: "between 14:05 and 14:20
 * yesterday" is a real question on an estate taking a few hundred alerts a
 * day, and a date-only control cannot ask it — a whole day was the finest cut
 * available, which on the busiest day is most of the data.
 *
 * An explicit range wins over the preset rather than combining with it: an
 * analyst who typed times meant them, and silently intersecting the two
 * answers a question nobody asked.
 */

import React from "react";

export type Window = {
  /** Hours back from now. Ignored while an explicit range is set. */
  hours: number;
  /** ISO-8601, local to the browser, minute precision. */
  since: string;
  until: string;
};

export const WINDOW_PRESETS = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "48h", hours: 48 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
  { label: "90d", hours: 2160 },
  // Two years. Retention decides what this actually reaches; the point is
  // that nothing is hidden by the control.
  { label: "All", hours: 17520 },
] as const;

export default function TimeWindow({
  value,
  onChange,
  label = "Time window",
}: {
  value: Window;
  onChange: (next: Window) => void;
  label?: string;
}) {
  const custom = Boolean(value.since || value.until);

  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
      <div role="group" aria-label={label} style={{ display: "flex", gap: 4 }}>
        {WINDOW_PRESETS.map((preset) => {
          const on = !custom && value.hours === preset.hours;
          return (
            <button
              key={preset.label}
              type="button"
              aria-pressed={on}
              // Picking a preset clears the range, so the control always
              // shows the window actually in effect.
              onClick={() => onChange({ hours: preset.hours, since: "", until: "" })}
              style={{
                padding: "4px 11px",
                borderRadius: 7,
                fontSize: 12,
                cursor: "pointer",
                border: `1px solid ${on ? "var(--accent)" : "var(--panel-divider-strong)"}`,
                background: on ? "var(--accent-subtle, rgba(56,139,253,0.16))" : "transparent",
                color: on ? "var(--text)" : "var(--text-muted)",
              }}
            >
              {preset.label}
            </button>
          );
        })}
      </div>

      <label style={stamp}>
        <span style={stampLabel}>from</span>
        <input
          type="datetime-local"
          value={value.since}
          onChange={(e) => onChange({ ...value, since: e.target.value })}
          aria-label="From, to the minute"
          style={input}
        />
      </label>
      <label style={stamp}>
        <span style={stampLabel}>to</span>
        <input
          type="datetime-local"
          value={value.until}
          onChange={(e) => onChange({ ...value, until: e.target.value })}
          aria-label="To, to the minute"
          style={input}
        />
      </label>

      {custom && (
        <button
          type="button"
          onClick={() => onChange({ hours: value.hours, since: "", until: "" })}
          style={{
            padding: "4px 10px", borderRadius: 7, fontSize: 11.5, cursor: "pointer",
            border: "1px solid var(--panel-divider-strong)",
            background: "transparent", color: "var(--text-muted)",
          }}
        >
          Clear range
        </button>
      )}
    </div>
  );
}

const stamp: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 5,
};

const stampLabel: React.CSSProperties = {
  fontSize: 10.5,
  letterSpacing: 0.4,
  textTransform: "uppercase",
  color: "var(--text-dim)",
};

const input: React.CSSProperties = {
  borderRadius: 8,
  border: "1px solid var(--panel-divider-strong, var(--border))",
  background: "var(--panel-card-bg, transparent)",
  color: "var(--text-strong, var(--text))",
  padding: "4px 8px",
  fontSize: 12,
  colorScheme: "dark light",
};

/**
 * A `datetime-local` value as an instant the server can agree with.
 *
 * The input hands back wall-clock text with no zone — "2026-10-07T10:00" —
 * and the API reads a naive timestamp as UTC. An analyst in Bucharest asking
 * for 10:00 was therefore served 13:00 their time: the window was silently
 * three hours out, which on a one-hour range means the wrong alerts entirely
 * and no sign that anything went wrong.
 *
 * `new Date` parses the zoneless form as local time, which is what the
 * analyst meant, and `toISOString` states it as the instant it is.
 */
export function toInstant(value: string | undefined): string {
  const text = String(value || "").trim();
  if (!text) return "";
  const at = new Date(text);
  return Number.isNaN(at.getTime()) ? "" : at.toISOString();
}
