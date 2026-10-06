"use client";

/**
 * Which fields the log table shows, and which rows it shows.
 *
 * The table had six fixed columns — time, agent, agent IP, domain, channel,
 * rule description — while every event already carried the rest of its
 * document in `fields`: command lines, parent process, logon ids, SIDs, the
 * subject account. An analyst could see those only by expanding one row at a
 * time, which is not how you compare twelve events.
 *
 * The six stay the default, because they are what makes a window scannable.
 * Anything else the loaded documents actually contain can be added, and the
 * field list is built from those documents rather than from a fixed catalogue
 * — a Sysmon window and a Security-channel window do not carry the same keys,
 * and a list that promises fields the events do not have is worse than a short
 * one.
 */

import React, { useMemo, useState } from "react";
import type { AlertLogEvent } from "@/lib/api";

/** The columns the table starts with. */
export const DEFAULT_COLUMNS = [
  "timestamp",
  "delta",
  "agent.name",
  "agent.ip",
  "domain",
  "channel",
  "rule.description",
] as const;

const LABELS: Record<string, string> = {
  timestamp: "Time",
  delta: "Δ",
  "agent.name": "Agent",
  "agent.ip": "Agent IP",
  domain: "Domain",
  channel: "System Channel",
  "rule.description": "Rule Description",
  "rule.id": "Rule ID",
  "rule.level": "Level",
  event_id: "Event ID",
  users: "User",
  "process.image": "Process",
  "process.command_line": "Command line",
  "network.src_ip": "Source IP",
  "network.dst_ip": "Destination IP",
  full_log: "Raw log",
  location: "Location",
  "decoder.name": "Decoder",
  "manager.name": "Manager",
};

/** Structured fields worth offering even when `fields` does not repeat them. */
const STRUCTURED = [
  "rule.id", "rule.level", "event_id", "users",
  "process.image", "process.command_line",
  "network.src_ip", "network.dst_ip",
  "location", "full_log",
];

function humanise(segment: string): string {
  return segment.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
}

/**
 * A readable name for a field.
 *
 * The tail segment alone, because `data.win.eventdata.parentProcessName` is a
 * path and "Parent Process Name" is a column heading. `peers` is the set the
 * label has to be distinguishable *within* — a real window of 98 events threw
 * up three collisions: `users` against `data.win.eventdata.user`,
 * `process.command_line` against `data.win.eventdata.commandLine`, and
 * `data.win.eventdata.processId` against `data.win.system.processID` (the
 * subject's process and the envelope's — different numbers, same words).
 *
 * Comparison is on the *rendered* label, normalised, not on the tail: `Id` and
 * `ID` collide for a reader even though the paths differ. A curated name is
 * never the one that pays — it keeps its short form and the raw path gets the
 * section, so the common case stays readable.
 */
const normaliseLabel = (text: string) => text.toLowerCase().replace(/[^a-z0-9]/g, "");

function baseLabel(field: string): string {
  if (LABELS[field]) return LABELS[field];
  return humanise(field.split(".").pop() || field);
}

export function labelFor(field: string, peers?: readonly string[]): string {
  const base = baseLabel(field);
  if (LABELS[field] || !peers) return base;
  const parts = field.split(".");
  if (parts.length < 2) return base;
  const key = normaliseLabel(base);
  const collides = peers.some((p) => p !== field && normaliseLabel(baseLabel(p)) === key);
  return collides ? `${base} (${parts[parts.length - 2]})` : base;
}

/** One event's value for a field, whether it is structured or in the map. */
export function valueOf(event: AlertLogEvent, field: string): string {
  const ev = event as unknown as Record<string, any>;
  switch (field) {
    case "timestamp":
      return String(ev.timestamp ?? "");
    case "agent.name":
      return String(ev.agent?.name ?? "");
    case "agent.ip":
      return String(ev.agent?.ip ?? "");
    case "manager.name":
      return String(ev.manager?.name ?? ev.manager ?? "");
    case "decoder.name":
      return String(ev.decoder?.name ?? ev.decoder ?? "");
    case "rule.description":
      return String(ev.rule?.description ?? "");
    case "rule.id":
      return String(ev.rule?.id ?? "");
    case "rule.level":
      return ev.rule?.level == null ? "" : String(ev.rule.level);
    case "users":
      return Array.isArray(ev.users) ? ev.users.join(", ") : String(ev.users ?? "");
    case "process.image":
      return String(ev.process?.image ?? "");
    case "process.command_line":
      return String(ev.process?.command_line ?? "");
    case "network.src_ip":
      return String(ev.network?.src_ip ?? "");
    case "network.dst_ip":
      return String(ev.network?.dst_ip ?? "");
    default:
      break;
  }
  if (field in ev && typeof ev[field] !== "object") return String(ev[field] ?? "");
  const found = (ev.fields as Array<{ name: string; value: unknown }> | undefined)?.find(
    (f) => f.name === field,
  );
  return found ? String(found.value ?? "") : "";
}

/** Every field the loaded documents actually carry, ordered for a picker. */
export function availableFields(events: AlertLogEvent[]): string[] {
  const seen = new Set<string>(DEFAULT_COLUMNS.filter((c) => c !== "delta"));
  for (const field of STRUCTURED) {
    if (events.some((e) => valueOf(e, field))) seen.add(field);
  }
  for (const event of events) {
    for (const f of ((event as any).fields || []) as Array<{ name: string }>) {
      if (f?.name) seen.add(f.name);
    }
  }
  const all = Array.from(seen);
  return all.sort((a, b) => labelFor(a, all).localeCompare(labelFor(b, all)));
}

export type FieldFilter = { field: string; value: string };

export function matchesFilters(event: AlertLogEvent, filters: FieldFilter[]): boolean {
  // Every condition must hold. Narrowing is the point — an OR would widen a
  // window an analyst opened to narrow.
  return filters.every((f) => {
    if (!f.field || !f.value) return true;
    return valueOf(event, f.field).toLowerCase().includes(f.value.toLowerCase());
  });
}

export default function LogFieldControls({
  events,
  columns,
  onColumns,
  filters,
  onFilters,
}: {
  events: AlertLogEvent[];
  columns: string[];
  onColumns: (next: string[]) => void;
  filters: FieldFilter[];
  onFilters: (next: FieldFilter[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const fields = useMemo(() => availableFields(events), [events]);
  // A window carries ~95 selectable fields (median, measured over the stored
  // windows). Scrolling a flat list of 95 chips to find `logonId` is not
  // finding it, so the list is searchable by label and by path.
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return fields;
    return fields.filter(
      (f) => f.toLowerCase().includes(q) || labelFor(f, fields).toLowerCase().includes(q),
    );
  }, [fields, query]);

  // Values actually present for the field being filtered, so an analyst picks
  // rather than guesses at spelling.
  const valuesFor = (field: string) => {
    const seen = new Set<string>();
    for (const e of events) {
      const v = valueOf(e, field);
      if (v) seen.add(v);
      if (seen.size > 40) break;
    }
    return Array.from(seen).sort();
  };

  const toggle = (field: string) =>
    onColumns(columns.includes(field) ? columns.filter((c) => c !== field) : [...columns, field]);

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button type="button" onClick={() => setOpen((v) => !v)} style={btn}>
          {open ? "Hide fields" : `Fields (${columns.length} shown of ${fields.length + 1})`}
        </button>
        <button
          type="button"
          onClick={() => onFilters([...filters, { field: fields[0] || "", value: "" }])}
          style={btn}
        >
          + Filter
        </button>
        {(columns.length !== DEFAULT_COLUMNS.length || filters.length > 0) && (
          <button
            type="button"
            onClick={() => {
              onColumns([...DEFAULT_COLUMNS]);
              onFilters([]);
            }}
            style={{ ...btn, color: "var(--text-dim)" }}
          >
            Reset
          </button>
        )}
      </div>

      {open && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
            padding: 10,
            border: "1px solid var(--border)",
            borderRadius: 10,
            maxHeight: 220,
            overflow: "auto",
          }}
        >
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Search ${fields.length} fields…`}
            style={{ ...input, flexBasis: "100%", minWidth: 0 }}
            aria-label="Search available fields"
          />
          {shown.length === 0 && (
            <span style={{ fontSize: 11.5, color: "var(--text-dim)" }}>
              No field in these events matches “{query}”.
            </span>
          )}
          {shown.map((field) => {
            const on = columns.includes(field);
            return (
              <label
                key={field}
                title={field}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  fontSize: 11.5,
                  padding: "3px 8px",
                  borderRadius: 999,
                  border: `1px solid ${on ? "var(--accent)" : "var(--border)"}`,
                  color: on ? "var(--text)" : "var(--text-dim)",
                  cursor: "pointer",
                }}
              >
                <input type="checkbox" checked={on} onChange={() => toggle(field)} />
                {labelFor(field, fields)}
              </label>
            );
          })}
        </div>
      )}

      {filters.map((filter, index) => (
        <div key={index} style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          <select
            value={filter.field}
            onChange={(e) => {
              const next = [...filters];
              next[index] = { field: e.target.value, value: "" };
              onFilters(next);
            }}
            style={input}
            aria-label="Field to filter on"
          >
            {fields.map((f) => (
              <option key={f} value={f}>
                {labelFor(f, fields)}
              </option>
            ))}
          </select>
          <input
            list={`vals-${index}`}
            value={filter.value}
            placeholder="contains…"
            onChange={(e) => {
              const next = [...filters];
              next[index] = { ...next[index], value: e.target.value };
              onFilters(next);
            }}
            style={{ ...input, minWidth: 220 }}
            aria-label="Value to match"
          />
          <datalist id={`vals-${index}`}>
            {valuesFor(filter.field).map((v) => (
              <option key={v} value={v} />
            ))}
          </datalist>
          <button
            type="button"
            onClick={() => onFilters(filters.filter((_, i) => i !== index))}
            style={{ ...btn, color: "var(--text-dim)" }}
            aria-label="Remove this filter"
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}

const btn: React.CSSProperties = {
  border: "1px solid var(--border)",
  background: "transparent",
  color: "var(--text)",
  borderRadius: 999,
  padding: "5px 12px",
  fontSize: 12,
  cursor: "pointer",
};

const input: React.CSSProperties = {
  borderRadius: 8,
  border: "1px solid var(--panel-divider-strong, var(--border))",
  background: "var(--panel-card-bg, transparent)",
  color: "var(--text-strong, var(--text))",
  padding: "5px 8px",
  fontSize: 12.5,
};
