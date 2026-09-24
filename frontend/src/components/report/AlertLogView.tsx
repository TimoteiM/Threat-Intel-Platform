"use client";

/**
 * The SIEM events around an alert, as an analyst reads them.
 *
 * Two things this view exists to keep distinct, because conflating them is how
 * an analyst comes to trust a verdict more than it deserves:
 *
 *   what was RETRIEVED  — everything in the ±10-minute window, all of it here
 *   what was SENT to AI — a ranked subset, marked, never the default filter
 *
 * A row that was not sent is not a row that was judged unimportant. The banner
 * says so, and the "sent to AI" filter is opt-in rather than the starting state.
 *
 * The alert itself is a marker in the timeline, not a boundary: events before
 * and after it read in one chronological list so a chain is visible as a chain.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";

import { getAlertLogs, reanalyseWithLogContext, type AlertLogEvent, type AlertLogPage } from "@/lib/api";

const PAGE_SIZE = 100;

function ts(value?: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function offsetOf(eventTime?: string | null, alertTime?: string | null): number | null {
  if (!eventTime || !alertTime) return null;
  const a = new Date(eventTime.replace(/([+-]\d{2})(\d{2})$/, "$1:$2")).getTime();
  const b = new Date(alertTime).getTime();
  if (Number.isNaN(a) || Number.isNaN(b)) return null;
  return Math.round((a - b) / 1000);
}

function relative(seconds: number | null): string {
  if (seconds === null) return "";
  const sign = seconds < 0 ? "−" : "+";
  const abs = Math.abs(seconds);
  if (abs < 60) return `${sign}${abs}s`;
  return `${sign}${Math.floor(abs / 60)}m ${abs % 60}s`;
}

const levelColour = (level?: number | null): string => {
  const n = Number(level ?? 0);
  if (n >= 12) return "var(--danger, #f85149)";
  if (n >= 7) return "var(--warning, #d29922)";
  return "var(--text-muted)";
};

export function AlertLogView({ runId }: { runId: string }) {
  const [page, setPage] = useState<AlertLogPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [side, setSide] = useState<"all" | "before" | "after">("all");
  const [minLevel, setMinLevel] = useState<number | undefined>(undefined);
  const [onlyRelevant, setOnlyRelevant] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQ(q);
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [q]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPage(
        await getAlertLogs(runId, {
          limit: PAGE_SIZE,
          offset,
          q: debouncedQ,
          side,
          min_level: minLevel,
          only_relevant: onlyRelevant,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the logs.");
    } finally {
      setLoading(false);
    }
  }, [runId, offset, debouncedQ, side, minLevel, onlyRelevant]);

  useEffect(() => {
    void load();
  }, [load]);

  const togglePin = (key: string) => {
    setPinned((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const requestReanalysis = async () => {
    setBusy(true);
    setNote(null);
    try {
      const result = await reanalyseWithLogContext(runId, Array.from(pinned));
      setNote(result.note);
    } catch (err) {
      setNote(err instanceof Error ? err.message : "Re-analysis could not be queued.");
    } finally {
      setBusy(false);
    }
  };

  const rows = page?.logs ?? [];
  const alertTime = page?.alert_time ?? null;

  // Where the alert falls in this page, so it can be drawn between two rows
  // rather than described in a caption.
  const markerIndex = useMemo(() => {
    if (!alertTime) return -1;
    const index = rows.findIndex((r) => (offsetOf(r.timestamp, alertTime) ?? 0) >= 0);
    return index;
  }, [rows, alertTime]);

  if (loading && !page) return <Muted>Loading the events around this alert…</Muted>;
  if (error) return <Muted>{error}</Muted>;
  if (!page) return null;

  if (page.status === "unavailable" || page.status === "skipped") {
    return (
      <div style={panel}>
        <strong style={{ color: "var(--text)" }}>No log context</strong>
        <Muted>{page.reason || "Log retrieval is not available for this alert."}</Muted>
      </div>
    );
  }

  const partial = page.window && !page.window.complete;
  const stale = (page.new_logs_since_analysis ?? 0) > 0;

  return (
    <div style={{ display: "grid", gap: 12 }}>
      {/* What this set is, and what it is not. */}
      <div style={{ ...panel, display: "grid", gap: 6 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "baseline" }}>
          <Fact label="Retrieved" value={`${page.retrieved_total} event${page.retrieved_total === 1 ? "" : "s"}`} />
          <Fact label="Ranked relevant" value={`${page.relevant_total ?? 0}`} />
          <Fact label="Sent to the AI" value={`${page.sent_to_ai_total}`} />
          <Fact label="Window" value={page.window ? `${ts(page.window.start)} → ${ts(page.window.end)}` : "—"} />
          {page.tenant_id && <Fact label="Client" value={page.tenant_id} mono />}
          {page.truncated && <Fact label="Retrieval limit" value="reached" />}
        </div>
        <Muted>
          Every retrieved event is listed here. <Chip>RELEVANT</Chip> is what the ranking judged
          worth your attention — advice, not a verdict, and nothing is sent to the AI because of it.
          <Chip>SENT</Chip> marks what actually reached the model. Select events and use
          &ldquo;Send to the AI&rdquo; to add any of them.
        </Muted>
        {page.truncated && (
          <Muted>
            The retrieval limit was reached, so this window held more events than were fetched.
          </Muted>
        )}
      </div>

      {(partial || stale || page.analysis_basis === "partial") && (
        <div style={{ ...panel, borderColor: "var(--warning, #d29922)" }}>
          <strong style={{ color: "var(--text)" }}>
            {stale ? "This analysis did not see all of these events" : "The window is still filling"}
          </strong>
          <Muted>
            {page.analysis_note ||
              "The alert is live and part of its window had not happened when the analysis ran."}
          </Muted>
          <div style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
            <button type="button" onClick={requestReanalysis} disabled={busy} style={primary(busy)}>
              {busy ? "Queueing…" : pinned.size > 0
                ? `Re-analyse with ${pinned.size} selected event${pinned.size === 1 ? "" : "s"}`
                : "Re-analyse with the complete context"}
            </button>
            <Muted>The current verdict is kept, not overwritten.</Muted>
          </div>
          {note && <Muted>{note}</Muted>}
        </div>
      )}

      {/* Filters. */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search message, rule, device, user, command line…"
          style={input}
          aria-label="Search events"
        />
        <select value={side} onChange={(e) => { setSide(e.target.value as any); setOffset(0); }} style={input}>
          <option value="all">Before and after</option>
          <option value="before">Before the alert</option>
          <option value="after">After the alert</option>
        </select>
        <select
          value={minLevel ?? ""}
          onChange={(e) => { setMinLevel(e.target.value ? Number(e.target.value) : undefined); setOffset(0); }}
          style={input}
        >
          <option value="">Any rule level</option>
          <option value="7">Level 7+</option>
          <option value="10">Level 10+</option>
          <option value="12">Level 12+</option>
        </select>
        <label style={{ display: "flex", gap: 6, alignItems: "center", color: "var(--text-muted)", fontSize: 13 }}>
          <input
            type="checkbox"
            checked={onlyRelevant}
            onChange={(e) => { setOnlyRelevant(e.target.checked); setOffset(0); }}
          />
          Only relevant events
        </label>
        <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 13 }}>
          {page.filtered_total} matching
        </span>
      </div>

      {/* The timeline. */}
      <div style={{ overflowX: "auto", border: "1px solid var(--border)", borderRadius: 8 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr>
              {["", "Time", "Δ", "Device", "User", "Rule / event", "Message", "Source"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((event, index) => {
              const delta = offsetOf(event.timestamp, alertTime);
              const isExpanded = expanded === event.key;
              return (
                <React.Fragment key={event.key}>
                  {index === markerIndex && markerIndex >= 0 && (
                    <tr>
                      <td colSpan={8} style={markerRow}>
                        ▶ THIS ALERT — {ts(alertTime)}
                      </td>
                    </tr>
                  )}
                  <tr
                    onClick={() => setExpanded(isExpanded ? null : event.key)}
                    style={{ cursor: "pointer", background: isExpanded ? "var(--surface-2, transparent)" : undefined }}
                  >
                    <td style={td}>
                      <input
                        type="checkbox"
                        checked={pinned.has(event.key)}
                        onClick={(e) => e.stopPropagation()}
                        onChange={() => togglePin(event.key)}
                        aria-label="Select this event for re-analysis"
                      />
                    </td>
                    <td style={{ ...td, whiteSpace: "nowrap", fontFamily: "var(--font-mono, monospace)" }}>
                      {ts(event.timestamp)}
                    </td>
                    <td style={{ ...td, whiteSpace: "nowrap", color: "var(--text-muted)" }}>{relative(delta)}</td>
                    <td style={td}>{event.agent?.name || "—"}</td>
                    <td style={td}>{(event.users && event.users[0]) || "—"}</td>
                    <td style={td}>
                      <span style={{ color: levelColour(event.rule?.level) }}>
                        {event.rule?.id ? `#${event.rule.id}` : ""}{event.event_id ? ` · EID ${event.event_id}` : ""}
                      </span>
                      {event.rule?.level != null && (
                        <span style={{ color: "var(--text-muted)" }}> · L{event.rule.level}</span>
                      )}
                    </td>
                    <td style={{ ...td, maxWidth: 420 }}>
                      <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {event.rule?.description || event.full_log || "—"}
                      </span>
                    </td>
                    <td style={{ ...td, whiteSpace: "nowrap" }}>
                      {event.relevant && <Chip>RELEVANT</Chip>}
                      {event.sent_to_ai && <Chip>SENT</Chip>}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={8} style={{ ...td, background: "var(--surface-2, transparent)" }}>
                        <div style={{ display: "grid", gap: 6 }}>
                          <Fact label="OpenSearch reference" value={event.key} mono />
                          {event.process?.command_line && (
                            <Fact label="Command line" value={event.process.command_line} mono />
                          )}
                          {event.process?.image && <Fact label="Process" value={event.process.image} mono />}
                          {(event.network?.src_ip || event.network?.dst_ip) && (
                            <Fact
                              label="Network"
                              value={`${event.network?.src_ip || "?"} → ${event.network?.dst_ip || "?"}`}
                              mono
                            />
                          )}
                          {event.rule?.groups?.length ? (
                            <Fact label="Rule groups" value={event.rule.groups.join(", ")} />
                          ) : null}
                          {event.matched_on?.length ? (
                            <Fact label="Matched on" value={event.matched_on.join(", ")} />
                          ) : null}
                          {event.full_log && (
                            <pre style={pre}>{event.full_log}</pre>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} style={{ ...td, color: "var(--text-muted)" }}>
                  No events match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} style={secondary}>
          Previous
        </button>
        <span style={{ color: "var(--text-muted)", fontSize: 13 }}>
          {page.filtered_total === 0 ? "0" : `${offset + 1}–${Math.min(offset + PAGE_SIZE, page.filtered_total)}`} of {page.filtered_total}
        </span>
        <button type="button" disabled={!page.has_more} onClick={() => setOffset(offset + PAGE_SIZE)} style={secondary}>
          Next
        </button>
        {pinned.size > 0 && (
          <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 13 }}>
            {pinned.size} selected for re-analysis
          </span>
        )}
      </div>
    </div>
  );
}

const panel: React.CSSProperties = {
  border: "1px solid var(--border)",
  borderRadius: 8,
  padding: "10px 12px",
  display: "grid",
  gap: 4,
};
const th: React.CSSProperties = {
  textAlign: "left",
  padding: "8px 10px",
  borderBottom: "1px solid var(--border)",
  color: "var(--text-muted)",
  fontWeight: 600,
  fontSize: 12,
  textTransform: "uppercase",
  letterSpacing: "0.04em",
  whiteSpace: "nowrap",
};
const td: React.CSSProperties = {
  padding: "7px 10px",
  borderBottom: "1px solid var(--border)",
  verticalAlign: "top",
  color: "var(--text)",
};
const markerRow: React.CSSProperties = {
  padding: "6px 10px",
  background: "var(--accent-subtle, rgba(210,153,34,0.12))",
  color: "var(--warning, #d29922)",
  fontWeight: 600,
  fontSize: 12,
  letterSpacing: "0.04em",
  borderBottom: "1px solid var(--border)",
};
const input: React.CSSProperties = {
  padding: "6px 8px",
  border: "1px solid var(--border)",
  borderRadius: 6,
  background: "var(--surface, transparent)",
  color: "var(--text)",
  fontSize: 13,
  minWidth: 160,
};
const pre: React.CSSProperties = {
  margin: 0,
  padding: 8,
  background: "var(--surface, transparent)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  overflowX: "auto",
  fontSize: 12,
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
};
const primary = (disabled: boolean): React.CSSProperties => ({
  padding: "6px 12px",
  borderRadius: 6,
  border: "1px solid var(--border)",
  background: disabled ? "var(--surface, transparent)" : "var(--accent, #1f6feb)",
  color: disabled ? "var(--text-muted)" : "#fff",
  cursor: disabled ? "default" : "pointer",
  fontSize: 13,
});
const secondary: React.CSSProperties = {
  padding: "6px 12px",
  borderRadius: 6,
  border: "1px solid var(--border)",
  background: "var(--surface, transparent)",
  color: "var(--text)",
  cursor: "pointer",
  fontSize: 13,
};

function Muted({ children }: { children: React.ReactNode }) {
  return <span style={{ color: "var(--text-muted)", fontSize: 13 }}>{children}</span>;
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 6px",
        borderRadius: 999,
        border: "1px solid var(--border)",
        color: "var(--text-muted)",
        fontSize: 11,
        letterSpacing: "0.04em",
      }}
    >
      {children}
    </span>
  );
}

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "baseline" }}>
      <span style={{ color: "var(--text-muted)", fontSize: 12 }}>{label}</span>
      <span
        style={{
          color: "var(--text)",
          fontSize: 13,
          fontFamily: mono ? "var(--font-mono, monospace)" : undefined,
          wordBreak: mono ? "break-all" : undefined,
        }}
      >
        {value}
      </span>
    </span>
  );
}

export default AlertLogView;
