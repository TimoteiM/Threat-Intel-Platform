"use client";

/**
 * The alert, in place, with the events either side of it.
 *
 * This is how an analyst actually reads a window: start at the thing that
 * fired, see a handful of events around it, and pull in more from whichever end
 * looks interesting. A flat page of a hundred rows makes you find the alert
 * before you can begin.
 *
 * Anchored on the alert's own OpenSearch document where its id is known, so the
 * highlighted row *is* the alert rather than the nearest event to its
 * timestamp. Where it is not in the retrieved set the anchor is synthesised at
 * the alert's own time and marked as such — the view is never anchorless, and
 * never silently pretends a neighbouring event is the alert.
 */

import React, { useCallback, useEffect, useState } from "react";

import {
  getAlertLogContext,
  reanalyseWithLogContext,
  type AlertLogContextPage,
  type AlertLogEvent,
} from "@/lib/api";

const STEP_DEFAULT = 5;

/**
 * The same 4-chars-per-token rule the server budgets with. An estimate, and
 * labelled as one — the point is that an analyst selecting thirty events can
 * see they are over budget before they spend a model call finding out.
 */
const CHARS_PER_TOKEN = 4;

function estimateTokens(events: AlertLogEvent[]): number {
  let chars = 0;
  for (const e of events) {
    chars +=
      JSON.stringify({
        ref: e.key,
        time: e.timestamp,
        device: e.agent?.name,
        user: e.users?.[0],
        rule: e.rule?.description,
        rule_id: e.rule?.id,
        level: e.rule?.level,
        event_id: e.event_id,
        process: e.process,
        network: e.network,
        log: e.full_log?.slice(0, 400),
      }).length;
  }
  return Math.ceil(chars / CHARS_PER_TOKEN);
}

function ts(value?: string | null): string {
  if (!value) return "—";
  const parsed = new Date(String(value).replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  if (Number.isNaN(parsed.getTime())) return String(value);
  const iso = parsed.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}`;
}

function delta(eventTime?: string | null, alertTime?: string | null): string {
  if (!eventTime || !alertTime) return "";
  const a = new Date(String(eventTime).replace(/([+-]\d{2})(\d{2})$/, "$1:$2")).getTime();
  const b = new Date(alertTime).getTime();
  if (Number.isNaN(a) || Number.isNaN(b)) return "";
  const s = Math.round((a - b) / 1000);
  if (s === 0) return "0s";
  const sign = s < 0 ? "−" : "+";
  const abs = Math.abs(s);
  return abs < 60 ? `${sign}${abs}s` : `${sign}${Math.floor(abs / 60)}m${abs % 60 ? ` ${abs % 60}s` : ""}`;
}

export function AlertLogContext({ runId }: { runId: string }) {
  const [page, setPage] = useState<AlertLogContextPage | null>(null);
  const [before, setBefore] = useState(STEP_DEFAULT);
  const [after, setAfter] = useState(STEP_DEFAULT);
  const [newerStep, setNewerStep] = useState(STEP_DEFAULT);
  const [olderStep, setOlderStep] = useState(STEP_DEFAULT);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPage(await getAlertLogContext(runId, before, after));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the surrounding events.");
    } finally {
      setLoading(false);
    }
  }, [runId, before, after]);

  useEffect(() => {
    void load();
  }, [load]);

  // Every event currently on screen, in the order it is drawn. "Select all"
  // means exactly what is displayed — expanding the window and selecting again
  // adds the newly shown ones rather than silently re-selecting everything.
  const displayed: AlertLogEvent[] = page
    ? [...[...page.after].reverse(), page.anchor, ...[...page.before].reverse()].filter(
        (e) => !(e as { synthetic?: boolean }).synthetic,
      )
    : [];
  const displayedKeys = displayed.map((e) => e.key);
  const allDisplayedPinned =
    displayedKeys.length > 0 && displayedKeys.every((k) => pinned.has(k));
  const someDisplayedPinned = displayedKeys.some((k) => pinned.has(k));

  const toggleAllDisplayed = () =>
    setPinned((current) => {
      const next = new Set(current);
      if (allDisplayedPinned) displayedKeys.forEach((k) => next.delete(k));
      else displayedKeys.forEach((k) => next.add(k));
      return next;
    });

  const selectedEvents = displayed.filter((e) => pinned.has(e.key));
  const selectedTokens = estimateTokens(selectedEvents);
  const budget = page?.ai_budget_tokens ?? 6000;
  const overBudget = selectedTokens > budget;

  const togglePin = (key: string) =>
    setPinned((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

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

  const hiddenNewer = Math.max(0, page.available_after - page.after.length);
  const hiddenOlder = Math.max(0, page.available_before - page.before.length);
  const stale = (page.new_logs_since_analysis ?? 0) > 0;

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "baseline" }}>
        <Fact label="Retrieved" value={`${page.retrieved_total} events in the window`} />
        <Fact label="Considered by AI" value={String(page.sent_to_ai_total)} />
        <Fact
          label="Showing"
          value={`${page.before.length} before · alert · ${page.after.length} after`}
        />
        {page.truncated && <Fact label="Retrieval limit" value="reached" />}
      </div>

      {(stale || page.analysis_basis === "partial") && (
        <div style={{ ...panel, borderColor: "var(--warning, #d29922)" }}>
          <strong style={{ color: "var(--text)" }}>
            {stale ? "This analysis did not see all of these events" : "The window is still filling"}
          </strong>
          <Muted>{page.analysis_note}</Muted>
          <div style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
            <button type="button" onClick={requestReanalysis} disabled={busy} style={primaryBtn(busy)}>
              {busy ? "Queueing…" : "Re-analyse with the complete context"}
            </button>
            <Muted>The current verdict is kept, not overwritten.</Muted>
          </div>
        </div>
      )}

      {/* Selection. Always present once something is picked, rather than only
          when the window is still filling — sending chosen events to the model
          is a thing an analyst does on any alert. */}
      {pinned.size > 0 && (
        <div
          style={{
            ...panel,
            borderColor: overBudget ? "var(--danger, #f85149)" : "var(--accent, #1f6feb)",
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: 12,
          }}
        >
          <strong style={{ color: "var(--text)" }}>
            {pinned.size} event{pinned.size === 1 ? "" : "s"} selected
          </strong>
          <span style={{ color: overBudget ? "var(--danger, #f85149)" : "var(--text-muted)", fontSize: 13 }}>
            ≈{selectedTokens.toLocaleString()} of {budget.toLocaleString()} token budget
            {overBudget ? " — over budget, the lowest-ranked will not fit" : ""}
          </span>
          <button type="button" onClick={() => setPinned(new Set())} style={secondaryBtn}>
            Clear
          </button>
          <button
            type="button"
            onClick={requestReanalysis}
            disabled={busy}
            style={{ ...primaryBtn(busy), marginLeft: "auto" }}
          >
            {busy ? "Queueing…" : `Send ${pinned.size} event${pinned.size === 1 ? "" : "s"} to the AI`}
          </button>
        </div>
      )}
      {note && <Muted>{note}</Muted>}

      {/* Newer end. */}
      <LoadBar
        direction="newer"
        step={newerStep}
        onStep={setNewerStep}
        hidden={hiddenNewer}
        onLoad={() => setAfter((n) => n + newerStep)}
      />

      <div style={{ overflowX: "auto", border: "1px solid var(--border)", borderRadius: 8 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr>
              <th style={{ ...th, width: 28 }}>
                <input
                  type="checkbox"
                  checked={allDisplayedPinned}
                  ref={(el) => {
                    // Indeterminate when only some of what is on screen is
                    // picked, so the control never claims more than it means.
                    if (el) el.indeterminate = someDisplayedPinned && !allDisplayedPinned;
                  }}
                  onChange={toggleAllDisplayed}
                  aria-label="Select every event shown"
                  title={
                    allDisplayedPinned
                      ? "Clear the events shown"
                      : `Select all ${displayedKeys.length} events shown`
                  }
                />
              </th>
              {["", "Time", "Δ", "Agent", "Agent IP", "Domain", "System Channel", "Rule Description", ""].map(
                (h, i) => (
                  <th key={`${h}-${i}`} style={th}>
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {/* Newest first, matching how the window reads top-down from the
                future into the past — the alert sits where it happened. */}
            {[...page.after].reverse().map((event) => (
              <Row
                key={event.key}
                event={event}
                alertTime={page.alert_time}
                expanded={expanded === event.key}
                onToggle={() => setExpanded(expanded === event.key ? null : event.key)}
                pinned={pinned.has(event.key)}
                onPin={() => togglePin(event.key)}
              />
            ))}

            <Row
              key={page.anchor.key}
              event={page.anchor}
              alertTime={page.alert_time}
              isAlert
              expanded={expanded === page.anchor.key}
              onToggle={() => setExpanded(expanded === page.anchor.key ? null : page.anchor.key)}
              pinned={pinned.has(page.anchor.key)}
              onPin={() => togglePin(page.anchor.key)}
            />

            {[...page.before].reverse().map((event) => (
              <Row
                key={event.key}
                event={event}
                alertTime={page.alert_time}
                expanded={expanded === event.key}
                onToggle={() => setExpanded(expanded === event.key ? null : event.key)}
                pinned={pinned.has(event.key)}
                onPin={() => togglePin(event.key)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Older end. */}
      <LoadBar
        direction="older"
        step={olderStep}
        onStep={setOlderStep}
        hidden={hiddenOlder}
        onLoad={() => setBefore((n) => n + olderStep)}
      />

      {page.anchor.synthetic && (
        <Muted>
          The alert&rsquo;s own document was not among the retrieved events, so the highlighted row is
          the alert itself, placed at its event time.
        </Muted>
      )}

    </div>
  );
}

function LoadBar({
  direction,
  step,
  onStep,
  hidden,
  onLoad,
}: {
  direction: "newer" | "older";
  step: number;
  onStep: (n: number) => void;
  hidden: number;
  onLoad: () => void;
}) {
  const exhausted = hidden <= 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <button
        type="button"
        onClick={onLoad}
        disabled={exhausted}
        style={{
          ...secondaryBtn,
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          opacity: exhausted ? 0.5 : 1,
          cursor: exhausted ? "default" : "pointer",
        }}
      >
        <span aria-hidden>{direction === "newer" ? "▲" : "▼"}</span> Load
      </button>
      <input
        type="number"
        min={1}
        max={200}
        value={step}
        onChange={(e) => onStep(Math.max(1, Math.min(200, Number(e.target.value) || 1)))}
        disabled={exhausted}
        style={{ ...numberInput, opacity: exhausted ? 0.5 : 1 }}
        aria-label={`How many ${direction} documents to load`}
      />
      <span style={{ color: "var(--text-muted)", fontSize: 13 }}>
        {direction} documents
        {exhausted
          ? direction === "newer"
            ? " — nothing newer in the window"
            : " — nothing older in the window"
          : ` (${hidden} more)`}
      </span>
    </div>
  );
}

function Row({
  event,
  alertTime,
  isAlert,
  expanded,
  onToggle,
  pinned,
  onPin,
}: {
  event: AlertLogEvent & { is_alert?: boolean; synthetic?: boolean };
  alertTime?: string | null;
  isAlert?: boolean;
  expanded: boolean;
  onToggle: () => void;
  pinned: boolean;
  onPin: () => void;
}) {
  const rowStyle: React.CSSProperties = isAlert
    ? {
        background: "var(--accent-subtle, rgba(56,139,253,0.16))",
        boxShadow: "inset 3px 0 0 var(--accent, #1f6feb)",
        cursor: "pointer",
      }
    : { cursor: "pointer", background: expanded ? "var(--surface-2, transparent)" : undefined };

  return (
    <>
      <tr onClick={onToggle} style={rowStyle}>
        <td style={{ ...td, width: 28 }} onClick={(e) => e.stopPropagation()}>
          {!event.synthetic && (
            <input
              type="checkbox"
              checked={pinned}
              onChange={onPin}
              aria-label="Select this event for the AI"
            />
          )}
        </td>
        <td style={{ ...td, width: 20, color: "var(--text-muted)" }} aria-hidden>
          {expanded ? "⌄" : "›"}
        </td>
        <td style={{ ...td, whiteSpace: "nowrap", fontFamily: "var(--font-mono, monospace)" }}>
          {ts(event.timestamp)}
        </td>
        <td style={{ ...td, whiteSpace: "nowrap", color: "var(--text-muted)" }}>
          {isAlert ? "—" : delta(event.timestamp, alertTime)}
        </td>
        <td style={td}>
          <span style={agentChip}>{event.agent?.name || "—"}</span>
        </td>
        <td style={{ ...td, whiteSpace: "nowrap" }}>{event.agent?.ip || "—"}</td>
        <td style={td}>{event.domain || "—"}</td>
        <td style={td}>{event.channel || "—"}</td>
        <td style={{ ...td, maxWidth: 520 }}>
          <span style={{ fontWeight: isAlert ? 600 : 400 }}>
            {event.rule?.description || event.full_log || "—"}
          </span>
        </td>
        <td style={{ ...td, whiteSpace: "nowrap" }}>
          {isAlert && <Chip tone="accent">THIS ALERT</Chip>}
          {!isAlert && event.sent_to_ai && <Chip>AI</Chip>}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={10} style={{ ...td, background: "var(--surface-2, transparent)" }}>
            <div style={{ display: "grid", gap: 6 }}>
              {!event.synthetic && <Fact label="OpenSearch reference" value={event.key} mono />}
              {event.rule?.id && (
                <Fact
                  label="Rule"
                  value={`#${event.rule.id}${event.rule.level != null ? ` · level ${event.rule.level}` : ""}`}
                />
              )}
              {event.event_id && <Fact label="Event ID" value={String(event.event_id)} />}
              {event.users?.length ? <Fact label="User" value={event.users.join(", ")} /> : null}
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
              {event.fields && event.fields.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 4 }}>
                    Document summary
                  </div>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <tbody>
                      {event.fields.map((field) => (
                        <tr key={field.name}>
                          <td style={summaryKey}>{field.name}</td>
                          <td style={summaryValue}>{field.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {event.full_log && <pre style={pre}>{event.full_log}</pre>}
            </div>
          </td>
        </tr>
      )}
    </>
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
  whiteSpace: "nowrap",
};
const td: React.CSSProperties = {
  padding: "8px 10px",
  borderBottom: "1px solid var(--border)",
  verticalAlign: "top",
  color: "var(--text)",
};
const agentChip: React.CSSProperties = {
  display: "inline-block",
  padding: "2px 8px",
  borderRadius: 6,
  border: "1px solid var(--border)",
  fontSize: 12,
  whiteSpace: "nowrap",
};
const numberInput: React.CSSProperties = {
  width: 72,
  padding: "6px 8px",
  border: "1px solid var(--border)",
  borderRadius: 6,
  background: "var(--bg-input, transparent)",
  color: "var(--text)",
  fontSize: 13,
};
const secondaryBtn: React.CSSProperties = {
  padding: "6px 12px",
  borderRadius: 6,
  border: "1px solid var(--border)",
  background: "var(--bg-input, transparent)",
  color: "var(--text)",
  fontSize: 13,
};
const primaryBtn = (disabled: boolean): React.CSSProperties => ({
  padding: "6px 12px",
  borderRadius: 6,
  border: "1px solid var(--border)",
  background: disabled ? "var(--surface, transparent)" : "var(--accent, #1f6feb)",
  color: disabled ? "var(--text-muted)" : "#fff",
  cursor: disabled ? "default" : "pointer",
  fontSize: 13,
});
const summaryKey: React.CSSProperties = {
  padding: "4px 10px 4px 0",
  borderBottom: "1px solid var(--border)",
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono, monospace)",
  whiteSpace: "nowrap",
  verticalAlign: "top",
  width: "1%",
};
const summaryValue: React.CSSProperties = {
  padding: "4px 0",
  borderBottom: "1px solid var(--border)",
  color: "var(--text)",
  fontFamily: "var(--font-mono, monospace)",
  wordBreak: "break-all",
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

function Muted({ children }: { children: React.ReactNode }) {
  return <span style={{ color: "var(--text-muted)", fontSize: 13 }}>{children}</span>;
}

function Chip({ children, tone }: { children: React.ReactNode; tone?: "accent" }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 7px",
        borderRadius: 999,
        border: `1px solid ${tone === "accent" ? "var(--accent, #1f6feb)" : "var(--border)"}`,
        color: tone === "accent" ? "var(--accent, #1f6feb)" : "var(--text-muted)",
        fontSize: 10.5,
        letterSpacing: "0.06em",
        fontWeight: 600,
        whiteSpace: "nowrap",
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

export default AlertLogContext;
