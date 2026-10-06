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
  getAnalysisStatus,
  reanalyseWithLogContext,
  type AlertLogContextPage,
  type AlertLogEvent,
  type AnalysisStatus,
} from "@/lib/api";
import LogFieldControls, {
  DEFAULT_COLUMNS,
  labelFor,
  matchesFilters,
  valueOf,
  type FieldFilter,
} from "@/components/report/LogFieldControls";

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

const INDETERMINATE_KEYFRAMES = `
@keyframes tip-indeterminate {
  0%   { margin-left: -35%; }
  100% { margin-left: 100%; }
}`;

export function AlertLogContext({
  runId,
  onReanalysed,
}: {
  runId: string;
  onReanalysed?: () => void;
}) {
  const [page, setPage] = useState<AlertLogContextPage | null>(null);
  const [before, setBefore] = useState(STEP_DEFAULT);
  const [after, setAfter] = useState(STEP_DEFAULT);
  const [newerStep, setNewerStep] = useState(STEP_DEFAULT);
  const [olderStep, setOlderStep] = useState(STEP_DEFAULT);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  // Which document fields the table shows, and which rows it keeps. Both start
  // where they were: the six columns that make a window scannable.
  const [columns, setColumns] = useState<string[]>([...DEFAULT_COLUMNS]);
  const [filters, setFilters] = useState<FieldFilter[]>([]);
  // The ranking's picks, as a filter rather than only as a chip on the row.
  // "Show me the ones worth reading" is the first thing an analyst does with a
  // hundred-event window, and the chip made them findable only by scrolling.
  const [onlyRelevant, setOnlyRelevant] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  // The re-analysis, watched to completion in place. An analyst who sends
  // events to the model should not have to guess whether it worked, reload, or
  // go somewhere else to read the answer.
  const [job, setJob] = useState<AnalysisStatus | null>(null);
  // "submitting" exists so that polling cannot begin before the request it is
  // meant to be waiting for. Going straight to "queued" started the poll loop
  // while the POST was still in flight, and the first tick then read the run
  // as it was *before* the request — completed, with the previous analysis.
  const [jobPhase, setJobPhase] = useState<
    "idle" | "submitting" | "queued" | "running" | "done" | "failed"
  >("idle");
  const [elapsed, setElapsed] = useState(0);
  const [supersedes, setSupersedes] = useState<string | null>(null);
  const [awaitingRequestId, setAwaitingRequestId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPage(await getAlertLogContext(runId, before, after, onlyRelevant));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the surrounding events.");
    } finally {
      setLoading(false);
    }
  }, [runId, before, after, onlyRelevant]);

  useEffect(() => {
    void load();
  }, [load]);

  // What survives the field filters. Computed before `displayed`, because
  // "select all" has to mean the rows on screen — selecting filtered-out
  // events would send the AI exactly what the analyst had just excluded.
  // `onlyRelevant` is applied by the server, which returns the whole flagged
  // set rather than a page — so there is nothing left to filter for it here.
  // Doing it in both places is how "4 of 11 match" was shown for a window the
  // ranking had flagged sixteen events in.
  const keep = (e: AlertLogEvent) => matchesFilters(e, filters);
  const visibleBefore = page ? page.before.filter(keep) : [];
  const visibleAfter = page ? page.after.filter(keep) : [];
  // The alert itself is drawn whatever the filter says — see the note by the
  // count line. It is never "relevant" in the ranking's sense; it is the thing
  // the ranking is about.
  const anchorMatches = page ? keep(page.anchor) : true;

  // Every event currently on screen, in the order it is drawn. "Select all"
  // means exactly what is displayed — expanding the window and selecting again
  // adds the newly shown ones rather than silently re-selecting everything.
  const displayed: AlertLogEvent[] = page
    ? [...[...visibleAfter].reverse(), page.anchor, ...[...visibleBefore].reverse()].filter(
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

  // Every event the ranking flagged in the whole window, from the server —
  // not the flagged rows on this page. "Re-analyse with the relevant events"
  // has to mean all of them, and the view only ever holds a window of ten.
  const relevantKeys = page?.relevant_refs ?? [];

  // The token estimate is about what gets *sent*, and what gets sent is the
  // pinned set (line below: `Array.from(pinned)`) — not the filtered view. A
  // pin is a deliberate act, so adding a filter afterwards must not quietly
  // drop events from the request; it would also under-report the budget and
  // surface later as "did not fit the token budget". So: select-all means the
  // rows on screen, the estimate means everything pinned in this window.
  const windowEvents: AlertLogEvent[] = page
    ? [...[...page.after].reverse(), page.anchor, ...[...page.before].reverse()].filter(
        (e) => !(e as { synthetic?: boolean }).synthetic,
      )
    : [];
  const selectedEvents = windowEvents.filter((e) => pinned.has(e.key));
  const pinnedHidden = selectedEvents.filter((e) => !displayedKeys.includes(e.key)).length;
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

  const requestReanalysis = async (refs?: string[]) => {
    setBusy(true);
    setNote(null);
    setJob(null);
    setElapsed(0);
    setAwaitingRequestId(null);
    setSupersedes(null);
    // Not "queued": nothing is queued until the POST below says so. Setting
    // the polling phase here started a tick that read the run before the
    // request had touched it.
    setJobPhase("submitting");
    try {
      // What the analyst was actually reading. Columns beyond the six
      // defaults, plus any field they filtered on — narrowing on `logonId` is
      // as clear a statement that it matters as putting it on screen, and the
      // projection the model receives carried neither. `delta` is computed
      // from the window, not a field of any document.
      const chosen = Array.from(
        new Set([
          ...columns.filter((c) => c !== "delta" && !DEFAULT_COLUMNS.includes(c as never)),
          ...filters.filter((f) => f.field && f.value).map((f) => f.field),
        ]),
      );
      const result = await reanalyseWithLogContext(runId, refs ?? Array.from(pinned), {
        extraFields: chosen,
        filters: filters.filter((f) => f.field && f.value),
      });
      // Matched exactly, by the id of this request. Comparing completion
      // timestamps left a hole whenever the run had no completion to compare
      // against, and a poll landing before the worker started then reported
      // the previous answer as this one — zero events, zero tokens, zero
      // history, and an interpretation that had not moved.
      setAwaitingRequestId(result.request_id ?? null);
      setSupersedes(result.previous_completed_at ?? null);
      setNote(result.note);
      // Only now is there something to wait for, and an id to recognise it by.
      setJobPhase("queued");
    } catch (err) {
      setJobPhase("failed");
      setNote(err instanceof Error ? err.message : "Re-analysis could not be queued.");
    } finally {
      setBusy(false);
    }
  };

  // Poll while a re-analysis is in flight. Three seconds is slow enough not to
  // matter and fast enough that the bar does not look stuck; the endpoint is a
  // single row read, not the hydrated run.
  useEffect(() => {
    if (jobPhase !== "queued" && jobPhase !== "running") return undefined;
    // No id means no way to tell this request's result from the one already on
    // screen, and guessing resolved to "yes" every time.
    if (!awaitingRequestId) return undefined;
    let cancelled = false;
    const started = Date.now();

    const tick = async () => {
      try {
        const status = await getAnalysisStatus(runId);
        if (cancelled) return;
        setElapsed(Math.round((Date.now() - started) / 1000));
        // Exactly this request, or nothing. The request_id is written by the
        // POST together with status="queued", so a run reporting *finished*
        // under this id can only be the worker having completed it since.
        //
        // The timestamp comparison that used to stand in for this is gone: it
        // treated "I cannot tell which request this is" as "this one", which
        // is how the previous analysis came to be presented as the new one —
        // instantly, with zero selected events and zero tokens.
        const isThisRequest = status.reanalysis?.request_id === awaitingRequestId;
        if (status.finished && isThisRequest) {
          setJob(status);
          setJobPhase(status.status === "completed" ? "done" : "failed");
          // The window's own numbers move with the new analysis, and so does
          // the page's analysis section — which otherwise keeps showing the
          // interpretation this run just replaced.
          void load();
          onReanalysed?.();
        } else {
          setJobPhase("running");
        }
      } catch {
        // A failed poll is not a failed analysis; keep waiting.
      }
    };

    void tick();
    const timer = setInterval(tick, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [jobPhase, runId, load, supersedes, awaitingRequestId, onReanalysed]);

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
      <style>{INDETERMINATE_KEYFRAMES}</style>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "baseline" }}>
        <Fact label="Retrieved" value={`${page.retrieved_total} events in the window`} />
        <Fact label="Ranked relevant" value={String(page.relevant_total ?? 0)} />
        <Fact label="Sent to the AI" value={String(page.sent_to_ai_total)} />
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
            <button
              type="button"
              onClick={() => void requestReanalysis(relevantKeys)}
              disabled={busy || relevantKeys.length === 0}
              style={primaryBtn(busy || relevantKeys.length === 0)}
            >
              {busy
                ? "Queueing…"
                : relevantKeys.length
                ? `Re-analyse with the ${relevantKeys.length} relevant event${relevantKeys.length === 1 ? "" : "s"}`
                : "No relevant events to add"}
            </button>
            <Muted>
              The current verdict is kept, not overwritten.
              {relevantKeys.length
                ? " Re-running with nothing added would ask the same question and get the same answer."
                : ""}
            </Muted>
          </div>
        </div>
      )}

      {/* The re-analysis, from request to result, without leaving the page. */}
      {jobPhase !== "idle" && (
        <div
          style={{
            ...panel,
            borderColor:
              jobPhase === "failed"
                ? "var(--danger, #f85149)"
                : jobPhase === "done"
                ? "var(--success, #3fb950)"
                : "var(--accent, #1f6feb)",
            gap: 8,
          }}
        >
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
            <strong style={{ color: "var(--text)" }}>
              {jobPhase === "submitting" && "Sending your selected events…"}
              {jobPhase === "queued" && "Queued for re-analysis…"}
              {jobPhase === "running" && "Re-analysing with your selected events…"}
              {jobPhase === "done" && "✓ Re-analysed"}
              {jobPhase === "failed" && "Re-analysis did not complete"}
            </strong>
            {(jobPhase === "submitting" || jobPhase === "queued" || jobPhase === "running") && (
              <Muted>{elapsed}s elapsed — this usually takes under a minute</Muted>
            )}
            {jobPhase === "done" && job && (
              <Muted>
                {job.log_selection.analyst_pinned.length} selected event
                {job.log_selection.analyst_pinned.length === 1 ? "" : "s"} considered
                {job.log_selection.events_found
                  ? ` of ${job.log_selection.events_found} retrieved`
                  : ""}
                {job.log_selection.analyst_pinned_dropped.length > 0
                  ? `, ${job.log_selection.analyst_pinned_dropped.length} did not fit the token budget`
                  : ""}
                {` · ${(job.log_selection.sent_tokens ?? 0).toLocaleString()} tokens of log context sent`}
              </Muted>
            )}
          </div>

          {/* Which of the fields the analyst added actually reached the model.
              Asked and sent differ whenever no selected event carried the
              field, and "the model saw my column" is a claim they should be
              able to check rather than assume. */}
          {jobPhase === "done" && job && (job.log_selection.extra_fields_requested?.length ?? 0) > 0 && (
            <Muted>
              {(() => {
                const asked = job.log_selection.extra_fields_requested ?? [];
                const sent = job.log_selection.extra_fields_sent ?? [];
                const missing = asked.filter((f) => !sent.includes(f));
                return (
                  <>
                    Fields you added, sent with your events:{" "}
                    {sent.length > 0 ? sent.map((f) => labelFor(f, asked)).join(", ") : "none"}
                    {missing.length > 0 &&
                      ` · not sent, because no selected event carried a value: ${missing
                        .map((f) => labelFor(f, asked))
                        .join(", ")}`}
                  </>
                );
              })()}
            </Muted>
          )}

          {(jobPhase === "submitting" || jobPhase === "queued" || jobPhase === "running") && (
            <div style={progressTrack} role="progressbar" aria-label="Re-analysis progress">
              <div style={progressBar} />
            </div>
          )}

          {jobPhase === "done" && job && (
            <>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <Fact label="Verdict" value={job.overall_verdict || "—"} />
                <Fact label="Risk" value={job.highest_risk_score != null ? `${job.highest_risk_score}/100` : "—"} />
                <Fact label="Earlier analyses kept" value={String(job.previous_analyses)} />
              </div>
              {/* Said plainly. A model that considered the added events and
                  kept its conclusion has answered the question; leaving the
                  analyst to compare two paragraphs by eye makes a real answer
                  look like a failed request. */}
              {job.previous && (
                <div
                  style={{
                    ...panel,
                    borderColor:
                      job.previous.verdict && job.previous.verdict !== job.overall_verdict
                        ? "var(--warning, #d29922)"
                        : "var(--border)",
                    gap: 4,
                  }}
                >
                  <strong style={{ color: "var(--text)" }}>
                    {job.previous.verdict && job.previous.verdict !== job.overall_verdict
                      ? `Verdict changed: ${job.previous.verdict} → ${job.overall_verdict}`
                      : `Verdict unchanged (${job.overall_verdict ?? "—"})`}
                  </strong>
                  <Muted>
                    {job.previous.interpretation_changed === null
                      ? "The earlier wording was not kept, so the two cannot be compared."
                      : job.previous.interpretation_changed
                      ? "The interpretation was rewritten with your events in it."
                      : "The model read your events and reached the same conclusion in the same words."}
                  </Muted>
                  {job.previous.report_markdown && (
                    <details>
                      <summary style={{ cursor: "pointer", color: "var(--text-muted)", fontSize: 12 }}>
                        Show the earlier interpretation
                      </summary>
                      <div style={{ ...reportBox, marginTop: 6 }}>{job.previous.report_markdown}</div>
                    </details>
                  )}
                </div>
              )}
              {job.report_markdown ? (
                <div style={{ marginTop: 4 }}>
                  <div style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 4 }}>
                    Updated interpretation
                    {job.generated_at && (
                      <span style={{ opacity: 0.85 }}>
                        {" — written "}
                        {new Date(job.generated_at).toLocaleTimeString()}
                        {job.log_events_considered
                          ? `, ${job.log_events_considered} log event${job.log_events_considered === 1 ? "" : "s"} in its context`
                          : ", alert body only"}
                        {job.generation_ms ? ` (${(job.generation_ms / 1000).toFixed(1)}s)` : ""}
                      </span>
                    )}
                  </div>
                  <div style={reportBox}>{job.report_markdown}</div>
                </div>
              ) : (
                <Muted>The analysis completed but produced no narrative.</Muted>
              )}
            </>
          )}

          {note && <Muted>{note}</Muted>}
          {jobPhase !== "queued" && jobPhase !== "running" && (
            <div>
              <button type="button" onClick={() => { setJobPhase("idle"); setJob(null); setNote(null); }} style={secondaryBtn}>
                Dismiss
              </button>
            </div>
          )}
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
          {pinnedHidden > 0 && (
            <span style={{ color: "var(--text-muted)", fontSize: 13 }}>
              {pinnedHidden} of them {pinnedHidden === 1 ? "is" : "are"} hidden by the
              current filter and will still be sent
            </span>
          )}
          <button type="button" onClick={() => setPinned(new Set())} style={secondaryBtn}>
            Clear
          </button>
          <button
            type="button"
            onClick={() => void requestReanalysis()}
            disabled={busy}
            style={{ ...primaryBtn(busy), marginLeft: "auto" }}
          >
            {busy ? "Queueing…" : `Send ${pinned.size} event${pinned.size === 1 ? "" : "s"} to the AI`}
          </button>
        </div>
      )}

      {/* Which fields the table shows, and which rows survive. Every event
          already carries its whole document; the six defaults are what makes a
          window scannable, not the limit of what is there. */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        {/* Disabled rather than hidden when nothing is ranked: an analyst who
            has seen this control before should find it where it was, told that
            there is nothing to narrow to, not left wondering if it moved. A
            run analysed before the ranking existed has no relevant set. */}
        <label
          title={
            (page.relevant_total ?? 0) > 0
              ? "Show only the events the ranking flagged"
              : "Nothing in this window is ranked relevant"
          }
          style={{
            display: "flex", gap: 6, alignItems: "center", fontSize: 12,
            cursor: (page.relevant_total ?? 0) > 0 ? "pointer" : "default",
            color: onlyRelevant ? "var(--text)" : "var(--text-muted)",
            opacity: (page.relevant_total ?? 0) > 0 ? 1 : 0.55,
          }}
        >
          <input
            type="checkbox"
            checked={onlyRelevant}
            disabled={(page.relevant_total ?? 0) === 0}
            onChange={(e) => setOnlyRelevant(e.target.checked)}
          />
          Only relevant events
          {page.relevant_total != null && ` (${page.relevant_total})`}
        </label>
        {/* Until now this action existed only inside the "did not see all of
            these events" panel, so once an analysis was current there was no
            way to ask for the ranking's picks at all. It is the same request
            either way, and it is worth making from a window that is complete. */}
        {!stale && page.analysis_basis !== "partial" && relevantKeys.length > 0 && (
          <button
            type="button"
            onClick={() => void requestReanalysis(relevantKeys)}
            disabled={busy}
            style={{ ...secondaryBtn, opacity: busy ? 0.6 : 1 }}
          >
            {busy
              ? "Queueing…"
              : `Re-analyse with the ${relevantKeys.length} relevant event${relevantKeys.length === 1 ? "" : "s"}`}
          </button>
        )}
      </div>

      <LogFieldControls
        events={[...page.before, page.anchor, ...page.after]}
        columns={columns}
        onColumns={setColumns}
        filters={filters}
        onFilters={setFilters}
      />

      {/* Only for the field filters. Relevance is now applied by the server,
          which returns the whole flagged set, so there is no "N of M loaded"
          to report for it — every one of them is on screen. */}
      {filters.length > 0 && (
        <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
          {visibleBefore.length + visibleAfter.length + (anchorMatches ? 1 : 0)} of{" "}
          {page.before.length + page.after.length + 1} loaded events match.
          {!anchorMatches && " The alert itself does not match, and is shown anyway."}
        </div>
      )}
      {onlyRelevant && filters.length === 0 && (
        <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
          Showing all {page.before.length + page.after.length} event
          {page.before.length + page.after.length === 1 ? "" : "s"} the ranking tied to this
          alert, either side of it. The alert itself is shown whether or not it was flagged.
        </div>
      )}

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
              <th style={th} />
              {columns.map((field) => (
                <th key={field} style={th} title={field}>
                  {labelFor(field, columns)}
                </th>
              ))}
              <th style={th} />
            </tr>
          </thead>
          <tbody>
            {/* Newest first, matching how the window reads top-down from the
                future into the past — the alert sits where it happened. */}
            {[...visibleAfter].reverse().map((event) => (
              <Row
                key={event.key}
                event={event}
                alertTime={page.alert_time}
                expanded={expanded === event.key}
                onToggle={() => setExpanded(expanded === event.key ? null : event.key)}
                pinned={pinned.has(event.key)}
                onPin={() => togglePin(event.key)}
                columns={columns}
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
              columns={columns}
            />

            {[...visibleBefore].reverse().map((event) => (
              <Row
                key={event.key}
                event={event}
                alertTime={page.alert_time}
                expanded={expanded === event.key}
                onToggle={() => setExpanded(expanded === event.key ? null : event.key)}
                pinned={pinned.has(event.key)}
                onPin={() => togglePin(event.key)}
                columns={columns}
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
  columns,
}: {
  event: AlertLogEvent & { is_alert?: boolean; synthetic?: boolean };
  alertTime?: string | null;
  isAlert?: boolean;
  expanded: boolean;
  onToggle: () => void;
  pinned: boolean;
  onPin: () => void;
  columns: string[];
}) {
  const rowStyle: React.CSSProperties = isAlert
    ? {
        background: "var(--accent-subtle, rgba(56,139,253,0.16))",
        boxShadow: "inset 3px 0 0 var(--accent, #1f6feb)",
        cursor: "pointer",
      }
    : {
        cursor: "pointer",
        background: expanded ? "var(--surface-2, transparent)" : undefined,
        // A flagged row should read as flagged before you reach the chip at the
        // far right of a wide table.
        boxShadow: event.relevant ? "inset 3px 0 0 var(--warning, #d29922)" : undefined,
      };

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
        {columns.map((field) => {
          if (field === "timestamp") {
            return (
              <td
                key={field}
                style={{ ...td, whiteSpace: "nowrap", fontFamily: "var(--font-mono, monospace)" }}
              >
                {ts(event.timestamp)}
              </td>
            );
          }
          if (field === "delta") {
            return (
              <td key={field} style={{ ...td, whiteSpace: "nowrap", color: "var(--text-muted)" }}>
                {isAlert ? "—" : delta(event.timestamp, alertTime)}
              </td>
            );
          }
          if (field === "agent.name") {
            return (
              <td key={field} style={td}>
                <span style={agentChip}>{event.agent?.name || "—"}</span>
              </td>
            );
          }
          if (field === "rule.description") {
            return (
              <td key={field} style={{ ...td, maxWidth: 520 }}>
                <span style={{ fontWeight: isAlert ? 600 : 400 }}>
                  {event.rule?.description || event.full_log || "—"}
                </span>
              </td>
            );
          }
          const value = valueOf(event, field);
          return (
            <td
              key={field}
              style={{
                ...td,
                maxWidth: 420,
                // Added columns are frequently paths and command lines.
                fontFamily: field.includes("ommand") || field.includes("rocess")
                  ? "var(--font-mono, monospace)"
                  : undefined,
                wordBreak: value.length > 60 ? "break-all" : undefined,
              }}
              title={value || undefined}
            >
              {value || "—"}
            </td>
          );
        })}
        <td style={{ ...td, whiteSpace: "nowrap" }}>
          {isAlert && <Chip tone="accent">THIS ALERT</Chip>}
          {!isAlert && event.relevant && <Chip tone="relevant">RELEVANT</Chip>}
          {!isAlert && event.sent_to_ai && <Chip>SENT</Chip>}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={columns.length + 2} style={{ ...td, background: "var(--surface-2, transparent)" }}>
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
const progressTrack: React.CSSProperties = {
  height: 4,
  borderRadius: 999,
  background: "var(--border)",
  overflow: "hidden",
};
// Indeterminate on purpose: the work is a model call whose duration is not
// knowable, and a bar that claims 60% would be inventing a number.
const progressBar: React.CSSProperties = {
  height: "100%",
  width: "35%",
  borderRadius: 999,
  background: "var(--accent, #1f6feb)",
  animation: "tip-indeterminate 1.4s ease-in-out infinite",
};
const reportBox: React.CSSProperties = {
  maxHeight: 360,
  overflowY: "auto",
  padding: 10,
  border: "1px solid var(--border)",
  borderRadius: 6,
  background: "var(--surface, transparent)",
  color: "var(--text)",
  fontSize: 13,
  lineHeight: 1.55,
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
};
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

function Chip({ children, tone }: { children: React.ReactNode; tone?: "accent" | "relevant" }) {
  const colour =
    tone === "accent"
      ? "var(--accent, #1f6feb)"
      : tone === "relevant"
      ? "var(--warning, #d29922)"
      : "var(--border)";
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 7px",
        borderRadius: 999,
        border: `1px solid ${colour}`,
        color: tone ? colour : "var(--text-muted)",
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
