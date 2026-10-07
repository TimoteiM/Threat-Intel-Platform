"use client";

/**
 * One case, in full.
 *
 * The correlated-cases list answers "is anything happening"; it is scanned, so
 * it carries a verdict and a line of prose and nothing more. This is where an
 * analyst comes to actually work the case, so everything that was competing for
 * room in that list lives here instead: the whole analysis, the activity drawn
 * on event time, what stands out, what fires most, what the alerts concluded,
 * the indicators, and every member alert.
 *
 * Reachable by case_key, which is derived from the session's first event time
 * and survives a change of query window — so this URL keeps working when the
 * page it was opened from has moved on.
 */

import React, { useEffect, useState } from "react";
import Link from "next/link";
import * as api from "@/lib/api";
import type { CaseDetail } from "@/lib/types";
import { EmptyState, LoadingState, Page, PageHeader } from "@/components/ui/Primitives";
import {
  MONO,
  Panel,
  riskColor,
  shortDate,
} from "@/components/detections/panels";

function verdictTone(verdict: string | null | undefined): string {
  const value = (verdict || "").toLowerCase();
  if (value.includes("malicious")) return "var(--status-danger)";
  if (value.includes("suspicious")) return "var(--status-warning)";
  if (value.includes("benign")) return "var(--status-success)";
  return "var(--text-secondary)";
}

function caseVerdict(markdown: string | null): string | null {
  if (!markdown) return null;
  const match = markdown.match(/\*\*\s*Verdict\s*:\s*([^*\n]+)\*\*/i);
  return match ? match[1].trim().replace(/\.$/, "") : null;
}

/** Seconds as an analyst would say them: "7 min", "3 h 12 m", "2 d". */
function humanDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h${m % 60 ? ` ${m % 60} m` : ""}`;
  const d = Math.floor(h / 24);
  return `${d} d${h % 24 ? ` ${h % 24} h` : ""}`;
}

export default function CasePage({ params }: { params: { caseKey: string } }) {
  const caseKey = params.caseKey;
  const [data, setData] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Named tabs, so a case reads the same way every time.
  //
  // Declared here, above the early returns. It was below them, so a render
  // that bailed out at `if (loading)` ran fewer hooks than the one after it
  // and React threw #310 — the case page crashed to "a client-side exception
  // has occurred" the moment its data arrived.
  const [tab, setTab] = useState<"analysis" | "observables" | "alerts">("analysis");
  // Fetched once, here, rather than inside the tab. The panel used to own
  // this: switching away unmounted it and switching back re-ran the request,
  // so every visit to Observables paid for it again.
  const [observables, setObservables] = useState<
    Awaited<ReturnType<typeof api.getCaseObservables>> | null
  >(null);
  const [observablesError, setObservablesError] = useState<string | null>(null);

  // Lazily: a case opened and never switched away from should not pay for a
  // tab nobody looked at.
  useEffect(() => {
    if (tab !== "observables" || observables || observablesError) return;
    let cancelled = false;
    api
      .getCaseObservables(caseKey)
      .then((d) => !cancelled && setObservables(d))
      .catch(
        (e) =>
          !cancelled &&
          setObservablesError(e instanceof Error ? e.message : "Could not load observables."),
      );
    return () => {
      cancelled = true;
    };
  }, [tab, caseKey, observables, observablesError]);

  // Re-read the case. Also called after "Send to AI now", so the header
  // flips to Closed without the analyst reloading the page.
  const reload = React.useCallback(() => {
    api.getCase(caseKey).then(setData).catch(() => undefined);
  }, [caseKey]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getCase(caseKey)
      .then((result) => !cancelled && setData(result))
      .catch((err) =>
        !cancelled && setError(err instanceof Error ? err.message : "Could not load this case"),
      )
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [caseKey]);

  if (loading) return <Page><LoadingState label="Assembling the case…" /></Page>;
  if (error || !data) {
    return (
      <Page>
        <EmptyState title="Could not open this case" hint={error || "No answer from the server."} />
      </Page>
    );
  }

  const item = data.case;
  const profile = data.profile;
  const verdict = caseVerdict(data.narrative.markdown);
  const host = item?.entity_host || profile?.host || caseKey.slice(0, 12);
  // `{host}/{user} — {what happened}`, composed server-side. Falls back to the
  // bare host for a case that no longer forms in the current window and so has
  // no freshly computed label.
  const label = item?.label || host;
  // The handle an analyst says out loud. The key is a sha256 and always will
  // be, because it has to be derivable from the events.
  const number = item?.case_number ?? (data.spine as any)?.case_number;
  const lifecycle = item?.lifecycle;
  const continues = item?.continues;

  return (
    <Page>
      <PageHeader
        title={number ? `#${number} — ${label}` : label}
        subtitle={
          item
            ? `${item.alert_count} alert(s) · ${item.distinct_rules} independent detections · ${shortDate(item.first_seen)} → ${shortDate(item.last_seen)}`
            : "This case no longer forms in the current window — its history is kept below."
        }
      />

      {continues?.case_key && (
        <div
          style={{
            marginBottom: 12, padding: "9px 12px",
            borderLeft: "3px solid var(--status-info, #388bfd)",
            borderRadius: "0 8px 8px 0", background: "var(--panel-card-bg, transparent)",
            fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6,
          }}
        >
          Continues{" "}
          <Link
            href={`/detections/cases/${continues.case_key}`}
            style={{ color: "var(--accent)", fontWeight: 600 }}
          >
            {continues.case_number ? `#${continues.case_number}` : "an earlier case"}
            {continues.title ? ` — ${continues.title}` : ""}
          </Link>
          {continues.resolution ? `, closed as ${String(continues.resolution).replace(/_/g, " ")}` : ""}
          . A detection that case had not seen arrived after it was answered, so this is counted
          on its own rather than reopening it.
        </div>
      )}

      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "center" }}>
        <Link href="/detections" style={{ fontSize: 11.5, color: "var(--accent)", textDecoration: "none" }}>
          ← all correlated cases
        </Link>
        {item && (
          <span style={{ ...MONO, fontSize: 13, color: riskColor(item.score) }}>
            {item.score}/100
          </span>
        )}
        {verdict && (
          <strong style={{ ...MONO, fontSize: 12, color: verdictTone(verdict), textTransform: "uppercase" }}>
            {verdict}
          </strong>
        )}
        {data.spine && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {data.spine.status}
            {data.spine.assignee ? ` · ${data.spine.assignee}` : ""}
            {" · peak "}{data.spine.peak_score}/100
          </span>
        )}
        {lifecycle?.resolution && (
          <strong
            style={{
              ...MONO, fontSize: 11, textTransform: "uppercase",
              color: lifecycle.resolution === "true_positive"
                ? "var(--status-critical)"
                : lifecycle.resolution === "false_positive"
                ? "var(--text-muted)"
                : "var(--status-warning)",
            }}
          >
            {String(lifecycle.resolution).replace(/_/g, " ")}
          </strong>
        )}
        {lifecycle?.resolve_seconds != null && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            resolved in {humanDuration(lifecycle.resolve_seconds)}
          </span>
        )}
        {data.narrative.assistant_session_id && (
          <a
            href={`/assistant?session=${data.narrative.assistant_session_id}`}
            target="_blank"
            rel="noreferrer"
            style={{ marginLeft: "auto", fontSize: 11, color: "var(--accent)", textDecoration: "none" }}
          >
            open in assistant
          </a>
        )}
      </div>

      {data.spine && (
        <div style={{ display: "flex", gap: 18, flexWrap: "wrap", fontSize: 11.5, color: "var(--text-muted)" }}>
          {/* Three different clocks, kept apart on purpose. When the activity
              happened, when it stopped, and when this platform first knew about
              it — on a replayed chain those sat 18 days apart. */}
          <span>Activity began <strong style={{ color: "var(--text-secondary)" }}>{shortDate(data.spine.opened_at)}</strong></span>
          <span>Last activity <strong style={{ color: "var(--text-secondary)" }}>{shortDate(data.spine.last_activity_at)}</strong></span>
          <span>Case first recorded <strong style={{ color: "var(--text-secondary)" }}>{shortDate(data.spine.first_recorded_at)}</strong></span>
        </div>
      )}

      {data.spine?.superseded_by && (
        <div style={{ fontSize: 11.5, color: "var(--status-warning)" }}>
          A later alert re-anchored this session. Its history continues under{" "}
          <Link href={`/detections/cases/${data.spine.superseded_by}`} style={{ color: "var(--accent)" }}>
            the case that absorbed it
          </Link>.
        </div>
      )}

      {/* One shape for every case: a header that always says the same things,
          then named tabs. The page used to be a vertical pile whose height and
          colour varied with whatever the AI had written, so no two cases
          looked alike and the analyst had to re-find each section. */}
      <div style={{ display: "flex", gap: 6, marginBottom: 14, flexWrap: "wrap" }}>
        {(["analysis", "observables", "alerts"] as const).map((name) => (
          <button
            key={name}
            type="button"
            onClick={() => setTab(name)}
            aria-pressed={tab === name}
            style={{
              padding: "5px 14px", borderRadius: 8, fontSize: 12.5,
              textTransform: "capitalize", cursor: "pointer",
              border: `1px solid ${tab === name ? "var(--accent)" : "var(--panel-divider-strong)"}`,
              background: tab === name ? "var(--accent-subtle, rgba(56,139,253,0.16))" : "transparent",
              color: tab === name ? "var(--text)" : "var(--text-muted)",
            }}
          >
            {name}
          </button>
        ))}
        <div style={{ marginLeft: "auto" }}>
          <AnalyseNowButton
            caseKey={caseKey}
            closed={Boolean(lifecycle?.closed_at)}
            onDone={reload}
          />
        </div>
      </div>

      {tab === "observables" ? (
        <ObservablesPanel data={observables} error={observablesError} />
      ) : tab === "alerts" ? null : (
      <>
      <Panel title="CASE ANALYSIS" hint="One reading of the whole case. Each alert keeps its own below.">
        {data.narrative.markdown ? (
          <pre
            style={{
              margin: 0, fontSize: 12, lineHeight: 1.7, whiteSpace: "pre-wrap",
              wordBreak: "break-word", color: "var(--text-secondary)", fontFamily: "inherit",
            }}
          >
            {data.narrative.markdown}
          </pre>
        ) : (
          <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
            {/* "Being written" was shown for every state that was not a
                failure, including a case nothing had started on. The hourly
                job that commissions these raised on every tick for weeks, and
                this line reported it as work in progress the whole time.
                Each state now says what is actually true of it. */}
            {data.narrative.status === "failed"
              ? `The case analysis could not be written${
                  data.narrative.error ? `: ${data.narrative.error}` : ""
                }. Everything below is unaffected.`
              : data.narrative.status === "running"
              ? "The case analysis is being written now. Everything below is already complete."
              : data.narrative.status === "stale"
              ? "The case has changed since its analysis was written; a new one is queued. Everything below is current."
              : "The case analysis is queued. It is written when the case goes quiet — ten minutes after its last alert — or immediately if you send it now. Everything below is already complete."}
          </div>
        )}
      </Panel>

      {item && item.reasons.length > 0 && (
        <Panel title="WHY THESE ALERTS ARE ONE CASE" hint="What the correlation measured, not what it concluded.">
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
            {item.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </Panel>
      )}

      {profile && (profile.notable || []).length > 0 && (
        <Panel title="WHAT STANDS OUT" hint="Drawn from concluded verdicts and indicator risk, not from alert volume.">
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 5 }}>
            {(profile.notable || []).map((entry) => (
              <li key={entry.text} style={{ fontSize: 12, color: riskColor(entry.risk), lineHeight: 1.5 }}>
                <span style={{ color: "var(--text-secondary)" }}>{entry.text}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* ACTIVITY, MOST TRIGGERED, BEHAVIOUR, VERDICTS and USERS used to sit
          here. They describe the machine, not this case: on a busy host the
          same five panels appeared identically on every one of its cases, and
          pushed the four things that are actually about the case — why these
          alerts are one case, what stands out, the indicators, the alerts
          themselves — below the fold. They are on Detections → Devices, where
          one row is one machine. */}

      </>
      )}

      {tab === "analysis" && profile && Object.keys(profile.indicators || {}).length > 0 && (
        <Panel title="INDICATORS" hint="Every indicator seen in this host's alerts, worst conclusion kept.">
          <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
            {Object.entries(profile.indicators || {}).map(([type, items]) => (
              <div key={type} style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 10.5, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>
                  {type} · {profile.indicator_totals?.[type] ?? items.length} distinct
                </span>
                {items.map((entry) => (
                  <div key={entry.value} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                    <span
                      style={{
                        ...MONO, fontSize: 11, flex: 1, overflow: "hidden",
                        textOverflow: "ellipsis", whiteSpace: "nowrap",
                        color: entry.excluded ? "var(--text-muted)" : "var(--text-secondary)",
                        textDecoration: entry.excluded ? "line-through" : "none",
                      }}
                      title={`${entry.value}${entry.classification ? ` — ${entry.classification}` : ""} · seen in ${entry.count} alert(s)`}
                    >
                      {entry.value}
                    </span>
                    {entry.risk > 0 && (
                      <span style={{ ...MONO, fontSize: 10.5, color: riskColor(entry.risk) }}>{entry.risk}</span>
                    )}
                    <span style={{ ...MONO, fontSize: 10.5, color: "var(--text-muted)" }}>x{entry.count}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Always available, on its own tab and under the analysis, because the
          alerts are the case and an analyst reaches for them from both. */}
      {item && tab !== "observables" && (
        <Panel title="ALERTS IN THIS CASE" hint="In the order they happened. Each keeps its own investigation.">
          <div style={{ display: "grid", gap: 4 }}>
            {item.alerts.map((alert) => (
              <div key={alert.run_id} style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                <span style={{ ...MONO, fontSize: 10.5, color: "var(--text-muted)", minWidth: 128 }}>
                  {shortDate(alert.event_time || alert.created_at)}
                </span>
                <a
                  href={`/alert-investigations/${alert.run_id}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ fontSize: 12, color: "var(--accent)", textDecoration: "none", flex: 1, minWidth: 220 }}
                >
                  {alert.detection_rule_name || alert.title || alert.run_id}
                </a>
                <span style={{ ...MONO, fontSize: 10.5, color: verdictTone(alert.overall_verdict) }}>
                  {alert.overall_verdict || "—"}
                </span>
                {alert.highest_risk_score ? (
                  <span style={{ ...MONO, fontSize: 10.5, color: riskColor(alert.highest_risk_score) }}>
                    {alert.highest_risk_score}
                  </span>
                ) : null}
              </div>
            ))}
          </div>
        </Panel>
      )}
    </Page>
  );
}

/**
 * The indicators a case's alerts carry, split by what is actually known.
 *
 * Two populations, never merged: one the platform looked up and has a verdict
 * for, one it only extracted. Showing them together is how an analyst comes
 * to believe an address was checked when it was merely seen.
 */
function ObservablesPanel({
  data,
  error,
}: {
  data: Awaited<ReturnType<typeof api.getCaseObservables>> | null;
  error: string | null;
}) {
  if (error) return <Panel title="OBSERVABLES"><div style={obsNote}>{error}</div></Panel>;
  if (!data) return <Panel title="OBSERVABLES"><div style={obsNote}>Loading…</div></Panel>;

  return (
    <>
      <Panel
        title="VERIFIED OBSERVABLES"
        hint="Looked up by the platform, with the verdict it reached."
      >
        {data.verified.length === 0 ? (
          <div style={obsNote}>Nothing in this case was investigated.</div>
        ) : (
          <ObservableTable
            rows={data.verified.map((o) => ({
              value: o.value,
              type: o.type,
              alerts: o.alerts,
              right: o.verdict
                ? `${o.verdict}${o.risk_score != null ? ` · ${o.risk_score}/100` : ""}`
                : "—",
              tone:
                o.verdict === "malicious"
                  ? "var(--status-critical)"
                  : o.verdict === "suspicious"
                  ? "var(--status-warning)"
                  : "var(--text-muted)",
            }))}
          />
        )}
      </Panel>

      <Panel
        title="IDENTIFIED OBSERVABLES"
        hint="Extracted from the alerts but not investigated, and why."
      >
        {data.identified.length === 0 ? (
          <div style={obsNote}>Everything extracted from this case was investigated.</div>
        ) : (
          <ObservableTable
            rows={data.identified.map((o) => ({
              value: o.value,
              type: o.type,
              alerts: o.alerts,
              right: (o.reason || "not investigated").replace(/_/g, " "),
              tone: "var(--text-muted)",
            }))}
          />
        )}
      </Panel>
    </>
  );
}

function ObservableTable({
  rows,
}: {
  rows: Array<{ value: string; type: string; alerts: number; right: string; tone: string }>;
}) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.type}:${r.value}`}>
              <td style={{ ...obsCell, width: "1%", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 11 }}>
                {r.type || "—"}
              </td>
              <td style={{ ...obsCell, ...MONO, wordBreak: "break-all", color: "var(--text)" }}>
                {r.value}
              </td>
              <td style={{ ...obsCell, width: "1%", whiteSpace: "nowrap", color: "var(--text-muted)", fontSize: 11 }}>
                {r.alerts} alert{r.alerts === 1 ? "" : "s"}
              </td>
              <td style={{ ...obsCell, width: "1%", whiteSpace: "nowrap", color: r.tone, fontSize: 11.5, textTransform: "capitalize" }}>
                {r.right}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Answer the case now instead of waiting out its quiet period.
 *
 * The automatic close waits ten minutes for alerts to stop arriving. An
 * analyst who has already read the case should not have to — and closing
 * early is a decision, so it is recorded as one rather than disguised as the
 * automatic close.
 */
function AnalyseNowButton({
  caseKey,
  closed,
  onDone,
}: {
  caseKey: string;
  closed: boolean;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  if (closed) {
    return <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>Already answered</span>;
  }

  return (
    <span style={{ display: "inline-flex", gap: 10, alignItems: "center" }}>
      {note && <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{note}</span>}
      <button
        type="button"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setNote(null);
          try {
            const result = await api.analyseCaseNow(caseKey);
            setNote(result.note);
            onDone();
          } catch (e) {
            setNote(e instanceof Error ? e.message : "Could not send this case for analysis.");
          } finally {
            setBusy(false);
          }
        }}
        style={{
          padding: "5px 14px", borderRadius: 8, fontSize: 12.5, cursor: busy ? "wait" : "pointer",
          border: "1px solid var(--accent)",
          background: busy ? "transparent" : "var(--accent-subtle, rgba(56,139,253,0.16))",
          color: "var(--text)",
        }}
      >
        {busy ? "Sending…" : "Send to AI now"}
      </button>
    </span>
  );
}

const obsNote: React.CSSProperties = { fontSize: 12, color: "var(--text-muted)" };
const obsCell: React.CSSProperties = {
  padding: "6px 12px 6px 0",
  borderBottom: "1px solid var(--panel-divider, var(--border))",
  verticalAlign: "top",
};
