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
  CountedRows,
  MONO,
  Panel,
  Timeline,
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

export default function CasePage({ params }: { params: { caseKey: string } }) {
  const caseKey = params.caseKey;
  const [data, setData] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <Page>
      <PageHeader
        title={host}
        subtitle={
          item
            ? `${item.alert_count} alert(s) · ${item.distinct_rules} independent detections · ${shortDate(item.first_seen)} → ${shortDate(item.last_seen)}`
            : "This case no longer forms in the current window — its history is kept below."
        }
      />

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

      {data.spine?.superseded_by && (
        <div style={{ fontSize: 11.5, color: "var(--status-warning)" }}>
          A later alert re-anchored this session. Its history continues under{" "}
          <Link href={`/detections/cases/${data.spine.superseded_by}`} style={{ color: "var(--accent)" }}>
            the case that absorbed it
          </Link>.
        </div>
      )}

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
            {data.narrative.status === "failed"
              ? "The case analysis could not be written. Everything below is unaffected."
              : "The case analysis is being written. Everything below is already complete."}
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

      {profile && (
        <Panel title="ACTIVITY" hint="Alerts on event time, in lanes by evidenced tactic. Shaded bands are sessions.">
          <Timeline profile={profile} />
        </Panel>
      )}

      {profile && (
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))" }}>
          <Panel title="MOST TRIGGERED" hint={profile.rules_total ? `${profile.rules_total} distinct rule(s) have fired here` : undefined}>
            <CountedRows
              rows={(profile.rules || []).map((rule) => ({
                label: rule.name, count: rule.count, risk: rule.max_risk,
                hint: `${rule.name}${rule.id ? ` · rule ${rule.id}` : ""}`,
              }))}
              emptyLabel="No alert here carries a detection rule."
            />
          </Panel>
          <Panel title="BEHAVIOUR" hint="Tactics the investigation evidenced. Rule claims are excluded.">
            <CountedRows
              rows={(profile.tactics || []).map((t) => ({ label: t.name, count: t.count }))}
              emptyLabel="No evidenced ATT&CK tactic on this host."
            />
          </Panel>
          <Panel title="VERDICTS" hint="What the alerts on this host concluded.">
            <CountedRows
              rows={(profile.verdicts || []).map((v) => ({
                label: v.name, count: v.count,
                risk: v.name === "malicious" ? 100 : v.name === "suspicious" ? 50 : 0,
              }))}
              emptyLabel="No concluded verdicts."
            />
          </Panel>
          <Panel
            title="USERS"
            hint={profile.users ? `Carried on ${profile.users.runs_with_user} of ${profile.users.runs_total} alert(s)` : undefined}
          >
            {profile.users && profile.users.values.length > 0 ? (
              <CountedRows
                rows={profile.users.values.map((u) => ({ label: u.name, count: u.count }))}
                emptyLabel=""
              />
            ) : (
              <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
                No alert on this host carries a user. The field is populated on a small
                minority of alerts across the estate, so its absence says nothing about
                who used the machine.
              </div>
            )}
          </Panel>
        </div>
      )}

      {profile && Object.keys(profile.indicators || {}).length > 0 && (
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

      {item && (
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
