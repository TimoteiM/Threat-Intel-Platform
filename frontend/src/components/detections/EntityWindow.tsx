"use client";

/**
 * One machine, and everything this platform has concluded about it.
 *
 * The cases list answers "is something happening here". The question an analyst
 * asks immediately afterwards — what is this machine, what does it normally do,
 * and which part of this is actually unusual — used to require opening forty
 * alerts in turn. Everything below is already stored; this is where it is
 * finally read in one place.
 *
 * The ordering is the argument: what stands out comes first, then the shape of
 * the activity over time, then the volume behind it. Counts are shown beside
 * every list because on this estate one rule accounts for most of the traffic,
 * and a list without counts would present that rule as one finding among many.
 */

import React, { useEffect, useState } from "react";
import * as api from "@/lib/api";
import type { EntityProfile } from "@/lib/types";
import {
  CountedRows,
  MONO,
  Panel,
  Timeline,
  riskColor,
  shortDate,
} from "@/components/detections/panels";
import { EmptyState, LoadingState } from "@/components/ui/Primitives";

/* ─── The window ─── */

export default function EntityWindow({
  host,
  onClose,
}: {
  host: string;
  onClose: () => void;
}) {
  const [profile, setProfile] = useState<EntityProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getEntityProfile(host)
      .then((result) => !cancelled && setProfile(result))
      .catch((err) =>
        !cancelled && setError(err instanceof Error ? err.message : "Could not load"),
      )
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [host]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const indicatorTypes = Object.keys(profile?.indicators || {});

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 60,
        background: "rgba(3,7,18,0.62)", display: "flex", justifyContent: "flex-end",
      }}
    >
      <div
        onClick={(event) => event.stopPropagation()}
        style={{
          width: "min(1000px, 100vw)", height: "100%", overflowY: "auto",
          background: "var(--bg)", borderLeft: "1px solid var(--panel-divider-strong)",
          padding: "18px 22px 40px", display: "grid",
          gap: 16, alignContent: "start",
        }}
      >
        <div style={{ display: "flex", gap: 12, alignItems: "baseline" }}>
          <div style={{ display: "grid", gap: 2 }}>
            <strong style={{ fontSize: 16, color: "var(--text)" }}>{host}</strong>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {profile?.found
                ? `${profile.alert_count} alert(s) · ${shortDate(profile.first_seen)} → ${shortDate(profile.last_seen)}`
                : "Everything collected about this machine"}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              marginLeft: "auto", background: "var(--panel-card-bg)", cursor: "pointer",
              border: "1px solid var(--panel-divider-strong)", borderRadius: 8,
              color: "var(--text-secondary)", fontSize: 11.5, padding: "5px 11px",
            }}
          >
            Close
          </button>
        </div>

        {loading && <LoadingState label="Reading everything stored about this host…" />}
        {!loading && error && (
          <EmptyState title="Could not load this host" hint={error} />
        )}
        {!loading && !error && profile && !profile.found && (
          <EmptyState
            title="Nothing stored for this host"
            hint="No alert run carries this hostname."
          />
        )}

        {!loading && !error && profile?.found && (
          <>
            {/* What stands out, first. An analyst opening this window has
                already decided something is interesting; the window's job is to
                say what, not to make them find it. */}
            {(profile.notable || []).length > 0 && (
              <Panel
                title="WHAT STANDS OUT"
                hint="Drawn from concluded verdicts and indicator risk, not from alert volume."
              >
                <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
                  {(profile.notable || []).map((item) => (
                    <li
                      key={item.text}
                      style={{ fontSize: 11.5, color: riskColor(item.risk), lineHeight: 1.5 }}
                    >
                      <span style={{ color: "var(--text-secondary)" }}>{item.text}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            <Panel
              title="ACTIVITY"
              hint="Alerts on event time, in lanes by evidenced tactic. Shaded bands are sessions."
            >
              <Timeline profile={profile} />
            </Panel>

            <div
              style={{
                display: "grid", gap: 12,
                gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
              }}
            >
              <Panel
                title="MOST TRIGGERED"
                hint={
                  profile.rules_total
                    ? `${profile.rules_total} distinct rule(s) have fired here`
                    : undefined
                }
              >
                <CountedRows
                  rows={(profile.rules || []).map((rule) => ({
                    label: rule.name,
                    count: rule.count,
                    risk: rule.max_risk,
                    hint: `${rule.name}${rule.id ? ` · rule ${rule.id}` : ""} · last ${shortDate(rule.last_seen)}`,
                  }))}
                  emptyLabel="No alert here carries a detection rule."
                />
              </Panel>

              <Panel
                title="BEHAVIOUR"
                hint="Tactics the investigation evidenced. Rule claims are excluded."
              >
                <CountedRows
                  rows={(profile.tactics || []).map((tactic) => ({
                    label: tactic.name,
                    count: tactic.count,
                  }))}
                  emptyLabel="No evidenced ATT&CK tactic on this host."
                />
              </Panel>

              <Panel title="VERDICTS" hint="What the alerts on this host concluded.">
                <CountedRows
                  rows={(profile.verdicts || []).map((verdict) => ({
                    label: verdict.name,
                    count: verdict.count,
                    risk:
                      verdict.name === "malicious" ? 100
                        : verdict.name === "suspicious" ? 50 : 0,
                  }))}
                  emptyLabel="No concluded verdicts."
                />
              </Panel>

              <Panel
                title="USERS"
                hint={
                  profile.users
                    ? `Carried on ${profile.users.runs_with_user} of ${profile.users.runs_total} alert(s)`
                    : undefined
                }
              >
                {profile.users && profile.users.values.length > 0 ? (
                  <CountedRows
                    rows={profile.users.values.map((user) => ({
                      label: user.name,
                      count: user.count,
                    }))}
                    emptyLabel=""
                  />
                ) : (
                  <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
                    No alert on this host carries a user. The field is populated on
                    a small minority of alerts across the estate, so its absence
                    here says nothing about who used the machine.
                  </div>
                )}
              </Panel>
            </div>

            {indicatorTypes.length > 0 && (
              <Panel
                title="COMMUNICATIONS AND ARTEFACTS"
                hint="Every indicator seen in this host's alerts, worst conclusion kept."
              >
                <div
                  style={{
                    display: "grid", gap: 12,
                    gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                  }}
                >
                  {indicatorTypes.map((type) => {
                    const items = profile.indicators?.[type] || [];
                    const total = profile.indicator_totals?.[type] ?? items.length;
                    return (
                      <div key={type} style={{ display: "grid", gap: 6 }}>
                        <span
                          style={{
                            fontSize: 10.5, color: "var(--text-muted)",
                            textTransform: "uppercase", letterSpacing: 0.5,
                          }}
                        >
                          {type} · {total} distinct
                        </span>
                        <div style={{ display: "grid", gap: 4 }}>
                          {items.map((item) => (
                            <div
                              key={item.value}
                              style={{ display: "flex", gap: 8, alignItems: "baseline" }}
                              title={`${item.value}${item.classification ? ` — ${item.classification}` : ""} · seen in ${item.count} alert(s) · last ${shortDate(item.last_seen)}`}
                            >
                              <span
                                style={{
                                  ...MONO, fontSize: 11, flex: 1,
                                  color: item.excluded ? "var(--text-muted)" : "var(--text-secondary)",
                                  overflow: "hidden", textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                  textDecoration: item.excluded ? "line-through" : "none",
                                }}
                              >
                                {item.value}
                              </span>
                              {item.risk > 0 && (
                                <span style={{ ...MONO, fontSize: 10.5, color: riskColor(item.risk) }}>
                                  {item.risk}
                                </span>
                              )}
                              <span style={{ ...MONO, fontSize: 10.5, color: "var(--text-muted)" }}>
                                x{item.count}
                              </span>
                            </div>
                          ))}
                          {total > items.length && (
                            <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
                              +{total - items.length} more
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            )}

            {(profile.sessions || []).length > 0 && (
              <Panel
                title="SESSIONS"
                hint="Stretches of activity, identified by when they began rather than by when they were read."
              >
                <div style={{ display: "grid", gap: 8 }}>
                  {(profile.sessions || []).map((session) => (
                    <div
                      key={session.case_key}
                      style={{
                        display: "flex", gap: 10, alignItems: "baseline",
                        flexWrap: "wrap", fontSize: 11.5,
                        color: "var(--text-secondary)",
                      }}
                    >
                      <span style={{ ...MONO, color: "var(--text-muted)" }}>
                        #{session.session_seq}
                      </span>
                      <span>{shortDate(session.started_at)} → {shortDate(session.last_activity_at)}</span>
                      <span style={{ ...MONO, color: riskColor(session.peak_score) }}>
                        peak {session.peak_score}/100
                      </span>
                      <span style={{ color: "var(--text-muted)" }}>{session.status}</span>
                      {session.assignee && <span>· {session.assignee}</span>}
                      {session.superseded_by && (
                        <span style={{ color: "var(--text-muted)" }}>
                          · superseded, history continues under a newer key
                        </span>
                      )}
                      {session.history.length > 1 && (
                        <span style={{ ...MONO, fontSize: 10.5, color: "var(--text-muted)" }}>
                          · {session.history.map((point) => point.score).join(" → ")}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </>
        )}
      </div>
    </div>
  );
}
