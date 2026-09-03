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

import React, { useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import type { EntityProfile } from "@/lib/types";
import { EmptyState, LoadingState } from "@/components/ui/Primitives";

const MONO: React.CSSProperties = {
  fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)",
};

/** Risk to colour, used identically everywhere so one hue always means one thing. */
function riskColor(risk: number): string {
  if (risk >= 70) return "var(--status-danger)";
  if (risk >= 40) return "var(--status-warning)";
  return "var(--text-muted)";
}

function verdictColor(verdict: string | null): string {
  const value = (verdict || "").toLowerCase();
  if (value === "malicious") return "var(--status-danger)";
  if (value === "suspicious") return "var(--status-warning)";
  if (value === "benign") return "var(--status-success)";
  return "var(--text-muted)";
}

function shortDate(iso: string | null | undefined): string {
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
function Timeline({ profile }: { profile: EntityProfile }) {
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

function CountedRows({
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

function Panel({ title, hint, children }: {
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
