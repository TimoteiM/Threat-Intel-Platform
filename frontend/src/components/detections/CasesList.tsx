"use client";

/**
 * The correlated cases list.
 *
 * One case is one session of activity on one device. This used to be a tab on
 * the Detections page, sitting beside rule tuning and ATT&CK coverage — which
 * put "is this rule any good" and "is someone in the estate right now" behind
 * the same control. It is its own page under Security Threats.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import type { CorrelatedCasesResponse } from "@/lib/types";
import type { TenantOption } from "@/lib/api";
import { EmptyState, MetricStrip, Section } from "@/components/ui/Primitives";
import Spinner from "@/components/shared/Spinner";
import EntityWindow from "@/components/detections/EntityWindow";
import CaseNarrative from "@/components/detections/CaseNarrative";
import ClientFilter from "@/components/detections/ClientFilter";

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

type Order = "score" | "newest" | "oldest" | "alerts";

const ORDERS: Array<{ id: Order; label: string }> = [
  { id: "score", label: "Score" },
  { id: "newest", label: "Newest" },
  { id: "oldest", label: "Oldest" },
  { id: "alerts", label: "Most alerts" },
];

const VERDICTS = ["malicious", "suspicious", "benign"] as const;

const VERDICT_TONE: Record<string, string> = {
  malicious: "var(--status-critical)",
  suspicious: "var(--status-warning)",
  benign: "var(--status-ok, var(--status-info))",
};

/** The narrative states its verdict in prose — "Suspicious, not confirmed
 *  malicious" — so filtering reads the words rather than expecting a code.
 *
 *  Only the part before the first comma is read, and that is the whole point:
 *  the qualifier after it routinely names the verdict it is ruling OUT. Two
 *  stored cases say "Suspicious, not confirmed malicious", and scanning the
 *  whole string for "malicious" filed both under Malicious — turning a
 *  one-case malicious filter into three, two of which say the opposite. */
function verdictOf(item: { narrative?: { verdict?: string | null } | null }): string | null {
  const stated = (item.narrative?.verdict || "").split(/[,;]/)[0].toLowerCase();
  if (!stated) return null;
  if (stated.includes("malicious")) return "malicious";
  if (stated.includes("suspicious")) return "suspicious";
  if (stated.includes("benign")) return "benign";
  // "Inconclusive", and anything else a model chose to write. Left unbucketed
  // rather than forced into one: it is visible with no filter applied, and a
  // wrong bucket is worse than no bucket.
  return null;
}

function when(value: string | null | undefined): number {
  const ms = value ? new Date(value).getTime() : NaN;
  return Number.isNaN(ms) ? 0 : ms;
}

// Alerts are processed in real time and a case exists within a second of its
// second alert. The engine's own latency to a *fully scored* case is the
// investigation time behind it — a measured 86s median, 95s at p90, running
// concurrently across members rather than in series. A refresh slower than that
// would make the platform look slower than it is.
const CASES_REFRESH_MS = 30_000;

// The windows this page offers, and the largest the endpoint accepts. The
// Detections header's 7d/30d/90d control used to seed this: at 90d it asked
// for 2,160 hours, the API refused it with a 422, and because a failed refresh
// was swallowed the view went on showing whatever it had last succeeded with —
// a count from one window beside a list from another. Owning its own control
// is how that stops being possible.
export const CASE_WINDOWS = [48, 168, 720] as const;
const MAX_WINDOW_HOURS = 720;

export default function CasesList({
  hours,
  since,
  until,
}: {
  hours: number;
  /** An explicit range, when the analyst picked dates instead of a preset. */
  since?: string;
  until?: string;
}) {
  const [openHost, setOpenHost] = useState<string | null>(null);
  const [tenant, setTenant] = useState("");
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("");
  const [order, setOrder] = useState<Order>("score");
  const [tenants, setTenants] = useState<TenantOption[]>([]);
  const [data, setData] = useState<CorrelatedCasesResponse | null>(null);
  const [loading, setLoading] = useState(true);

  // Alerts arrive in real time and a case forms within a second of its second
  // alert, so a view that only loaded on mount would hide a live intrusion
  // behind a page the analyst had already opened. Refreshed quietly: the
  // spinner shows on the first load only, so a background refresh never blanks
  // the list someone is reading.
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null);
  const [staleSince, setStaleSince] = useState<Date | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let first = true;

    const load = () => {
      if (first) setLoading(true);
      api
        .getCorrelatedCases({
          hours,
          tenant: tenant || undefined,
          since: since || undefined,
          until: until || undefined,
          // A wide window returns far more than the default 50, and a list
          // that silently stops at 50 while the header says 300 is worse than
          // a slow one.
          limit: 500,
        })
        .then((result) => {
          if (cancelled) return;
          setData(result);
          setTenants((result as { available_tenants?: TenantOption[] }).available_tenants || []);
          setRefreshedAt(new Date());
          setStaleSince(null);
          setLoadError(null);
        })
        .catch((err) => {
          if (cancelled) return;
          // Never silently keep stale rows. A refresh that fails while the page
          // stays open is exactly how a count and a list end up describing
          // different windows.
          if (first) setData(null);
          setStaleSince((current) => current ?? new Date());
          setLoadError(err instanceof Error ? err.message : "refresh failed");
        })
        .finally(() => {
          if (cancelled) return;
          setLoading(false);
          first = false;
        });
    };

    load();
    const timer = setInterval(load, CASES_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [hours, tenant, since, until]);

  // Filtering and ordering happen here, not on the server: the whole window is
  // already in hand, so a keystroke costs nothing and never waits on a scan
  // that takes seconds. The client filter stays server-side because that one
  // is a permission boundary, not a convenience.
  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    let list = (data?.cases || []).filter((item) => {
      if (verdict && verdictOf(item) !== verdict) return false;
      if (!needle) return true;
      const haystack = [
        item.label,
        item.entity_host,
        ...(item.entity_users || []),
        ...(item.tactics || []),
        ...(item.alerts || []).slice(0, 25).map((a) => a.detection_rule_name || ""),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
    list = [...list];
    if (order === "newest") list.sort((a, b) => when(b.last_seen) - when(a.last_seen));
    else if (order === "oldest") list.sort((a, b) => when(a.first_seen) - when(b.first_seen));
    else if (order === "alerts") list.sort((a, b) => (b.alert_count || 0) - (a.alert_count || 0));
    else list.sort((a, b) => (b.score || 0) - (a.score || 0) || (b.distinct_rules || 0) - (a.distinct_rules || 0));
    return list;
  }, [data, search, verdict, order]);

  if (loading && !data) return <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Loading…</div>;
  if (!data) return <EmptyState title="Correlation could not be read" hint="The endpoint did not answer." />;

  return (
    <div style={{ display: "grid", gap: "var(--space-5)" }}>
      <MetricStrip
        metrics={[
          { label: "Cases", value: data.total_cases, status: data.total_cases ? "warning" : "success" },
          { label: "Entities watched", value: data.entities_seen },
          { label: "Senders", value: data.sources_seen, hint: "cases never span these" },
          { label: "Clients", value: data.clients_seen, hint: "cases never span these" },
        ]}
      />

      {/* No window buttons here: the page header carries the only one, so a
          reader is never asked which of two controls is in effect. */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <ClientFilter options={tenants} value={tenant} onChange={setTenant} />

        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search host, account, rule or tactic"
          aria-label="Search cases"
          style={{
            flex: "1 1 240px", minWidth: 200, borderRadius: 10,
            border: "1px solid var(--panel-divider-strong, var(--border))",
            background: "var(--panel-card-bg, transparent)",
            color: "var(--text-strong, var(--text))",
            padding: "6px 10px", fontSize: 13,
          }}
        />

        <div role="group" aria-label="Filter by verdict" style={{ display: "flex", gap: 6 }}>
          {VERDICTS.map((name) => (
            <button
              key={name}
              type="button"
              aria-pressed={verdict === name}
              onClick={() => setVerdict(verdict === name ? "" : name)}
              style={{
                border: `1px solid ${verdict === name ? VERDICT_TONE[name] : "var(--border)"}`,
                background: verdict === name ? "var(--accent-glow, transparent)" : "transparent",
                color: verdict === name ? VERDICT_TONE[name] : "var(--text-dim)",
                borderRadius: 999, padding: "5px 12px", fontSize: 12,
                cursor: "pointer", textTransform: "capitalize",
              }}
            >
              {name}
            </button>
          ))}
        </div>

        <label style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <span style={{
            fontSize: "var(--font-micro, 10px)", fontWeight: 700,
            letterSpacing: "0.06em", textTransform: "uppercase",
            color: "var(--text-muted)",
          }}>
            Order
          </span>
          <select
            value={order}
            onChange={(e) => setOrder(e.target.value as Order)}
            aria-label="Order cases"
            style={{
              borderRadius: 10,
              border: "1px solid var(--panel-divider-strong, var(--border))",
              background: "var(--panel-card-bg, transparent)",
              color: "var(--text-strong, var(--text))",
              padding: "6px 10px", fontSize: 13,
            }}
          >
            {ORDERS.map((o) => (
              <option key={o.id} value={o.id}>{o.label}</option>
            ))}
          </select>
        </label>
        {staleSince && (
          <span style={{ fontSize: 10.5, color: "var(--status-warning)" }}>
            not refreshing since {staleSince.toLocaleTimeString()}
            {loadError ? ` — ${loadError}` : ""}
          </span>
        )}
        {refreshedAt && (
          <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-muted)", ...MONO }}>
            updated {refreshedAt.toLocaleTimeString()} · refreshes every {CASES_REFRESH_MS / 1000}s
          </span>
        )}
      </div>

      {openHost && <EntityWindow host={openHost} onClose={() => setOpenHost(null)} />}

      {shown.length === 0 ? (
        // Two different nothings. "No case matched your filter" and "nothing
        // correlated at all" ask for opposite next actions, and one message
        // for both sends an analyst to widen a window that was never the
        // problem.
        data.cases.length > 0 ? (
          <EmptyState
            title="No case matches these filters"
            hint={`${data.cases.length} case(s) in this window. Clear the search or the verdict filter to see them.`}
          />
        ) : (
          <EmptyState
            title="Nothing correlated in this window"
            hint="A case needs two independent detections on one entity. One rule firing repeatedly is not a case — which is the point."
          />
        )
      ) : (
        <Section
          title={
            shown.length === data.cases.length
              ? "Cases"
              : `Cases — ${shown.length} of ${data.cases.length}`
          }
          hint="Alerts within a case are newest first. Select one to open it."
        >
          <div style={{ display: "grid", gap: "var(--space-4)" }}>
            {shown.map((item) => (
              // Keyed on the case, not on its host. A host can hold several
              // sessions now, so source:client:host collided — 20 cases shared
              // 13 keys — and React kept stale rows from the previous window
              // alongside the new ones. That is why the list could be counted
              // as thirty while the header, reading the same response, said
              // twenty.
              <div key={item.case_key} style={{ display: "grid", gap: 6 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                  <a
                    href={`/detections/cases/${item.case_key}`}
                    title="Open the full case"
                    style={{
                      color: "var(--text)", fontSize: 13, fontWeight: 600,
                      textDecoration: "none",
                      borderBottom: "1px solid var(--panel-divider-strong)",
                    }}
                  >
                    {item.label || item.entity_host}
                  </a>
                  <button
                    type="button"
                    onClick={() => setOpenHost(item.entity_host)}
                    title={`Everything collected about ${item.entity_host}, across all its cases`}
                    style={{
                      color: "var(--text)", fontSize: 13, fontWeight: 600, padding: 0,
                      background: "none", border: "none",
                      borderBottom: "1px dotted var(--panel-divider-strong)",
                      cursor: "pointer", fontFamily: "inherit",
                    }}
                  >
                    device
                  </button>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", ...MONO }}>
                    {item.source}
                    {item.client && item.client !== "unknown" ? ` / ${item.client}` : ""}
                  </span>
                  <span
                    style={{
                      marginLeft: "auto", ...MONO, fontSize: 12,
                      color: item.score >= 70 ? "var(--status-danger)" : "var(--status-warning)",
                    }}
                  >
                    {item.score}/100
                  </span>
                </div>
                {/* The conclusion first. The reasons below explain why the
                    engine grouped these alerts; this says what they were. An
                    analyst who reads only one thing on this row should read
                    this one. */}
                {(item.members_investigating ?? 0) > 0 && (
                  <div style={{ fontSize: 11, color: "var(--status-warning)" }}>
                    {item.members_investigating} of {item.alert_count} alerts still
                    investigating — tactics, verdicts and the score will rise as they finish
                  </div>
                )}

                <CaseNarrative item={item} />

                {/* The list is scanned, so it carries the conclusion and one line
                    of why. Everything that used to compete for room here — the
                    reasons, the rules, the timeline, the indicators — is on the
                    case page, which is where the case is actually worked. */}
                <div style={{ display: "flex", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {item.distinct_rules} independent detections ·{" "}
                    {(item.tactics || []).length} tactic(s)
                    {item.tactics?.length ? ` reaching ${item.tactics[item.tactics.length - 1]}` : ""}
                  </span>
                  {/* Dated on event time, and separately on when we were told.
                      Alerts here arrive replayed — this deployment has an
                      18-day gap on a live case — so "when did this happen" and
                      "when did we find out" are different questions and a row
                      showing only one of them invites the wrong answer. */}
                  <span
                    style={{ fontSize: 11, color: "var(--text-muted)" }}
                    title={
                      item.first_ingested
                        ? `Reported to this platform ${new Date(item.first_ingested).toLocaleString()}`
                        : undefined
                    }
                  >
                    began {item.first_seen ? new Date(item.first_seen).toLocaleString() : "—"}
                    {" · last activity "}
                    {item.last_seen ? new Date(item.last_seen).toLocaleString() : "—"}
                  </span>
                  <a
                    href={`/detections/cases/${item.case_key}`}
                    style={{ fontSize: 11.5, color: "var(--accent)", textDecoration: "none" }}
                  >
                    open the full case →
                  </a>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}
