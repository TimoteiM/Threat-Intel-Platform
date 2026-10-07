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
import { shortDate } from "@/components/detections/panels";
import Pager from "@/components/shared/Pager";
import { toInstant } from "@/components/shared/TimeWindow";
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
          since: toInstant(since) || undefined,
          until: toInstant(until) || undefined,
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
        item.case_number ? `#${item.case_number}` : "",
        String(item.case_number ?? ""),
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

  // 25 a page. The list ran to 946 rows in one scroll, which is not a list
  // anybody reads — it is a list somebody gives up on.
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);

  // Any change to what is being shown returns to the first page. Staying on
  // page 12 of a filter that now has three results shows nothing, and reads
  // as "no cases" rather than "you are past the end".
  useEffect(() => {
    setPage(0);
  }, [search, verdict, order, tenant, hours, since, until, pageSize]);

  // Clamped the same way the pager clamps it. A background refresh can return
  // fewer cases without any filter changing — a case closing out of the
  // window does it — and an unclamped slice would then render an empty table
  // under a pager still reporting a valid page.
  const paged = useMemo(() => {
    const last = Math.max(0, Math.ceil(shown.length / pageSize) - 1);
    const current = Math.min(page, last);
    return shown.slice(current * pageSize, current * pageSize + pageSize);
  }, [shown, page, pageSize]);

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
          hint="Every case has the same shape. Select one to open it."
        >
          {/* One shape for every case.
              The list used to render each case as a card whose body was the AI
              narrative, tinted by verdict — so a page of cases was a page of
              green, red and grey blocks of different heights, and two cases
              were never comparable at a glance. A case is a record with a
              status, a number, a severity and an owner; it reads as a table,
              and colour carries severity and nothing else. */}
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr>
                  {["Status", "Case", "Severity", "Source", "Resolution", "Alerts",
                    "Opened", "Last activity", "Closed"].map((head) => (
                    <th key={head} style={th}>{head}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paged.map((item) => {
                  // Keyed on the case, not its host: a host holds several
                  // sessions now, so source:client:host collided and React
                  // kept stale rows beside new ones.
                  const lifecycle = item.lifecycle || {};
                  const closed = Boolean(lifecycle.closed_at);
                  return (
                    <tr key={item.case_key} style={rowStyle}>
                      <td style={td}>
                        <StatusChip closed={closed} kind={lifecycle.closure_kind} />
                      </td>
                      <td style={{ ...td, maxWidth: 520 }}>
                        <a href={`/detections/cases/${item.case_key}`} style={caseLink}>
                          {item.case_number ? `#${item.case_number}` : "—"}
                          <span style={{ color: "var(--text-muted)" }}>{" · "}</span>
                          {item.label || item.entity_host}
                        </a>
                        {item.continues?.case_number ? (
                          <div style={subtle}>
                            continues{" "}
                            <a
                              href={`/detections/cases/${item.continues.case_key}`}
                              style={{ color: "var(--accent)" }}
                            >
                              #{item.continues.case_number}
                            </a>
                          </div>
                        ) : null}
                      </td>
                      <td style={td}><SeverityPill score={item.score} /></td>
                      <td style={{ ...td, ...MONO, fontSize: 11, color: "var(--text-muted)" }}>
                        {item.source}
                        {item.client && item.client !== "unknown" ? ` / ${item.client}` : ""}
                      </td>
                      <td style={td}>
                        {lifecycle.resolution ? (
                          <span style={subtle}>
                            {String(lifecycle.resolution).replace(/_/g, " ")}
                          </span>
                        ) : (
                          <span style={{ ...subtle, opacity: 0.6 }}>—</span>
                        )}
                      </td>
                      <td style={{ ...td, ...MONO, whiteSpace: "nowrap" }}>
                        {item.alert_count}
                        <span style={{ color: "var(--text-muted)" }}>
                          {" · "}{item.distinct_rules} rule{item.distinct_rules === 1 ? "" : "s"}
                        </span>
                      </td>
                      <td style={{ ...td, ...MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                        {shortDate(item.first_seen)}
                      </td>
                      <td style={{ ...td, ...MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                        {shortDate(item.last_seen)}
                      </td>
                      <td style={{ ...td, ...MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                        {lifecycle.closed_at ? shortDate(lifecycle.closed_at) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager
            total={shown.length}
            page={page}
            pageSize={pageSize}
            onPage={setPage}
            onPageSize={setPageSize}
            noun="cases"
          />
        </Section>
      )}
    </div>
  );
}

// ── one shape for every row ──────────────────────────────────────────────────
//
// Colour carries severity and nothing else. The previous list tinted each
// case by its AI verdict, so the page read as a wall of green, red and grey
// blocks of different heights and no two cases were comparable at a glance.

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "7px 12px 7px 0",
  borderBottom: "1px solid var(--panel-divider-strong, var(--border))",
  fontSize: 10.5,
  letterSpacing: 0.4,
  textTransform: "uppercase",
  color: "var(--text-dim)",
  fontWeight: 600,
  whiteSpace: "nowrap",
};

const td: React.CSSProperties = {
  padding: "9px 12px 9px 0",
  borderBottom: "1px solid var(--panel-divider, var(--border))",
  verticalAlign: "top",
  color: "var(--text-secondary)",
};

const rowStyle: React.CSSProperties = { background: "transparent" };

const subtle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-muted)",
  textTransform: "capitalize",
};

const caseLink: React.CSSProperties = {
  color: "var(--text)",
  fontSize: 13,
  fontWeight: 600,
  textDecoration: "none",
};

/** Open or Closed, and — only when it is not the ordinary case — how. */
function StatusChip({ closed, kind }: { closed: boolean; kind?: string | null }) {
  const label = closed ? "Closed" : "Open";
  return (
    <span
      title={
        closed
          ? kind === "analyst"
            ? "Closed by an analyst, without waiting for the quiet period"
            : kind === "aged_out"
            ? "Closed without an answer: its alerts left the correlation window"
            : kind === "inherited"
            ? "Closed with the resolution its parent case was already given"
            : "Answered automatically after its alerts stopped arriving"
          : "Still receiving alerts, or waiting for its quiet period"
      }
      style={{
        display: "inline-block",
        minWidth: 62,
        textAlign: "center",
        padding: "2px 9px",
        borderRadius: 6,
        fontSize: 11,
        fontWeight: 600,
        border: `1px solid ${closed ? "var(--panel-divider-strong)" : "var(--status-warning)"}`,
        color: closed ? "var(--text-muted)" : "var(--status-warning)",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

/** Severity, as the one thing colour is allowed to mean on this page. */
function SeverityPill({ score }: { score?: number | null }) {
  const n = Number(score ?? 0);
  const [letter, tone, title] =
    n >= 75
      ? ["H", "var(--status-critical)", "High"]
      : n >= 40
      ? ["M", "var(--status-warning)", "Medium"]
      : ["L", "var(--status-info, #388bfd)", "Low"];
  return (
    <span
      title={`${title} — ${n}/100`}
      style={{
        display: "inline-block", width: 22, textAlign: "center",
        padding: "1px 0", borderRadius: 5, fontSize: 11, fontWeight: 700,
        border: `1px solid ${tone}`, color: tone,
      }}
    >
      {letter}
    </span>
  );
}
