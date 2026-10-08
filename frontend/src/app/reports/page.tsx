"use client";

/**
 * Reports — what the service actually did, for one client, in one month.
 *
 * The figures a monthly service review is written from: how many cases, how
 * severe, how they were resolved, and how long detection and response took
 * against the target.
 *
 * Everything here is derived from stored timestamps on request rather than
 * kept as a running total, so a definition that turns out to be wrong is a
 * query away from being right instead of a backfill.
 *
 * Two things this page refuses to do, because both are how a service report
 * comes to flatter:
 *
 *   * It never prints a mean over a population that cannot support one. A
 *     month whose cases were all closed by a later catch-up has no measurable
 *     response time, and it says so rather than reporting the arithmetic.
 *   * It never hides what it left out. Every exclusion is counted on the page,
 *     next to the number it was excluded from.
 */

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import {
  getCaseReport,
  getCaseReportOptions,
  type CaseReport,
  type CaseReportOptions,
  type CaseReportStats,
} from "@/lib/api";
import { EmptyState, Page, PageHeader, Section } from "@/components/ui/Primitives";

const MONTH_NAMES = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

function monthLabel(value: string) {
  const [year, month] = String(value || "").split("-");
  const index = Number(month) - 1;
  return MONTH_NAMES[index] ? `${MONTH_NAMES[index]} ${year}` : value;
}

/** Seconds as the largest unit that still reads as a duration. */
function duration(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined) return null;
  if (seconds < 90) return `${Math.round(seconds)}s`;
  const minutes = seconds / 60;
  if (minutes < 90) return `${minutes.toFixed(1)} min`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)} h`;
  return `${(hours / 24).toFixed(1)} days`;
}

export default function ReportsPage() {
  return (
    <Suspense fallback={null}>
      <ReportsPageInner />
    </Suspense>
  );
}

function ReportsPageInner() {
  // The selection lives in the URL, so a particular month for a particular
  // client is a link somebody can send to a colleague or put in a review pack.
  const router = useRouter();
  const params = useSearchParams();
  const month = params.get("month") || "";
  const client = params.get("client") || "all";

  const [options, setOptions] = useState<CaseReportOptions | null>(null);
  const [report, setReport] = useState<CaseReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const write = useCallback(
    (next: { month?: string; client?: string }) => {
      const query = new URLSearchParams(params.toString());
      Object.entries(next).forEach(([key, value]) => {
        if (!value) query.delete(key);
        else query.set(key, value);
      });
      router.replace(`?${query.toString()}`, { scroll: false });
    },
    [params, router],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const opts = await getCaseReportOptions();
        if (cancelled) return;
        setOptions(opts);
        // Default to the most recent month that has cases, rather than to the
        // calendar's current month, which may be empty.
        if (!month && opts.months.length) write({ month: opts.months[0].month });
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not read the reporting options.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // Intentionally once: the options are the estate's history, not a function
    // of the current selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    void (async () => {
      try {
        const data = await getCaseReport({ month: month || undefined, client });
        if (!cancelled) setReport(data);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not build the report.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [month, client]);

  const targetLabel = useMemo(
    () => (report ? duration(report.sla.target_seconds) : null),
    [report],
  );

  return (
    <Page>
      <PageHeader
        title="Reports"
        subtitle="Case volume, severity, outcomes and response times for one client in one month — the figures a service review is written from."
        actions={
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <label style={label}>
              <span style={caption}>Client</span>
              <select value={client} onChange={(e) => write({ client: e.target.value })} style={control}>
                <option value="all">All clients</option>
                {(options?.clients || []).map((c) => (
                  <option key={c.tenant_id} value={c.tenant_id}>
                    {c.label} ({c.cases.toLocaleString()})
                  </option>
                ))}
              </select>
            </label>
            <label style={label}>
              <span style={caption}>Month</span>
              <select value={month} onChange={(e) => write({ month: e.target.value })} style={control}>
                <option value="all">All months</option>
                {/* Only months the estate actually has. A month with no cases
                    is not offered, so an empty report always means the filter
                    found nothing rather than that the month never existed. */}
                {(options?.months || []).map((m) => (
                  <option key={m.month} value={m.month}>
                    {monthLabel(m.month)} ({m.cases.toLocaleString()})
                  </option>
                ))}
              </select>
            </label>
          </div>
        }
      />

      {error && <EmptyState title="The report could not be built" hint={error} />}

      {!error && loading && !report && (
        <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Building…</div>
      )}

      {!error && report && (
        <>
          <Section
            title="The month"
            hint={
              report.scope.all_tenants
                ? "Every client you may read."
                : "Your client's cases only."
            }
          >
            <div style={grid}>
              <Tile label="Cases" value={report.cases_total.toLocaleString()} />
              <Tile label="Still open" value={report.cases_open.toLocaleString()} />
              <Tile
                label="Alerts in closed cases"
                value={report.alerts_in_closed_cases.toLocaleString()}
              />
              <Tile label="SLA target" value={targetLabel || "—"} />
            </div>
          </Section>

          <Section
            title="Detection and response"
            hint={
              "Single-alert and multi-alert cases are reported apart: they are not the " +
              "same work, and a mean that mixes them is mostly a measure of how many " +
              "single alerts arrived."
            }
          >
            <table style={table}>
              <thead>
                <tr>
                  <th style={th}>Population</th>
                  <th style={th}>Cases</th>
                  <th style={th}>Measurable</th>
                  <th style={th}>MTTD</th>
                  <th style={th}>MTTR</th>
                  <th style={th}>Within target</th>
                  <th style={th}>Breached</th>
                </tr>
              </thead>
              <tbody>
                <StatRow name="All cases" stats={report.sla.all} strong />
                <StatRow name="Single alert" stats={report.sla.single_alert} />
                <StatRow name="More than one alert" stats={report.sla.multi_alert} />
              </tbody>
            </table>
          </Section>

          <div style={{ display: "grid", gap: 14, gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            <Section title="Severity" hint="By the case's peak correlation score.">
              <Bars
                rows={[
                  { key: "High (75+)", value: report.severity.high, tone: "var(--status-critical)" },
                  { key: "Medium (40–74)", value: report.severity.medium, tone: "var(--status-warning)" },
                  { key: "Low (under 40)", value: report.severity.low, tone: "var(--status-info, #388bfd)" },
                ]}
              />
            </Section>

            <Section title="How they were resolved" hint="As the case was closed.">
              <Bars
                rows={Object.entries(report.resolutions).map(([key, value]) => ({
                  key: key.replace(/_/g, " "),
                  value,
                  tone:
                    key === "true_positive"
                      ? "var(--status-critical)"
                      : key === "needs_review"
                      ? "var(--status-warning)"
                      : "var(--text-dim)",
                }))}
              />
            </Section>
          </div>

          <Section
            title="What these figures leave out"
            hint="Stated rather than applied quietly — an average is only as honest as the population behind it."
          >
            <div style={grid}>
              <Tile
                label="Closed by a later sweep"
                value={report.excluded.closed_by_later_sweep.toLocaleString()}
                hint="Not answered within the response window, so not in MTTR."
              />
              <Tile
                label="Never answered"
                value={report.excluded.never_answered.toLocaleString()}
                hint="Aged out, expired, or merged into another case."
              />
              <Tile
                label="No honest detection time"
                value={report.excluded.backfilled_detection.toLocaleString()}
                hint="Recorded long after the alert — a backfill, not a detection."
              />
            </div>
            <p style={{ fontSize: 11.5, color: "var(--text-muted)", marginTop: 10, lineHeight: 1.6 }}>
              {report.excluded.note}
            </p>
          </Section>
        </>
      )}
    </Page>
  );
}

function StatRow({ name, stats, strong }: { name: string; stats: CaseReportStats; strong?: boolean }) {
  const mttd = duration(stats.mttd_seconds);
  const mttr = duration(stats.mttr_seconds);
  return (
    <tr>
      <td style={{ ...td, fontWeight: strong ? 600 : 400 }}>{name}</td>
      <td style={td}>{stats.cases.toLocaleString()}</td>
      <td style={td}>{stats.closed.toLocaleString()}</td>
      {/* "Not measurable" rather than a dash or a zero: a month whose cases
          were all swept up has no response time, and either of the other two
          would read as one. */}
      <td style={td}>{mttd ?? <NotMeasurable />}</td>
      <td style={td}>{mttr ?? <NotMeasurable />}</td>
      <td style={td}>{stats.closed ? stats.sla_met.toLocaleString() : "—"}</td>
      <td style={{ ...td, color: stats.sla_breached ? "var(--status-critical)" : undefined }}>
        {stats.closed ? stats.sla_breached.toLocaleString() : "—"}
      </td>
    </tr>
  );
}

function NotMeasurable() {
  return (
    <span
      style={{ color: "var(--text-dim)", fontStyle: "italic" }}
      title="No case in this population was answered within the response window, so there is no mean to report."
    >
      not measurable
    </span>
  );
}

function Bars({ rows }: { rows: Array<{ key: string; value: number; tone: string }> }) {
  const total = rows.reduce((sum, r) => sum + r.value, 0);
  if (!total) return <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Nothing in this month.</div>;
  return (
    <div style={{ display: "grid", gap: 8 }}>
      {rows.map((row) => (
        <div key={row.key} style={{ display: "grid", gap: 4 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
            <span style={{ textTransform: "capitalize" }}>{row.key}</span>
            <span style={{ color: "var(--text-muted)", fontVariantNumeric: "tabular-nums" }}>
              {row.value.toLocaleString()} · {((row.value / total) * 100).toFixed(0)}%
            </span>
          </div>
          <div style={{ height: 6, borderRadius: 999, background: "var(--panel-divider, var(--border))" }}>
            <div
              style={{
                width: `${(row.value / total) * 100}%`,
                height: "100%", borderRadius: 999, background: row.tone,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function Tile({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--panel-divider, var(--border))",
        borderRadius: 10, padding: "10px 12px", minWidth: 0,
      }}
    >
      <div style={caption}>{label}</div>
      <div style={{ fontSize: 22, fontVariantNumeric: "tabular-nums", marginTop: 2 }}>{value}</div>
      {hint && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, lineHeight: 1.5 }}>
          {hint}
        </div>
      )}
    </div>
  );
}

const caption: React.CSSProperties = {
  fontSize: "var(--font-micro, 10px)", fontWeight: 700,
  letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)",
};

const control: React.CSSProperties = {
  borderRadius: 10,
  border: "1px solid var(--panel-divider-strong, var(--border))",
  background: "var(--panel-card-bg, transparent)",
  color: "var(--text-strong, var(--text))",
  padding: "6px 10px", fontSize: 13,
};

const label: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 6 };

const grid: React.CSSProperties = {
  display: "grid", gap: 12,
  gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
};

const table: React.CSSProperties = {
  width: "100%", borderCollapse: "collapse", fontSize: 13,
  fontVariantNumeric: "tabular-nums",
};

const th: React.CSSProperties = {
  textAlign: "left", padding: "6px 10px 8px 0",
  borderBottom: "1px solid var(--panel-divider-strong, var(--border))",
  fontSize: "var(--font-micro, 10px)", fontWeight: 700,
  letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)",
};

const td: React.CSSProperties = {
  padding: "8px 10px 8px 0",
  borderBottom: "1px solid var(--panel-divider, var(--border))",
};
