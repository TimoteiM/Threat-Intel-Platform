"use client";

/**
 * Reports — what the service did for one client in one month.
 *
 * Alerts in, cases out, how severe, how fast, and what they turned out to be.
 *
 * Every figure is derived from stored timestamps on request rather than kept
 * as a running total, so a definition that turns out to be wrong is a query
 * away from being right instead of a backfill.
 *
 * **Alerts and cases are two charts, not one with two axes.** The dashboard
 * this is modelled on plots 22,004 alerts and 1,163 cases against a left and a
 * right scale, and where those two lines cross is decided by the scales rather
 * than by anything that happened — slide one axis and the "crossover" moves.
 * Two panels over a shared month read the same way and cannot mislead.
 *
 * The severity palette is validated, not chosen by eye: four hues checked for
 * colour-vision separation, chroma and contrast against both surfaces. Red and
 * amber sit at ΔE 11.7 under deuteranopia, which is the one pair a severity
 * ramp always gets wrong. Amber runs brighter than the dark-mode lightness
 * band on purpose — pulling it into band collapsed that separation to ΔE 1.8,
 * and a band is a consistency preference where separation is whether somebody
 * can read the chart at all. Every severity mark carries its number, which is
 * also what the amber's light-mode contrast requires.
 */

import React, { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  getCaseReport,
  getCaseReportOptions,
  type CaseReport,
  type CaseReportOptions,
  type CaseReportTiming,
} from "@/lib/api";
import { EmptyState, Page, PageHeader, Section } from "@/components/ui/Primitives";

/** Severity, in the fixed order it is always drawn in. Colour follows the
 *  band, never its rank in the current month — a filter that empties the
 *  critical band must not repaint the others. */
const SEVERITY = [
  { id: "critical", label: "Critical", color: "#e04a33" },
  { id: "high", label: "High", color: "#caa63b" },
  { id: "medium", label: "Medium", color: "#4387d6" },
  { id: "low", label: "Low", color: "#2e9e6b" },
] as const;

const ALERT_COLOR = "#e04a33";
const CASE_COLOR = "#4387d6";

const MONTHS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

function monthLabel(value: string) {
  const [year, month] = String(value || "").split("-");
  const index = Number(month) - 1;
  return MONTHS[index] ? `${MONTHS[index]} ${year}` : value;
}

function dayLabel(value: string) {
  return String(value || "").slice(8) || value;
}

export default function ReportsPage() {
  return (
    <Suspense fallback={null}>
      <ReportsPageInner />
    </Suspense>
  );
}

function ReportsPageInner() {
  // The selection lives in the URL, so one month for one client is a link
  // somebody can put in a review pack.
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
        // The most recent month that has cases, rather than the calendar's
        // current month, which may be empty.
        if (!month && opts.months.length) write({ month: opts.months[0].month });
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not read the options.");
      }
    })();
    return () => { cancelled = true; };
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
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not build the report.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [month, client]);

  const severityRows = useMemo(
    () =>
      report
        ? SEVERITY.map((s) => ({
            name: s.label,
            value: report.severity[s.id as keyof typeof report.severity] ?? 0,
            color: s.color,
          }))
        : [],
    [report],
  );

  const timingRows = useCallback(
    (source: Record<string, CaseReportTiming>) =>
      SEVERITY.map((s) => {
        const cell = source[s.id];
        const measured = cell?.median !== null && cell?.median !== undefined;
        const value = cell?.median ?? 0;
        return {
          name: s.label,
          value,
          measured,
          mean: cell?.mean ?? null,
          count: cell?.count ?? 0,
          // Computed here, not in a LabelList formatter: Recharts does not
          // hand the row to one, so reading `measured` off its second
          // argument was always undefined and every bar printed "not
          // measured" while the tooltip showed the real figure.
          label: measured ? `${value.toFixed(1)} (n=${cell?.count ?? 0})` : "not measured",
          color: s.color,
        };
      }),
    [],
  );

  const resolutionRows = useMemo(() => {
    if (!report) return [];
    // True positive always shown, even at zero: a month with no confirmed
    // detection is a finding, and a row that disappears when it is zero reads
    // as though the question was never asked.
    const order = ["true_positive", "needs_review", "inconclusive", "false_positive"];
    const known = new Set(order);
    const rest = Object.keys(report.resolutions).filter((k) => !known.has(k));
    return [...order, ...rest].map((key) => ({
      name: key.replace(/_/g, " "),
      value: report.resolutions[key] ?? 0,
      color:
        key === "true_positive" ? "#e04a33"
        : key === "needs_review" ? "#caa63b"
        : key === "inconclusive" ? "#4387d6"
        : key === "false_positive" ? "#2e9e6b"
        : "var(--text-dim)",
    }));
  }, [report]);

  return (
    <Page>
      <PageHeader
        title="Reports"
        subtitle="Alerts, cases, severity and response times for one client in one month."
        actions={
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <label style={labelStyle}>
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
            <label style={labelStyle}>
              <span style={caption}>Month</span>
              <select value={month} onChange={(e) => write({ month: e.target.value })} style={control}>
                <option value="all">All months</option>
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
          <div style={kpiGrid}>
            <Kpi label="Alerts triggered" value={report.alerts_triggered} tone={ALERT_COLOR} />
            <Kpi label="Cases created" value={report.cases_created} tone={CASE_COLOR} />
            <Kpi label="Cases closed" value={report.cases_closed} tone="#2e9e6b" />
            <Kpi label="Cases active" value={report.cases_active} tone="#caa63b" />
          </div>

          <Section
            title="Alerts and cases through the month"
            hint="Two panels over the same days rather than one chart with two scales — where two lines of very different size cross is decided by the scales, not by anything that happened."
          >
            <DayArea data={report.by_day} dataKey="alerts" name="Alerts triggered" color={ALERT_COLOR} />
            <div style={{ height: 10 }} />
            <DayArea data={report.by_day} dataKey="cases" name="Cases created" color={CASE_COLOR} />
          </Section>

          <div style={twoUp}>
            <Section title="Cases by severity">
              <CountBars rows={severityRows} />
            </Section>
            <Section title="Case resolution status" hint="What each case was closed as.">
              <CountBars rows={resolutionRows} />
            </Section>
          </div>

          <div style={twoUp}>
            <Section
              title="Response time"
              hint="Minutes from the first alert until the platform had a case about it. The bar is the typical case (median); the tooltip carries the average and how many cases are behind it."
            >
              <TimingBars rows={timingRows(report.response_minutes)} />
            </Section>
            <Section
              title="Resolution time"
              hint="Minutes from the first alert until the case was answered. Median, with the average in the tooltip."
            >
              <TimingBars rows={timingRows(report.resolution_minutes)} />
              {report.resolution_excludes_swept > 0 && (
                <p style={footnote}>
                  {report.resolution_excludes_swept.toLocaleString()} case
                  {report.resolution_excludes_swept === 1 ? "" : "s"} closed more than six hours
                  after their last alert are left out: they were closed by a later sweep rather
                  than answered, and counting them reported one month as a mean of 21.8 days.
                </p>
              )}
            </Section>
          </div>

          {report.alerts_timestamped_ahead > 0 && (
            <p style={footnote}>
              {report.alerts_timestamped_ahead.toLocaleString()} alert
              {report.alerts_timestamped_ahead === 1 ? " is" : "s are"} timestamped later than
              the moment we received {report.alerts_timestamped_ahead === 1 ? "it" : "them"} — a
              clock or timezone fault at the source. A negative detection time is clamped to
              zero, so {report.alerts_timestamped_ahead === 1 ? "it reports" : "they report"} as
              detected instantly and pull these figures down.
            </p>
          )}

          <Section title="Cases by severity, day by day">
            <SeverityByDay data={report.by_day} />
          </Section>

          <Section title="What produced the most cases" hint="The ten detections behind the month.">
            <TopDetections rows={report.top_detections} />
          </Section>
        </>
      )}
    </Page>
  );
}

/* ── charts ──────────────────────────────────────────────────────────────── */

function DayArea({
  data, dataKey, name, color,
}: {
  data: CaseReport["by_day"]; dataKey: "alerts" | "cases"; name: string; color: string;
}) {
  if (!data.length) return <Nothing />;
  return (
    <div style={{ width: "100%", height: 150 }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`fill-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={color} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--panel-divider)" vertical={false} />
          <XAxis dataKey="date" tickFormatter={dayLabel} tick={axisTick} tickLine={false} axisLine={false} minTickGap={14} />
          <YAxis tick={axisTick} tickLine={false} axisLine={false} width={44} allowDecimals={false} />
          <Tooltip content={<DayTip label={name} />} cursor={{ stroke: "var(--text-dim)", strokeWidth: 1 }} />
          {/* One series, so the panel title names it and no legend box is needed. */}
          <Area
            type="monotone" dataKey={dataKey} name={name}
            stroke={color} strokeWidth={2} fill={`url(#fill-${dataKey})`}
            dot={false} activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--panel-card-bg, #0d0f18)" }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function SeverityByDay({ data }: { data: CaseReport["by_day"] }) {
  if (!data.length) return <Nothing />;
  return (
    <div style={{ width: "100%", height: 240 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="var(--panel-divider)" vertical={false} />
          <XAxis dataKey="date" tickFormatter={dayLabel} tick={axisTick} tickLine={false} axisLine={false} minTickGap={10} />
          <YAxis tick={axisTick} tickLine={false} axisLine={false} width={44} allowDecimals={false} />
          <Tooltip content={<StackTip />} cursor={{ fill: "var(--panel-divider)", fillOpacity: 0.35 }} />
          <Legend wrapperStyle={legendStyle} iconType="circle" iconSize={8} />
          {SEVERITY.map((s, index) => (
            <Bar
              key={s.id} dataKey={s.id} name={s.label} stackId="severity" fill={s.color}
              // A 2px surface gap between stacked segments, so adjacent
              // severities read as separate marks and not one block.
              stroke="var(--panel-card-bg, #0d0f18)" strokeWidth={2}
              radius={index === 0 ? [3, 3, 0, 0] : undefined}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Horizontal bars with the number printed on every mark. The number is not
 *  decoration: the amber step falls below 3:1 on the light surface, and a
 *  visible label is what that is allowed with. */
function CountBars({ rows }: { rows: Array<{ name: string; value: number; color: string }> }) {
  const total = rows.reduce((sum, r) => sum + r.value, 0);
  if (!total) return <Nothing />;
  return (
    <div style={{ width: "100%", height: Math.max(130, rows.length * 34) }}>
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 44, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--panel-divider)" horizontal={false} />
          <XAxis type="number" tick={axisTick} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="name" tick={axisTick} tickLine={false} axisLine={false} width={104} />
          <Tooltip content={<CountTip total={total} />} cursor={{ fill: "var(--panel-divider)", fillOpacity: 0.35 }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
            {rows.map((row) => (
              <Cell key={row.name} fill={row.color} />
            ))}
            <LabelList
              dataKey="value" position="right" style={labelText}
              formatter={(v: any) => Number(v ?? 0).toLocaleString()}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TimingBars({
  rows,
}: {
  rows: Array<{ name: string; value: number; measured: boolean; color: string }>;
}) {
  if (!rows.some((r) => r.measured)) {
    return (
      <div style={{ fontSize: 12, color: "var(--text-muted)", padding: "18px 0" }}>
        Nothing in this month was answered within the response window, so there is no mean to
        report. Not zero — unmeasured.
      </div>
    );
  }
  return (
    <div style={{ width: "100%", height: 150 }}>
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 56, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--panel-divider)" horizontal={false} />
          <XAxis type="number" tick={axisTick} tickLine={false} axisLine={false} unit=" min" />
          <YAxis type="category" dataKey="name" tick={axisTick} tickLine={false} axisLine={false} width={74} />
          <Tooltip content={<MinutesTip />} cursor={{ fill: "var(--panel-divider)", fillOpacity: 0.35 }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
            {rows.map((row) => (
              <Cell key={row.name} fill={row.measured ? row.color : "var(--panel-divider)"} />
            ))}
            {/* "not measured" rather than 0: a severity nothing was answered
                in has no mean, and a zero would read as instant.

                The text is computed in the data, not in a formatter.
                Recharts does not hand the row to a LabelList formatter — the
                second argument is not the datum — so reading `measured` off
                it was always undefined and every bar printed "not measured"
                while its tooltip, which does get the row, showed the real
                figure. */}
            <LabelList dataKey="label" position="right" style={labelText} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopDetections({ rows }: { rows: CaseReport["top_detections"] }) {
  if (!rows.length) return <Nothing />;
  return (
    <div style={{ width: "100%", height: Math.max(180, rows.length * 30) }}>
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 48, bottom: 4, left: 4 }}>
          <CartesianGrid stroke="var(--panel-divider)" horizontal={false} />
          <XAxis type="number" tick={axisTick} tickLine={false} axisLine={false} allowDecimals={false} />
          {/* Horizontal, because detection names are sentences and a vertical
              axis would turn them on their side or truncate them. */}
          <YAxis
            type="category" dataKey="detection" tick={axisTick} tickLine={false} axisLine={false}
            width={250}
            tickFormatter={(v: string) => (v.length > 38 ? `${v.slice(0, 37)}…` : v)}
          />
          <Tooltip content={<DetectionTip />} cursor={{ fill: "var(--panel-divider)", fillOpacity: 0.35 }} />
          <Bar dataKey="cases" fill={CASE_COLOR} radius={[0, 4, 4, 0]} barSize={13}>
            <LabelList dataKey="cases" position="right" style={labelText} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── tooltips ────────────────────────────────────────────────────────────── */

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        background: "var(--panel-card-bg, #0d0f18)",
        border: "1px solid var(--panel-divider-strong, var(--border))",
        borderRadius: 8, padding: "7px 10px", fontSize: 12,
        boxShadow: "0 6px 20px rgba(0,0,0,0.35)",
      }}
    >
      {children}
    </div>
  );
}

function DayTip({ active, payload, label, label: _l }: any & { label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <Shell>
      <div style={{ color: "var(--text-muted)" }}>{payload[0]?.payload?.date}</div>
      <div style={{ fontVariantNumeric: "tabular-nums" }}>
        {Number(payload[0].value).toLocaleString()} {payload[0].name}
      </div>
    </Shell>
  );
}

function StackTip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((sum: number, p: any) => sum + Number(p.value || 0), 0);
  return (
    <Shell>
      <div style={{ color: "var(--text-muted)" }}>{payload[0]?.payload?.date}</div>
      {payload
        .filter((p: any) => Number(p.value) > 0)
        .map((p: any) => (
          <div key={p.name} style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: p.color }} />
            <span>{p.name}</span>
            <strong style={{ marginLeft: "auto", fontVariantNumeric: "tabular-nums" }}>{p.value}</strong>
          </div>
        ))}
      <div style={{ marginTop: 3, color: "var(--text-muted)" }}>{total} in total</div>
    </Shell>
  );
}

function CountTip({ active, payload, total }: any & { total: number }) {
  if (!active || !payload?.length) return null;
  const value = Number(payload[0].value || 0);
  return (
    <Shell>
      <div style={{ textTransform: "capitalize" }}>{payload[0]?.payload?.name}</div>
      <div style={{ fontVariantNumeric: "tabular-nums" }}>
        {value.toLocaleString()} · {total ? ((value / total) * 100).toFixed(0) : 0}%
      </div>
    </Shell>
  );
}

function MinutesTip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload;
  if (!row?.measured) {
    return (
      <Shell>
        <div>{row?.name}</div>
        <div>nothing in this band was answered — not zero, unmeasured</div>
      </Shell>
    );
  }
  return (
    <Shell>
      <div>{row.name}</div>
      <div style={{ fontVariantNumeric: "tabular-nums" }}>
        median {Number(row.value).toFixed(1)} min
      </div>
      {/* The mean is kept beside the median rather than instead of it: on
          this distribution they differ by hours, and one case that waited a
          day moves the mean and not the median. */}
      <div style={{ fontVariantNumeric: "tabular-nums", color: "var(--text-muted)" }}>
        mean {row.mean === null ? "—" : `${Number(row.mean).toFixed(1)} min`} · {row.count} case
        {row.count === 1 ? "" : "s"}
      </div>
      {row.count < 5 && (
        <div style={{ color: "var(--status-warning)", marginTop: 3 }}>
          too few cases to read as a rate
        </div>
      )}
    </Shell>
  );
}

function DetectionTip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload;
  return (
    <Shell>
      <div style={{ maxWidth: 320 }}>{row?.detection}</div>
      <div style={{ fontVariantNumeric: "tabular-nums" }}>{row?.cases} cases</div>
    </Shell>
  );
}

/* ── pieces ──────────────────────────────────────────────────────────────── */

function Kpi({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--panel-divider, var(--border))",
        borderLeft: `3px solid ${tone}`,
        borderRadius: 10, padding: "12px 14px",
      }}
    >
      <div style={{ fontSize: 30, fontVariantNumeric: "tabular-nums", lineHeight: 1.1 }}>
        {value.toLocaleString()}
      </div>
      <div style={{ ...caption, marginTop: 4 }}>{label}</div>
    </div>
  );
}

function Nothing() {
  return <div style={{ fontSize: 12, color: "var(--text-muted)", padding: "18px 0" }}>Nothing in this month.</div>;
}

const axisTick = { fill: "var(--text-muted)", fontSize: 11 };
const labelText = { fill: "var(--text)", fontSize: 11, fontVariantNumeric: "tabular-nums" } as const;
const legendStyle: React.CSSProperties = { fontSize: 11.5, paddingTop: 6 };

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

const labelStyle: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 6 };

const kpiGrid: React.CSSProperties = {
  display: "grid", gap: 12,
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
};

const twoUp: React.CSSProperties = {
  display: "grid", gap: 14,
  gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
};

const footnote: React.CSSProperties = {
  fontSize: 11, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.6,
};
