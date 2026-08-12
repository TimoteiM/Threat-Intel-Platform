"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  CartesianGrid,
  Cell,
  PieChart,
  Pie,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import * as api from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import type { DashboardStats } from "@/lib/types";
import ConsoleModule from "@/components/ui/ConsoleModule";
import IntelTable from "@/components/ui/IntelTable";
import MetadataGrid from "@/components/ui/MetadataGrid";
import PageHero from "@/components/ui/PageHero";
import { ErrorState, LoadingState, Page, PageHeader } from "@/components/ui/Primitives";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

const CHART_COLORS = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
};

const CHART_TOOLTIP_STYLE: React.CSSProperties = {
  background: "var(--panel-card-bg)",
  border: "1px solid var(--panel-divider-strong)",
  borderRadius: 14,
  fontSize: 12,
  color: "var(--text-strong)",
  boxShadow: "var(--panel-shadow-card)",
};

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getDashboardStats()
      .then(setStats)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const derived = useMemo(() => {
    if (!stats) return null;

    const classificationTotals = Object.values(stats.classification_breakdown).reduce((acc, count) => acc + count, 0);
    const maliciousCount = stats.classification_breakdown.malicious || 0;
    const suspiciousCount = stats.classification_breakdown.suspicious || 0;
    const benignCount = stats.classification_breakdown.benign || 0;
    const inconclusiveCount = stats.classification_breakdown.inconclusive || 0;

    const pieData = Object.entries(stats.classification_breakdown)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({
        name: key,
        value,
        color: CHART_COLORS[key as keyof typeof CHART_COLORS] || CHART_COLORS.inconclusive,
      }));

    const riskData = stats.risk_distribution.map((r) => ({
      bucket: r.bucket,
      count: r.count,
    }));

    const timelineDates: Record<string, Record<string, number>> = {};
    for (const entry of stats.timeline) {
      if (!entry.date) continue;
      const day = entry.date.slice(0, 10);
      if (!timelineDates[day]) timelineDates[day] = {};
      timelineDates[day][entry.classification] = (timelineDates[day][entry.classification] || 0) + entry.count;
    }

    const timelineData = Object.entries(timelineDates)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, cls]) => ({
        date: date.slice(5),
        malicious: cls.malicious || 0,
        suspicious: cls.suspicious || 0,
        benign: cls.benign || 0,
        inconclusive: cls.inconclusive || 0,
      }));

    const highestRiskBucket = riskData.reduce<{ bucket: string; count: number } | null>((winner, current) => {
      if (!winner || current.count > winner.count) return current;
      return winner;
    }, null);

    const totalLabel = `${classificationTotals.toLocaleString()} concluded`;
    const maliciousShare = classificationTotals > 0 ? Math.round((maliciousCount / classificationTotals) * 100) : 0;

    return {
      classificationTotals,
      maliciousCount,
      suspiciousCount,
      benignCount,
      inconclusiveCount,
      pieData,
      riskData,
      timelineData,
      highestRiskBucket,
      totalLabel,
      maliciousShare,
    };
  }, [stats]);

  if (loading) {
    return <DashboardState title="Loading dashboard intelligence" description="The mission-control view is warming up and pulling the latest telemetry." loading />;
  }

  if (!stats || !derived) {
    return <DashboardState title="Dashboard feed unavailable" description="We could not load the overview snapshot. Try again in a moment." danger />;
  }

  const { pieData, riskData, timelineData, highestRiskBucket, classificationTotals, maliciousCount, suspiciousCount, benignCount, inconclusiveCount, totalLabel, maliciousShare } = derived;

  // The header metrics used to be repeated three times over: as hero badges, as
  // four stat cards, and again as an "operational snapshot" grid. One copy.

  const recentMaliciousRows = stats.recent_malicious.map((inv) => ({
    id: inv.id,
    domain: (
      <button
        type="button"
        onClick={() => router.push(`/investigations/${inv.id}`)}
        style={rowLinkStyle}
      >
        {inv.domain}
      </button>
    ),
    risk_score: inv.risk_score != null ? (
      <StatusPill tone="danger" size="sm" mono>
        {inv.risk_score}
      </StatusPill>
    ) : (
      <span style={mutedCellStyle}>-</span>
    ),
    classification: (
      <StatusPill tone="danger" size="sm">
        {inv.classification || "malicious"}
      </StatusPill>
    ),
    created_at: inv.created_at ? new Date(inv.created_at).toLocaleString() : "-",
    tone: "danger" as const,
  }));

  const registrarRows = stats.top_registrars.map((entry, index) => ({
    id: `${entry.name}-${index}`,
    name: <span style={tablePrimaryStyle}>{entry.name}</span>,
    count: <StatusPill tone={index === 0 ? "danger" : "warning"} size="sm" mono>{entry.count}</StatusPill>,
  }));

  const hostingRows = stats.top_hosting_providers.map((entry, index) => ({
    id: `${entry.name}-${index}`,
    name: <span style={tablePrimaryStyle}>{entry.name}</span>,
    count: <StatusPill tone={index === 0 ? "warning" : "info"} size="sm" mono>{entry.count}</StatusPill>,
  }));

  return (
    <div style={{ paddingTop: 18, paddingBottom: 40, display: "grid", gap: 18 }}>
      <PageHero
        title="Overview"
        description="Investigation volume, verdict mix and the latest malicious findings."
        stats={
          <>
            <SignalCard
              label="Malicious"
              value={maliciousCount.toLocaleString()}
              caption={`${maliciousShare}% of concluded`}
              tone="danger"
              accent="var(--status-danger)"
            />
            <SignalCard
              label="Suspicious"
              value={suspiciousCount.toLocaleString()}
              caption="needs corroboration"
              tone="warning"
              accent="var(--status-warning)"
            />
            <SignalCard label="Concluded" value={classificationTotals.toLocaleString()} tone="neutral" />
            <SignalCard label="Total investigations" value={stats.total_investigations.toLocaleString()} tone="neutral" />
            <SignalCard
              label="Peak risk band"
              value={highestRiskBucket ? highestRiskBucket.bucket : "—"}
              caption={highestRiskBucket ? `${highestRiskBucket.count} investigations` : "no risk data"}
              tone="neutral"
            />
          </>
        }
        actions={
          <button
            type="button"
            onClick={() => router.push("/investigations")}
            style={heroActionStyle}
          >
            Open investigations
          </button>
        }
      />

      <div style={twoColumnGrid}>
        <ConsoleModule title="Verdict distribution" tone="info" variant="solid">
          {pieData.length > 0 ? (
            <div style={chartSplitLayout}>
              <div style={{ minHeight: 240 }}>
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={58}
                      outerRadius={92}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`${entry.name}-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} itemStyle={{ color: "var(--text-strong)" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={legendColumnStyle}>
                {pieData.map((entry) => {
                  const config = CLASSIFICATION_CONFIG[entry.name as keyof typeof CLASSIFICATION_CONFIG];
                  return (
                    <div key={entry.name} style={legendRowStyle}>
                      <span style={{ ...legendSwatchStyle, background: entry.color }} />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={legendLabelStyle}>{config?.label || entry.name}</div>
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", color: entry.color, fontWeight: 700 }}>{entry.value}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <EmptyPanel title="No classification data yet" description="This module will populate once the backend returns breakdown data." />
          )}
        </ConsoleModule>

        <ConsoleModule title="Risk score distribution" tone="warning" variant="solid">
          {riskData.some((bucket) => bucket.count > 0) ? (
            <div style={{ display: "grid", gap: 14 }}>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={riskData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-grid-stroke)" />
                  <XAxis dataKey="bucket" tick={{ fill: "var(--text-dim)", fontSize: 11 }} />
                  <YAxis tick={{ fill: "var(--text-dim)", fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} itemStyle={{ color: "var(--text-strong)" }} />
                  <Bar dataKey="count" fill="#60a5fa" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              {/* The largest bucket and the malicious/suspicious split are both
                  in the header strip already; repeating them under the chart
                  they describe added nothing. */}
              <div style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>
                {benignCount} benign · {inconclusiveCount} inconclusive
              </div>
            </div>
          ) : (
            <EmptyPanel title="No risk scores recorded yet" description="This chart fills in once investigations conclude with a score." />
          )}
        </ConsoleModule>
      </div>

      {timelineData.length > 0 ? (
        <ConsoleModule
          title="Activity, last 30 days"
          description="Stacked by verdict, so a surge shows which kind it is."
          tone="info"
          variant="glass"
        >
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-grid-stroke)" />
              <XAxis dataKey="date" tick={{ fill: "var(--text-dim)", fontSize: 10 }} />
              <YAxis tick={{ fill: "var(--text-dim)", fontSize: 11 }} allowDecimals={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} itemStyle={{ color: "var(--text-strong)" }} />
              <Area type="monotone" dataKey="malicious" stackId="1" fill={CHART_COLORS.malicious} stroke={CHART_COLORS.malicious} fillOpacity={0.26} />
              <Area type="monotone" dataKey="suspicious" stackId="1" fill={CHART_COLORS.suspicious} stroke={CHART_COLORS.suspicious} fillOpacity={0.24} />
              <Area type="monotone" dataKey="benign" stackId="1" fill={CHART_COLORS.benign} stroke={CHART_COLORS.benign} fillOpacity={0.22} />
              <Area type="monotone" dataKey="inconclusive" stackId="1" fill={CHART_COLORS.inconclusive} stroke={CHART_COLORS.inconclusive} fillOpacity={0.18} />
            </AreaChart>
          </ResponsiveContainer>
        </ConsoleModule>
      ) : (
        <ConsoleModule title="Activity, last 30 days" tone="neutral" variant="glass">
          <EmptyPanel title="No activity in the last 30 days" description="" />
        </ConsoleModule>
      )}

      <div style={twoColumnGrid}>
        <ConsoleModule
          eyebrow="Infrastructure"
          title="Top registrars"
          description="Registrars most often associated with malicious or suspicious outcomes."
          tone="danger"
          variant="solid"
          compact
        >
          {registrarRows.length > 0 ? (
            <IntelTable
              columns={[
                { key: "name", label: "Registrar", wrap: true },
                { key: "count", label: "Count", align: "right" },
              ]}
              rows={registrarRows}
              showHeader={false}
              density="compact"
            />
          ) : (
            <EmptyPanel title="No registrar data yet" description="Registrar intelligence will appear once malicious or suspicious cases are recorded." />
          )}
        </ConsoleModule>

        <ConsoleModule
          eyebrow="Infrastructure"
          title="Top hosting providers"
          description="Hosts most frequently seen in high-risk investigations."
          tone="warning"
          variant="solid"
          compact
        >
          {hostingRows.length > 0 ? (
            <IntelTable
              columns={[
                { key: "name", label: "Hosting provider", wrap: true },
                { key: "count", label: "Count", align: "right" },
              ]}
              rows={hostingRows}
              showHeader={false}
              density="compact"
            />
          ) : (
            <EmptyPanel title="No hosting data yet" description="Hosting intelligence will appear once the dashboard has high-risk samples to summarize." />
          )}
        </ConsoleModule>
      </div>

      <ConsoleModule title="Recent malicious investigations" tone="danger" variant="glass">
        {recentMaliciousRows.length > 0 ? (
          <IntelTable
            columns={[
              { key: "domain", label: "Investigation", wrap: true },
              { key: "risk_score", label: "Risk", align: "right" },
              { key: "classification", label: "Classification", align: "center" },
              { key: "created_at", label: "Created", align: "right" },
            ]}
            rows={recentMaliciousRows}
            density="compact"
            rowKey="id"
          />
        ) : (
          <EmptyPanel title="No malicious investigations yet" description="Once hostile activity is detected, it will show up here with the newest items at the top." />
        )}
      </ConsoleModule>
    </div>
  );
}

function DashboardState({
  title,
  description,
  loading = false,
  danger = false,
}: {
  title: string;
  description: string;
  loading?: boolean;
  danger?: boolean;
}) {
  // Loading and failure states used to render four placeholder stat cards and
  // two panels of prose about themselves. A line each is enough.
  return (
    <Page>
      <PageHeader title="Overview" />
      {loading ? <LoadingState label={title} /> : <ErrorState title={title} detail={description} />}
    </Page>
  );
}

function EmptyPanel({ title, description }: { title: React.ReactNode; description: React.ReactNode }) {
  return (
    <div
      style={{
        display: "grid",
        gap: 8,
        padding: 18,
        borderRadius: 18,
        border: "1px dashed var(--panel-divider-strong)",
        background: "var(--panel-empty-bg)",
      }}
    >
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-strong)" }}>{title}</div>
      <div style={{ fontSize: 13, lineHeight: 1.7, color: "var(--text-secondary)" }}>{description}</div>
    </div>
  );
}

const twoColumnGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
  gap: 18,
  alignItems: "start",
};

const chartSplitLayout: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
  gap: 18,
  alignItems: "center",
};

const legendColumnStyle: React.CSSProperties = {
  display: "grid",
  gap: 12,
};

const legendRowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "10px 0",
  borderBottom: "1px solid rgba(120, 145, 178, 0.10)",
};

const legendSwatchStyle: React.CSSProperties = {
  width: 12,
  height: 12,
  borderRadius: 4,
  flex: "0 0 auto",
  boxShadow: "0 0 0 4px var(--accent-glow)",
};

const legendLabelStyle: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 700,
  color: "var(--text-strong)",
};

const legendHintStyle: React.CSSProperties = {
  fontSize: 12,
  lineHeight: 1.6,
  color: "var(--text-secondary)",
  marginTop: 4,
};

const rowLinkStyle: React.CSSProperties = {
  border: "none",
  padding: 0,
  background: "transparent",
  color: "var(--text-strong)",
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  fontWeight: 700,
  cursor: "pointer",
  textAlign: "left",
};

const tablePrimaryStyle: React.CSSProperties = {
  fontWeight: 700,
  color: "var(--text-strong)",
  fontFamily: "var(--font-sans)",
};

const mutedCellStyle: React.CSSProperties = {
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono)",
};

const heroActionStyle: React.CSSProperties = {
  padding: "10px 16px",
  borderRadius: 14,
  border: "1px solid rgba(102, 168, 255, 0.30)",
  background: "linear-gradient(135deg, rgba(102, 168, 255, 0.18), rgba(37, 99, 235, 0.28))",
  color: "var(--text-strong)",
  fontSize: 12,
  fontWeight: 800,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  cursor: "pointer",
  fontFamily: "var(--font-sans)",
  boxShadow: "var(--panel-shadow-soft)",
};
