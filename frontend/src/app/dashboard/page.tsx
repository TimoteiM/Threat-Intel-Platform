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
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

const CHART_COLORS = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
};

const CHART_TOOLTIP_STYLE: React.CSSProperties = {
  background: "rgba(10, 16, 28, 0.98)",
  border: "1px solid rgba(120, 145, 178, 0.22)",
  borderRadius: 14,
  fontSize: 12,
  color: "var(--text-strong)",
  boxShadow: "0 20px 44px rgba(3, 8, 20, 0.34)",
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

  const summaryItems = [
    {
      label: "Investigations",
      value: stats.total_investigations.toLocaleString(),
      hint: "All ingested cases currently visible in the workspace.",
      tone: "info" as const,
    },
    {
      label: "Concluded",
      value: totalLabel,
      hint: "Resolved investigations that feed the current signal mix.",
      tone: "success" as const,
    },
    {
      label: "Malicious share",
      value: `${maliciousShare}%`,
      hint: "Portion of concluded items carrying a malicious verdict.",
      tone: "danger" as const,
    },
    {
      label: "Peak risk bucket",
      value: highestRiskBucket ? `${highestRiskBucket.bucket} (${highestRiskBucket.count})` : "No risk data",
      hint: "Most populated risk band in the current sample.",
      tone: "warning" as const,
      mono: true,
    },
  ];

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
        eyebrow="Mission Control"
        title="Dashboard overview"
        description="A live command surface for intelligence volume, risk posture, and the latest malicious activity across the workspace."
        status={<StatusPill tone="info">Live telemetry</StatusPill>}
        badges={
          <>
            <StatusPill tone="neutral" outline>
              30d window
            </StatusPill>
            <StatusPill tone={maliciousCount > suspiciousCount ? "danger" : "warning"} outline>
              {maliciousCount} malicious
            </StatusPill>
            <StatusPill tone={suspiciousCount > 0 ? "warning" : "neutral"} outline>
              {suspiciousCount} suspicious
            </StatusPill>
          </>
        }
        stats={
          <>
            <SignalCard
              label="Total investigations"
              value={stats.total_investigations.toLocaleString()}
              caption="Workspace-wide cases currently tracked in the system."
              tone="info"
              trend="up"
            />
            <SignalCard
              label="Malicious"
              value={maliciousCount.toLocaleString()}
              caption="Confirmed hostile findings that should stay top of mind."
              tone="danger"
              trend={maliciousCount > suspiciousCount ? "up" : "flat"}
            />
            <SignalCard
              label="Suspicious"
              value={suspiciousCount.toLocaleString()}
              caption="Investigations that warrant attention but need corroboration."
              tone="warning"
              trend={suspiciousCount > 0 ? "up" : "flat"}
            />
            <SignalCard
              label="Concluded"
              value={classificationTotals.toLocaleString()}
              caption="Resolved investigations reflected in the current dashboard mix."
              tone="success"
              trend="flat"
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

      <ConsoleModule
        eyebrow="Mission Brief"
        title="Operational snapshot"
        description="The fastest scan of the workspace: what is happening now, how concentrated the risk is, and where the latest malicious activity is landing."
        variant="glass"
        compact
      >
        <MetadataGrid items={summaryItems} compact />
      </ConsoleModule>

      <div style={twoColumnGrid}>
        <ConsoleModule
          eyebrow="Classification"
          title="Verdict distribution"
          description="How the workload is spread across benign, suspicious, malicious, and inconclusive results."
          tone="info"
          variant="solid"
          actions={<StatusPill tone="info" outline>{pieData.length} active classes</StatusPill>}
        >
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
                        <div style={legendHintStyle}>Classification slice of the current dashboard total.</div>
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

        <ConsoleModule
          eyebrow="Risk"
          title="Score distribution"
          description="The workspace risk profile plotted by score bucket so spikes stand out immediately."
          tone="warning"
          variant="solid"
          actions={<StatusPill tone="warning" outline>Risk posture</StatusPill>}
        >
          {riskData.some((bucket) => bucket.count > 0) ? (
            <div style={{ display: "grid", gap: 14 }}>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={riskData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(120, 145, 178, 0.10)" />
                  <XAxis dataKey="bucket" tick={{ fill: "var(--text-dim)", fontSize: 11 }} />
                  <YAxis tick={{ fill: "var(--text-dim)", fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} itemStyle={{ color: "var(--text-strong)" }} />
                  <Bar dataKey="count" fill="#60a5fa" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <MetadataGrid
                compact
                items={[
                  {
                    label: "Largest bucket",
                    value: highestRiskBucket ? highestRiskBucket.bucket : "-",
                    hint: highestRiskBucket ? `${highestRiskBucket.count} investigations in the busiest band.` : "No populated buckets yet.",
                    tone: "warning",
                    mono: true,
                  },
                  {
                    label: "Current signal mix",
                    value: `${maliciousCount} malicious / ${suspiciousCount} suspicious`,
                    hint: `${benignCount} benign and ${inconclusiveCount} inconclusive round out the view.`,
                    tone: maliciousCount > suspiciousCount ? "danger" : "info",
                  },
                ]}
              />
            </div>
          ) : (
            <EmptyPanel title="No risk buckets available" description="Risk data will appear here once the backend returns score distribution data." />
          )}
        </ConsoleModule>
      </div>

      {timelineData.length > 0 ? (
        <ConsoleModule
          eyebrow="Activity"
          title="Investigation timeline"
          description="Rolling activity over the last 30 days, stacked by classification so surges are easy to spot."
          tone="info"
          variant="glass"
          actions={<StatusPill tone="neutral" outline>{timelineData.length} days</StatusPill>}
        >
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(120, 145, 178, 0.10)" />
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
        <ConsoleModule
          eyebrow="Activity"
          title="Investigation timeline"
          description="This module will light up when the system has enough activity to plot a 30 day trend."
          tone="neutral"
          variant="glass"
        >
          <EmptyPanel title="No timeline data yet" description="Once investigations accumulate, the timeline will reveal activity bursts and classification shifts." />
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

      <ConsoleModule
        eyebrow="Recent Activity"
        title="Recent malicious investigations"
        description="The most recent hostile cases, arranged as a scan-friendly intelligence table."
        tone="danger"
        variant="glass"
      >
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
  return (
    <div style={{ paddingTop: 18, paddingBottom: 40, display: "grid", gap: 18 }}>
      <PageHero
        eyebrow="Mission Control"
        title={title}
        description={description}
        status={<StatusPill tone={danger ? "danger" : loading ? "info" : "warning"}>{loading ? "warming" : danger ? "error" : "pending"}</StatusPill>}
        stats={
          <>
            <SignalCard label="Telemetry" value={loading ? "Loading" : danger ? "Unavailable" : "Pending"} tone={danger ? "danger" : "info"} trend="flat" />
            <SignalCard label="Signal mix" value="—" caption="No overview data is available yet." tone="neutral" trend="flat" />
            <SignalCard label="Risk posture" value="—" caption="Waiting on dashboard statistics from the backend." tone="warning" trend="flat" />
            <SignalCard label="Recent activity" value="—" caption="The timeline will populate after the feed returns." tone="success" trend="flat" />
          </>
        }
      />

      <ConsoleModule
        eyebrow="Console State"
        title={loading ? "Loading intelligence stream" : "Dashboard unavailable"}
        description={description}
        tone={danger ? "danger" : "neutral"}
        variant="glass"
      >
        <EmptyPanel
          title={loading ? "Fetching dashboard stats" : "Unable to render the dashboard"}
          description={loading ? "The landing page is collecting the latest telemetry." : "The overview snapshot could not be loaded from the backend. Refresh the page or try again shortly."}
        />
      </ConsoleModule>
    </div>
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
        border: "1px dashed rgba(120, 145, 178, 0.18)",
        background: "rgba(9, 14, 24, 0.64)",
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
  boxShadow: "0 0 0 4px rgba(255, 255, 255, 0.02)",
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
  boxShadow: "0 14px 30px rgba(3, 8, 20, 0.20)",
};
