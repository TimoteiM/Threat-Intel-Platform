"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import * as api from "@/lib/api";
import type { AssistantDailyMetrics } from "@/lib/types";
import ConsoleModule from "@/components/ui/ConsoleModule";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

interface AssistantDailyActivityProps {
  refreshKey?: number;
}

export default function AssistantDailyActivity({ refreshKey = 0 }: AssistantDailyActivityProps) {
  const today = useMemo(() => formatLocalDate(new Date()), []);
  const [selectedDate, setSelectedDate] = useState(today);
  const [metrics, setMetrics] = useState<AssistantDailyMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    api.getAssistantDailyMetrics(selectedDate, new Date().getTimezoneOffset())
      .then((data) => {
        if (!cancelled) setMetrics(data);
      })
      .catch(() => {
        if (!cancelled) {
          setMetrics(null);
          setFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey, selectedDate]);

  const comparison = metrics
    ? formatComparison(metrics.total, metrics.previous_total, metrics.change_percent)
    : "Waiting for activity data";
  const activeHours = metrics?.hourly.filter((point) => point.count > 0).length || 0;

  return (
    <ConsoleModule
      title="Alerts treated by AI Assistant"
      description="Successfully completed alert-analysis sessions, grouped by the hour they finished in your local time."
      tone="info"
      variant="glass"
      actions={
        <label style={dateControlStyle}>
          <span style={dateLabelStyle}>Activity date</span>
          <input
            type="date"
            value={selectedDate}
            max={today}
            onChange={(event) => setSelectedDate(event.target.value)}
            style={dateInputStyle}
            aria-label="Select AI Assistant activity date"
          />
        </label>
      }
    >
      {failed ? (
        <div style={emptyStyle}>
          Daily assistant activity could not be loaded. Try selecting the date again.
        </div>
      ) : (
        <div style={activityLayoutStyle}>
          <div style={signalGridStyle}>
            <SignalCard
              label="Alerts treated"
              value={loading ? "—" : (metrics?.total || 0).toLocaleString()}
              caption={loading ? "Loading completed runs" : comparison}
              tone="info"
              trend={(metrics?.change_percent || 0) > 0 ? "up" : (metrics?.change_percent || 0) < 0 ? "down" : "flat"}
              compact
            />
            <SignalCard
              label="Busiest hour"
              value={loading ? "—" : metrics?.peak_hour || "No activity"}
              caption={activeHours ? `${activeHours} active hour${activeHours === 1 ? "" : "s"} during this day` : "No completed alert runs for this day"}
              tone={metrics?.peak_hour ? "success" : "neutral"}
              trend={metrics?.peak_hour ? "up" : "flat"}
              compact
            />
          </div>

          <div style={chartShellStyle}>
            <div style={chartHeaderStyle}>
              <div>
                <div style={chartTitleStyle}>Hourly throughput</div>
                <div style={chartCaptionStyle}>Completion volume across the selected 24-hour window</div>
              </div>
              <StatusPill tone={loading ? "warning" : metrics?.total ? "success" : "neutral"} outline mono>
                {loading ? "Loading" : `${metrics?.total || 0} completed`}
              </StatusPill>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={metrics?.hourly || emptyHourlyData()} margin={{ top: 12, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid vertical={false} strokeDasharray="3 3" stroke="var(--panel-grid-stroke)" />
                <XAxis
                  dataKey="hour"
                  interval={2}
                  tick={{ fill: "var(--text-dim)", fontSize: 10 }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--panel-divider-strong)" }}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "var(--text-dim)", fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  cursor={{ fill: "rgba(102, 168, 255, 0.08)" }}
                  contentStyle={tooltipStyle}
                  itemStyle={{ color: "var(--text-strong)" }}
                  formatter={(value) => [`${Number(value)} alert${Number(value) === 1 ? "" : "s"}`, "Completed"]}
                />
                <Bar dataKey="count" fill="#66a8ff" radius={[6, 6, 2, 2]} maxBarSize={24} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </ConsoleModule>
  );
}

function formatLocalDate(value: Date): string {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, "0");
  const day = String(value.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function formatComparison(total: number, previous: number, change: number | null): string {
  if (previous === 0) {
    return total === 0 ? "No activity on this day or the previous day" : "New activity compared with the previous day";
  }
  if (change === 0) return `Same volume as the previous day (${previous})`;
  return `${Math.abs(change || 0)}% ${change && change > 0 ? "more" : "fewer"} than the previous day (${previous})`;
}

function emptyHourlyData() {
  return Array.from({ length: 24 }, (_, hour) => ({
    hour: `${String(hour).padStart(2, "0")}:00`,
    count: 0,
  }));
}

const activityLayoutStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(220px, 0.55fr) minmax(0, 1.45fr)",
  gap: 16,
  alignItems: "stretch",
};

const signalGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 12,
};

const chartShellStyle: React.CSSProperties = {
  minWidth: 0,
  padding: "16px 16px 6px",
  borderRadius: 18,
  border: "1px solid var(--panel-divider-strong)",
  background: "var(--panel-card-bg)",
};

const chartHeaderStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 12,
  marginBottom: 4,
};

const chartTitleStyle: React.CSSProperties = {
  color: "var(--text-strong)",
  fontSize: 14,
  fontWeight: 800,
};

const chartCaptionStyle: React.CSSProperties = {
  marginTop: 5,
  color: "var(--text-dim)",
  fontSize: 11,
};

const dateControlStyle: React.CSSProperties = {
  display: "grid",
  gap: 5,
};

const dateLabelStyle: React.CSSProperties = {
  color: "var(--text-dim)",
  fontSize: 10,
  fontWeight: 800,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
};

const dateInputStyle: React.CSSProperties = {
  colorScheme: "dark",
  minHeight: 38,
  padding: "7px 10px",
  borderRadius: 10,
  border: "1px solid var(--panel-divider-strong)",
  background: "var(--panel-card-bg)",
  color: "var(--text-strong)",
  fontFamily: "var(--font-mono)",
};

const tooltipStyle: React.CSSProperties = {
  background: "var(--panel-card-bg)",
  border: "1px solid var(--panel-divider-strong)",
  borderRadius: 12,
  fontSize: 12,
  color: "var(--text-strong)",
  boxShadow: "var(--panel-shadow-card)",
};

const emptyStyle: React.CSSProperties = {
  padding: 26,
  borderRadius: 16,
  border: "1px dashed var(--panel-divider-strong)",
  color: "var(--text-secondary)",
  textAlign: "center",
};
