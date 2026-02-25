"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  PieChart, Pie, Cell, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
  ResponsiveContainer,
} from "recharts";
import * as api from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import type { DashboardStats } from "@/lib/types";

const CHART_COLORS = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
};

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getDashboardStats()
      .then(setStats)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
          Loading dashboard...
        </div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <div style={{ fontSize: 13, color: "var(--red)", fontFamily: "var(--font-sans)" }}>
          Failed to load dashboard data
        </div>
      </div>
    );
  }

  const totalConcluded = Object.values(stats.classification_breakdown).reduce((a, b) => a + b, 0);
  const maliciousCount = stats.classification_breakdown.malicious || 0;
  const suspiciousCount = stats.classification_breakdown.suspicious || 0;

  // Pie chart data
  const pieData = Object.entries(stats.classification_breakdown).map(([key, value]) => ({
    name: key,
    value,
    color: CHART_COLORS[key as keyof typeof CHART_COLORS] || "#94a3b8",
  }));

  // Risk distribution data
  const riskData = stats.risk_distribution.map((r) => ({
    bucket: r.bucket,
    count: r.count,
  }));

  // Timeline: aggregate by date (stacked)
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
      date: date.slice(5), // MM-DD
      malicious: cls.malicious || 0,
      suspicious: cls.suspicious || 0,
      benign: cls.benign || 0,
      inconclusive: cls.inconclusive || 0,
    }));

  return (
    <div style={{ paddingTop: 20, paddingBottom: 40 }}>
      {/* Page title */}
      <div style={{
        fontSize: 18, fontWeight: 800, color: "var(--text)",
        fontFamily: "var(--font-mono)", marginBottom: 20,
        letterSpacing: "0.04em",
      }}>
        DASHBOARD
      </div>

      {/* Stats cards */}
      <div style={{
        display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12,
        marginBottom: 20,
      }}>
        <StatCard label="Total Investigations" value={stats.total_investigations} color="var(--accent)" index={0} />
        <StatCard label="Malicious" value={maliciousCount} color="var(--red)" index={1} />
        <StatCard label="Suspicious" value={suspiciousCount} color="var(--yellow)" index={2} />
        <StatCard label="Concluded" value={totalConcluded} color="var(--green)" index={3} />
      </div>

      {/* Charts row 1: Classification pie + Risk distribution */}
      <div className="animate-fade-up" style={{
        display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12,
        marginBottom: 16,
      }}>
        {/* Classification breakdown */}
        <ChartCard title="Classification Breakdown">
          {pieData.length > 0 ? (
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <ResponsiveContainer width="60%" height={200}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%" cy="50%"
                    innerRadius={50} outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#1e293b", border: "1px solid #334155",
                      borderRadius: 6, fontSize: 12,
                    }}
                    itemStyle={{ color: "#e2e8f0" }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1 }}>
                {pieData.map((entry) => {
                  const config = CLASSIFICATION_CONFIG[entry.name as keyof typeof CLASSIFICATION_CONFIG];
                  return (
                    <div key={entry.name} style={{
                      display: "flex", alignItems: "center", gap: 8,
                    }}>
                      <div style={{
                        width: 10, height: 10, borderRadius: 2,
                        background: entry.color,
                      }} />
                      <span style={{
                        fontSize: 12, color: "var(--text-secondary)",
                        fontFamily: "var(--font-sans)", flex: 1,
                        textTransform: "capitalize",
                      }}>
                        {config?.label || entry.name}
                      </span>
                      <span style={{
                        fontSize: 13, fontWeight: 700, color: entry.color,
                        fontFamily: "var(--font-mono)",
                      }}>
                        {entry.value}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <EmptyChart />
          )}
        </ChartCard>

        {/* Risk distribution */}
        <ChartCard title="Risk Score Distribution">
          {riskData.some((r) => r.count > 0) ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={riskData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="bucket" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#1e293b", border: "1px solid #334155",
                    borderRadius: 6, fontSize: 12,
                  }}
                  itemStyle={{ color: "#e2e8f0" }}
                />
                <Bar dataKey="count" fill="#60a5fa" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart />
          )}
        </ChartCard>
      </div>

      {/* Timeline */}
      {timelineData.length > 0 && (
        <ChartCard title="Investigation Timeline (30 days)" className="animate-fade-up">
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="date" tick={{ fill: "#94a3b8", fontSize: 10 }} />
              <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  background: "#1e293b", border: "1px solid #334155",
                  borderRadius: 6, fontSize: 12,
                }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Area type="monotone" dataKey="malicious" stackId="1" fill="#f87171" stroke="#f87171" fillOpacity={0.3} />
              <Area type="monotone" dataKey="suspicious" stackId="1" fill="#fbbf24" stroke="#fbbf24" fillOpacity={0.3} />
              <Area type="monotone" dataKey="benign" stackId="1" fill="#34d399" stroke="#34d399" fillOpacity={0.3} />
              <Area type="monotone" dataKey="inconclusive" stackId="1" fill="#94a3b8" stroke="#94a3b8" fillOpacity={0.3} />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
      )}

      {/* Charts row 2: Top registrars + hosting */}
      <div className="animate-fade-up" style={{
        display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12,
        marginTop: 16, marginBottom: 16,
      }}>
        <ChartCard title="Top Registrars (Malicious/Suspicious)">
          {stats.top_registrars.length > 0 ? (
            <ResponsiveContainer width="100%" height={Math.max(200, stats.top_registrars.length * 30)}>
              <BarChart data={stats.top_registrars} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
                <YAxis
                  type="category" dataKey="name"
                  tick={{ fill: "#94a3b8", fontSize: 10 }}
                  width={150}
                />
                <Tooltip
                  contentStyle={{
                    background: "#1e293b", border: "1px solid #334155",
                    borderRadius: 6, fontSize: 12,
                  }}
                  itemStyle={{ color: "#e2e8f0" }}
                />
                <Bar dataKey="count" fill="#f87171" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart message="No malicious/suspicious investigations yet" />
          )}
        </ChartCard>

        <ChartCard title="Top Hosting Providers (Malicious/Suspicious)">
          {stats.top_hosting_providers.length > 0 ? (
            <ResponsiveContainer width="100%" height={Math.max(200, stats.top_hosting_providers.length * 30)}>
              <BarChart data={stats.top_hosting_providers} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
                <YAxis
                  type="category" dataKey="name"
                  tick={{ fill: "#94a3b8", fontSize: 10 }}
                  width={150}
                />
                <Tooltip
                  contentStyle={{
                    background: "#1e293b", border: "1px solid #334155",
                    borderRadius: 6, fontSize: 12,
                  }}
                  itemStyle={{ color: "#e2e8f0" }}
                />
                <Bar dataKey="count" fill="#fbbf24" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart message="No malicious/suspicious investigations yet" />
          )}
        </ChartCard>
      </div>

      {/* Recent malicious */}
      {stats.recent_malicious.length > 0 && (
        <ChartCard title="Recent Malicious Investigations" className="animate-fade-up">
          <div style={{ display: "flex", flexDirection: "column" }}>
            {stats.recent_malicious.map((inv, i) => (
              <button
                key={inv.id}
                onClick={() => router.push(`/investigations/${inv.id}`)}
                style={{
                  display: "flex", alignItems: "center", gap: 16,
                  padding: "10px 0",
                  background: "transparent", border: "none",
                  borderBottom: i < stats.recent_malicious.length - 1 ? "1px solid var(--border-dim)" : "none",
                  cursor: "pointer", textAlign: "left",
                  color: "var(--text)", width: "100%",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-card-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{
                  fontSize: 12, fontWeight: 600, flex: 1,
                  fontFamily: "var(--font-mono)",
                }}>
                  {inv.domain}
                </span>
                {inv.risk_score != null && (
                  <span style={{
                    fontSize: 12, fontWeight: 700, color: "var(--red)",
                    fontFamily: "var(--font-mono)", minWidth: 30,
                  }}>
                    {inv.risk_score}
                  </span>
                )}
                <span style={{
                  fontSize: 10, fontWeight: 600,
                  padding: "3px 10px",
                  background: "rgba(248,113,113,0.10)",
                  color: "var(--red)",
                  borderRadius: "var(--radius-sm)",
                  fontFamily: "var(--font-sans)",
                  textTransform: "uppercase",
                }}>
                  malicious
                </span>
                <span style={{
                  fontSize: 11, color: "var(--text-muted)",
                  fontFamily: "var(--font-sans)",
                }}>
                  {inv.created_at ? new Date(inv.created_at).toLocaleDateString() : ""}
                </span>
              </button>
            ))}
          </div>
        </ChartCard>
      )}
    </div>
  );
}

function StatCard({ label, value, color, index = 0 }: {
  label: string; value: number; color: string; index?: number;
}) {
  return (
    <div
      className={`animate-in card-hover stagger-${index + 1}`}
      style={{
        padding: "20px 16px",
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        textAlign: "center",
      }}
    >
      <div className="stat-value" style={{
        fontSize: 28, fontWeight: 800, color,
        fontFamily: "var(--font-mono)",
      }}>
        {value}
      </div>
      <div style={{
        fontSize: 11, fontWeight: 600, color: "var(--text-muted)",
        letterSpacing: "0.01em", marginTop: 4,
        fontFamily: "var(--font-sans)",
      }}>
        {label}
      </div>
    </div>
  );
}

function ChartCard({ title, children, className }: {
  title: string; children: React.ReactNode; className?: string;
}) {
  return (
    <div className={className} style={{
      padding: 20,
      background: "var(--bg-card)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius-lg)",
    }}>
      <div style={{
        fontSize: 13, fontWeight: 600, color: "var(--text-dim)",
        letterSpacing: "0.01em", marginBottom: 16,
        fontFamily: "var(--font-sans)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function EmptyChart({ message }: { message?: string }) {
  return (
    <div style={{
      padding: 40, textAlign: "center",
      fontSize: 12, color: "var(--text-dim)",
      fontFamily: "var(--font-sans)",
    }}>
      {message || "No data available yet"}
    </div>
  );
}
