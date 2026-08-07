"use client";

/**
 * Provider spend, and what the avoidance machinery saved.
 *
 * Every layer built to skip redundant work — alert-id dedupe, the exclusion
 * list, prior-investigation reuse — records what it skipped on the run that
 * skipped it. Those records were never read back, so the saving was real but
 * invisible. This page is the other half.
 *
 * Savings are counts of work not done, not money: a skipped VirusTotal lookup
 * is worth a different amount to everyone, so the valuation is left to whoever
 * is reading.
 */

import React, { useCallback, useEffect, useState } from "react";
import * as api from "@/lib/api";
import type { CostDashboard } from "@/lib/types";
import Spinner from "@/components/shared/Spinner";

const CARD: React.CSSProperties = {
  background: "var(--bg-card)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: 16,
};

const LABEL: React.CSSProperties = {
  fontSize: 9,
  fontWeight: 700,
  color: "var(--text-muted)",
  letterSpacing: "0.08em",
  fontFamily: "var(--font-mono)",
};

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

function usageColor(percent: number | null): string {
  if (percent === null) return "#64748b";
  if (percent >= 90) return "#ef4444";
  if (percent >= 70) return "#f59e0b";
  return "#10b981";
}

export default function CostPage() {
  const [data, setData] = useState<CostDashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);

  const fetchData = useCallback(() => {
    setLoading(true);
    api
      .getCostDashboard({ days })
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [days]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const savings = data?.savings;

  return (
    <div style={{ paddingTop: 20, paddingBottom: 40, maxWidth: 1280 }}>
      <div
        className="animate-in"
        style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}
      >
        <div>
          <div
            style={{
              fontSize: 18,
              fontWeight: 800,
              color: "var(--text)",
              letterSpacing: "0.04em",
              marginBottom: 4,
              ...MONO,
            }}
          >
            COST AND QUOTA
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            What we spent on providers, and what we avoided spending
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {[7, 30, 90].map((value) => (
            <button
              key={value}
              onClick={() => setDays(value)}
              style={{
                padding: "6px 12px",
                background: days === value ? "var(--bg-hover)" : "transparent",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: days === value ? "var(--text)" : "var(--text-dim)",
                fontSize: 10,
                fontWeight: 700,
                cursor: "pointer",
                ...MONO,
              }}
            >
              {value}D
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <Spinner />
        </div>
      ) : !data ? (
        <div style={{ ...CARD, borderStyle: "dashed", color: "var(--text-dim)", fontSize: 12 }}>
          Could not load usage. The counters live in Redis — check that it is reachable.
        </div>
      ) : (
        <>
          <div
            style={{
              ...CARD,
              marginBottom: 16,
              fontSize: 12,
              color: "var(--text)",
              borderLeft: "3px solid #3b82f6",
            }}
          >
            {data.note}
          </div>

          {/* Savings */}
          {savings && (
            <>
              <div style={{ ...LABEL, marginBottom: 8 }}>WORK AVOIDED</div>
              <div style={{ display: "flex", gap: 12, marginBottom: 8, flexWrap: "wrap" }}>
                <Tile
                  label="Lookups avoided"
                  value={savings.indicator_lookups_avoided}
                  accent="#10b981"
                  hint={
                    savings.avoidance_rate !== null
                      ? `${Math.round(savings.avoidance_rate * 100)}% of all indicator work`
                      : undefined
                  }
                />
                <Tile label="By exclusion list" value={savings.avoided_by_exclusion_list} />
                <Tile label="By prior reuse" value={savings.avoided_by_prior_investigation_reuse} />
                <Tile
                  label="Duplicate alerts absorbed"
                  value={savings.duplicate_alert_deliveries_absorbed}
                />
                <Tile label="AI analyses skipped" value={savings.ai_analyses_skipped} />
              </div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 20 }}>
                Counted from {savings.alert_runs} alert run{savings.alert_runs !== 1 ? "s" : ""} in this
                window · {savings.indicator_lookups_performed} lookup
                {savings.indicator_lookups_performed !== 1 ? "s" : ""} actually performed ·{" "}
                {savings.exclusion_hits_all_time} exclusion hits all time
              </div>
            </>
          )}

          {/* Spend */}
          <div style={{ ...LABEL, marginBottom: 8 }}>PROVIDER USAGE</div>
          {data.providers.length === 0 ? (
            <div style={{ ...CARD, borderStyle: "dashed", color: "var(--text-dim)", fontSize: 12 }}>
              No provider requests recorded yet today or this month.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {data.providers.map((provider) => (
                <div key={provider.key} style={{ ...CARD, padding: "12px 16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text)", minWidth: 150 }}>
                      {provider.provider}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-dim)", ...MONO }}>
                      {provider.requests_today} today · {provider.requests_this_month} this month
                    </span>
                    {provider.daily_limit && (
                      <span style={{ fontSize: 10, color: "var(--text-muted)", ...MONO }}>
                        limit {provider.daily_limit}/day · {provider.remaining_today} left
                      </span>
                    )}
                    {provider.percent_used !== null && (
                      <span
                        style={{
                          marginLeft: "auto",
                          fontSize: 12,
                          fontWeight: 700,
                          color: usageColor(provider.percent_used),
                          ...MONO,
                        }}
                      >
                        {provider.percent_used}%
                      </span>
                    )}
                  </div>
                  {provider.percent_used !== null && (
                    <div
                      style={{
                        marginTop: 8,
                        height: 4,
                        background: "var(--bg-input)",
                        borderRadius: 2,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${Math.min(provider.percent_used, 100)}%`,
                          height: "100%",
                          background: usageColor(provider.percent_used),
                        }}
                      />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {data.providers_idle.length > 0 && (
            <div style={{ marginTop: 12, fontSize: 10, color: "var(--text-muted)" }}>
              No requests recorded: {data.providers_idle.join(", ")}. A configured provider showing
              nothing is either unused or not reporting its usage.
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Tile({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: number;
  hint?: string;
  accent?: string;
}) {
  return (
    <div style={{ ...CARD, flex: 1, minWidth: 160 }}>
      <div style={LABEL}>{label.toUpperCase()}</div>
      <div
        style={{
          fontSize: 24,
          fontWeight: 700,
          color: accent || "var(--text)",
          marginTop: 6,
          ...MONO,
        }}
      >
        {value.toLocaleString()}
      </div>
      {hint && <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
}
