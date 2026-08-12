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
 *
 * The one thing an analyst acts on here is a provider close to its quota, so
 * that is what the page leads with when it happens.
 */

import React, { useCallback, useEffect, useState } from "react";
import * as api from "@/lib/api";
import type { CostDashboard } from "@/lib/types";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  MetricStrip,
  Page,
  PageHeader,
  Section,
} from "@/components/ui/Primitives";

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

function usageColor(percent: number | null): string {
  if (percent === null) return "var(--status-neutral)";
  if (percent >= 90) return "var(--status-danger)";
  if (percent >= 70) return "var(--status-warning)";
  return "var(--status-success)";
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
  // A provider over 70% of its daily quota is the only thing on this page that
  // needs doing something about, so it is lifted out of the list.
  const pressured = (data?.providers || []).filter(
    (provider) => provider.percent_used !== null && provider.percent_used >= 70,
  );

  return (
    <Page>
      <PageHeader
        title="Cost and quota"
        subtitle="What we spent on providers, and what we avoided spending."
        actions={
          <div className="ds-toolbar" role="group" aria-label="Time window">
            {[7, 30, 90].map((value) => (
              <Button
                key={value}
                variant={days === value ? "primary" : "secondary"}
                aria-pressed={days === value}
                onClick={() => setDays(value)}
              >
                {value}d
              </Button>
            ))}
          </div>
        }
      />

      {loading ? (
        <LoadingState label="Loading usage…" />
      ) : !data ? (
        <ErrorState
          title="Could not load usage"
          detail="The counters live in Redis — check that it is reachable."
          action={
            <Button onClick={fetchData} variant="secondary">
              Try again
            </Button>
          }
        />
      ) : (
        <>
          {pressured.length > 0 && (
            <ErrorState
              partial
              title={`${pressured.length} provider${pressured.length === 1 ? "" : "s"} near the daily quota`}
              detail={pressured
                .map((provider) => `${provider.provider} ${provider.percent_used}% (${provider.remaining_today} left)`)
                .join(" · ")}
            />
          )}

          {savings && (
            <Section
              title="Work avoided"
              hint={`From ${savings.alert_runs} alert run${savings.alert_runs !== 1 ? "s" : ""} in this window · ${
                savings.indicator_lookups_performed
              } lookup${savings.indicator_lookups_performed !== 1 ? "s" : ""} actually performed · ${
                savings.exclusion_hits_all_time
              } exclusion hits all time`}
            >
              <MetricStrip
                metrics={[
                  {
                    label: "Lookups avoided",
                    value: savings.indicator_lookups_avoided.toLocaleString(),
                    status: "success",
                    hint:
                      savings.avoidance_rate !== null
                        ? `${Math.round(savings.avoidance_rate * 100)}% of all indicator work`
                        : undefined,
                  },
                  { label: "By exclusion list", value: savings.avoided_by_exclusion_list.toLocaleString() },
                  { label: "By prior reuse", value: savings.avoided_by_prior_investigation_reuse.toLocaleString() },
                  {
                    label: "Duplicate alerts absorbed",
                    value: savings.duplicate_alert_deliveries_absorbed.toLocaleString(),
                  },
                  { label: "AI analyses skipped", value: savings.ai_analyses_skipped.toLocaleString() },
                ]}
              />
            </Section>
          )}

          <Section title="Provider usage" hint={data.note}>
            {data.providers.length === 0 ? (
              <EmptyState title="No provider requests recorded yet today or this month." />
            ) : (
              <div className="ds-rows">
                {data.providers.map((provider) => (
                  <div key={provider.key} style={{ padding: "var(--space-3) 0", borderBottom: "1px solid var(--panel-divider-soft)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "var(--font-body)", fontWeight: 600, color: "var(--text)", minWidth: 150 }}>
                        {provider.provider}
                      </span>
                      <span style={{ fontSize: "var(--font-meta)", color: "var(--text-dim)", ...MONO }}>
                        {provider.requests_today} today · {provider.requests_this_month} this month
                      </span>
                      {provider.daily_limit && (
                        <span style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)", ...MONO }}>
                          limit {provider.daily_limit}/day · {provider.remaining_today} left
                        </span>
                      )}
                      {provider.percent_used !== null && (
                        <span
                          style={{
                            marginLeft: "auto",
                            fontSize: "var(--font-body)",
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
                        role="progressbar"
                        aria-valuenow={provider.percent_used}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label={`${provider.provider} daily quota used`}
                        style={{
                          marginTop: "var(--space-2)",
                          height: 3,
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
              <div style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>
                No requests recorded: {data.providers_idle.join(", ")}. A configured provider showing
                nothing is either unused or not reporting its usage.
              </div>
            )}
          </Section>
        </>
      )}
    </Page>
  );
}
