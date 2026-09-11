"use client";

/**
 * Provider spend, and what the avoidance machinery saved.
 *
 * Rendered inside Settings rather than as a page of its own. Spend and quota
 * are configuration facts an operator checks occasionally, not something an
 * analyst navigates to during an investigation, and a top-level nav slot is
 * the most expensive place in the app to put something read once a month.
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
  Section,
} from "@/components/ui/Primitives";

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

function usageColor(percent: number | null): string {
  if (percent === null) return "var(--status-neutral)";
  if (percent >= 90) return "var(--status-danger)";
  if (percent >= 70) return "var(--status-warning)";
  return "var(--status-success)";
}

export default function CostSection() {
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
    <div style={{ display: "grid", gap: "var(--space-4)" }}>
      <AISpendPanel />
      <div className="ds-toolbar" role="group" aria-label="Time window" style={{ justifySelf: "start" }}>
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
    </div>
  );
}


/**
 * What the AI providers have cost us this month.
 *
 * Deliberately not called a balance. Neither OpenAI nor Anthropic will return
 * remaining credit over an API — OpenAI's Usage API reports spend, and needs an
 * admin-scoped key — so this is metered from our own requests: every call
 * reports its tokens, we price them, and the total counts down from a budget
 * entered here. The scope note says so on the panel rather than in a docstring
 * nobody reading the number will see.
 */
function AISpendPanel() {
  const [spend, setSpend] = useState<api.AISpend | null>(null);
  const [days, setDays] = useState(30);
  const [budgetInput, setBudgetInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const next = await api.getAISpend(days);
      setSpend(next);
      if (next.budget) setBudgetInput(String(next.budget.monthly_usd));
    } catch (err: any) {
      setError(err?.message || "Could not read AI spend.");
    }
  }, [days]);

  useEffect(() => {
    load();
  }, [load]);

  const saveBudget = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.setAIBudget(Number(budgetInput) || 0);
      await load();
    } catch (err: any) {
      setError(err?.message || "Could not save the budget.");
    } finally {
      setSaving(false);
    }
  };

  if (error && !spend) return <ErrorState title="AI spend unavailable" detail={error} />;
  if (!spend) return null;
  if (!spend.available) {
    return <ErrorState title="AI spend unavailable" detail={spend.reason || "The usage store is unreachable."} partial />;
  }

  const win = spend.window!;
  const budget = spend.budget;
  const unpriced = spend.unpriced_models || [];
  const tokens = win.input_tokens + win.output_tokens;

  return (
    <Section title="AI spend" hint={spend.scope_note}>
      {/* Buckets are UTC calendar days, so the shortest window is "today so
          far" rather than a rolling 24 hours. Labelled as such. */}
      <div className="ds-toolbar" role="group" aria-label="Spend window" style={{ justifySelf: "start", marginBottom: "var(--space-3)" }}>
        {[
          { value: 1, label: "24h" },
          { value: 7, label: "7 days" },
          { value: 30, label: "30 days" },
        ].map((option) => (
          <Button
            key={option.value}
            variant={days === option.value ? "primary" : "secondary"}
            aria-pressed={days === option.value}
            onClick={() => setDays(option.value)}
          >
            {option.label}
          </Button>
        ))}
      </div>

      <WindowCoverage spend={spend} />

      <MetricStrip
        metrics={[
          {
            label: spend.window_label || `Last ${spend.window_days} days`,
            value: `$${win.usd.toFixed(4)}`,
            hint: `${win.calls} call${win.calls === 1 ? "" : "s"}`,
          },
          {
            label: "Tokens in window",
            value: tokens >= 1000 ? `${(tokens / 1000).toFixed(1)}k` : String(tokens),
            hint: `${win.input_tokens.toLocaleString()} in · ${win.output_tokens.toLocaleString()} out`,
          },
          {
            label: "Budget remaining",
            value: budget ? `$${budget.remaining_usd.toFixed(2)}` : "—",
            hint: budget
              ? `${budget.percent_used}% of $${budget.monthly_usd.toFixed(2)} used this calendar month`
              : "no budget set",
            status: budget ? (budget.percent_used >= 90 ? "danger" : budget.percent_used >= 70 ? "warning" : undefined) : undefined,
          },
        ]}
      />

      {unpriced.length > 0 && (
        <div
          role="note"
          style={{
            marginTop: "var(--space-3)",
            padding: "var(--space-3)",
            borderLeft: "3px solid var(--status-warning)",
            background: "rgba(240, 160, 80, 0.07)",
            borderRadius: "0 var(--shell-radius-sm) var(--shell-radius-sm) 0",
            fontSize: "var(--font-meta)",
            lineHeight: 1.6,
            color: "var(--text-secondary)",
          }}
        >
          <strong style={{ color: "var(--status-warning)" }}>
            {win.unpriced_calls} call{win.unpriced_calls === 1 ? "" : "s"} could not be costed.
          </strong>{" "}
          No rate is configured for {unpriced.join(", ")}, so their tokens are counted but their
          dollars are not — the figure above is therefore a floor, not a total. Set the rate with
          the <code style={MONO}>AI_MODEL_PRICES</code> environment variable, in dollars per
          million tokens.
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", marginTop: "var(--space-3)", flexWrap: "wrap" }}>
        <label htmlFor="ai-budget" style={{ fontSize: "var(--font-meta)", color: "var(--text-dim)" }}>
          Monthly budget (USD)
        </label>
        <input
          id="ai-budget"
          type="number"
          min={0}
          step="1"
          value={budgetInput}
          onChange={(event) => setBudgetInput(event.target.value)}
          placeholder="0 to clear"
          style={{
            ...MONO,
            width: 120,
            padding: "6px 9px",
            borderRadius: "var(--shell-radius-sm)",
            border: "1px solid var(--border)",
            background: "var(--bg-input)",
            color: "var(--text)",
            fontSize: "var(--font-meta)",
          }}
        />
        <Button variant="secondary" onClick={saveBudget} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </Button>
        {error && <span style={{ fontSize: "var(--font-micro)", color: "var(--status-danger)" }}>{error}</span>}
      </div>

      {(spend.by_model || []).length > 0 && (
        <div style={{ marginTop: "var(--space-4)", overflowX: "auto" }}>
          <table className="ds-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Model</th>
                <th style={{ textAlign: "right" }}>Calls</th>
                <th style={{ textAlign: "right" }}>Input</th>
                <th style={{ textAlign: "right" }}>Output</th>
                <th style={{ textAlign: "right" }}>Rate $/M (in · out)</th>
                <th style={{ textAlign: "right" }}>Cost</th>
              </tr>
            </thead>
            <tbody>
              {(spend.by_model || []).map((row) => (
                <tr key={`${row.provider}:${row.model}`}>
                  <td style={MONO}>
                    {row.model}{" "}
                    <span style={{ color: "var(--text-muted)", fontSize: "var(--font-micro)" }}>{row.provider}</span>
                  </td>
                  <td style={{ ...MONO, textAlign: "right" }}>{row.calls.toLocaleString()}</td>
                  <td style={{ ...MONO, textAlign: "right" }}>{row.input_tokens.toLocaleString()}</td>
                  <td style={{ ...MONO, textAlign: "right" }}>{row.output_tokens.toLocaleString()}</td>
                  {/* The rate is on the row so the cost can be checked by hand:
                      tokens ÷ 1,000,000 × rate. */}
                  <td style={{ ...MONO, textAlign: "right", color: "var(--text-dim)" }}>
                    {row.priced ? `${row.input_per_mtok} · ${row.output_per_mtok}` : "—"}
                  </td>
                  <td style={{ ...MONO, textAlign: "right" }}>
                    {row.priced ? `$${row.usd.toFixed(4)}` : <span style={{ color: "var(--status-warning)" }}>unpriced</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: "var(--space-2)", fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>
            {spend.prices_source}
          </div>
        </div>
      )}
    </Section>
  );
}


/**
 * What the selected window actually covers.
 *
 * Three buttons that all report the same total read as a broken control. They
 * are not — there is simply one day of history, because metering began then.
 * Saying so is cheaper than letting someone conclude the filter is dead.
 */
function WindowCoverage({ spend }: { spend: api.AISpend }) {
  const start = spend.window_start;
  const end = spend.window_end;
  const first = spend.first_recorded_day;
  if (!start || !end) return null;

  const singleDay = !first || first === end;
  const coveredFrom = first && first > start ? first : start;

  return (
    <div style={{ marginBottom: "var(--space-3)", fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>
      {start === end ? `${start} (UTC)` : `${start} to ${end} (UTC)`}
      {singleDay ? (
        <>
          {" · "}
          <span style={{ color: "var(--status-warning)" }}>
            metering began {first || end}, so every window covers the same single day so far
          </span>
        </>
      ) : coveredFrom !== start ? (
        <>{` · data begins ${coveredFrom}`}</>
      ) : null}
    </div>
  );
}
