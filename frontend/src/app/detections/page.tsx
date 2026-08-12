"use client";

/**
 * Detection quality and ATT&CK coverage.
 *
 * A SIEM reports how often a rule fired; it cannot report whether firing was
 * useful, because it never investigates what it produced. This page reads that
 * back from stored runs: which rules cost attention and return nothing, whose
 * ATT&CK mapping the evidence never bears out, and which techniques show up in
 * evidence that no detection claims.
 *
 * Rules below the scoring threshold show counts and no rates — a proportion
 * from two alerts is noise, and presenting it as a score would mislead.
 */

import React, { useCallback, useEffect, useState } from "react";
import * as api from "@/lib/api";
import type {
  AttackCoverageResponse,
  DetectionQualityResponse,
  FeedbackAccuracy,
  TacticAlert,
} from "@/lib/types";
import {
  Button,
  Card,
  Details,
  EmptyState,
  LoadingState,
  MetricStrip,
  Page,
  PageHeader,
  Section,
} from "@/components/ui/Primitives";
import Spinner from "@/components/shared/Spinner";

const WINDOWS = [7, 30, 90];

// Rules and techniques are records in a list, not objects worth a frame each.
// The only card left on this page is the one around a rule, because a rule is a
// thing an analyst acts on.
const LABEL: React.CSSProperties = {
  fontSize: "var(--font-micro)",
  fontWeight: 700,
  color: "var(--text-muted)",
  letterSpacing: "0.06em",
  textTransform: "uppercase",
};

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

function rateColor(rate: number | null, invert = false): string {
  if (rate === null) return "var(--text-muted)";
  const bad = invert ? rate < 0.3 : rate >= 0.8;
  const mid = invert ? rate < 0.6 : rate >= 0.5;
  return bad ? "var(--status-danger)" : mid ? "var(--status-warning)" : "var(--status-success)";
}

function pct(rate: number | null): string {
  return rate === null ? "—" : `${Math.round(rate * 100)}%`;
}

export default function DetectionsPage() {
  const [tab, setTab] = useState<"rules" | "attack" | "accuracy">("rules");
  const [days, setDays] = useState(30);
  const [quality, setQuality] = useState<DetectionQualityResponse | null>(null);
  const [coverage, setCoverage] = useState<AttackCoverageResponse | null>(null);
  const [accuracy, setAccuracy] = useState<FeedbackAccuracy | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchAll = useCallback(() => {
    setLoading(true);
    Promise.all([
      api.getDetectionQuality({ days }).catch(() => null),
      api.getAttackCoverage({ days: Math.max(days, 90) }).catch(() => null),
      api.getFeedbackAccuracy({ days: Math.max(days, 90) }).catch(() => null),
    ])
      .then(([q, c, a]) => {
        setQuality(q);
        setCoverage(c);
        setAccuracy(a);
      })
      .finally(() => setLoading(false));
  }, [days]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  const tabs = [
    { id: "rules" as const, label: "Rules" },
    { id: "attack" as const, label: "ATT&CK coverage" },
    { id: "accuracy" as const, label: "Platform accuracy" },
  ];

  return (
    <Page>
      <PageHeader
        title="Detection quality"
        subtitle="What each rule is worth, measured from what its alerts turned out to be."
        actions={
          <div className="ds-toolbar" role="group" aria-label="Time window">
            {WINDOWS.map((value) => (
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

      <div role="tablist" aria-label="Detection quality views" className="ds-toolbar">
        {tabs.map((entry) => (
          <button
            key={entry.id}
            role="tab"
            id={`tab-${entry.id}`}
            aria-selected={tab === entry.id}
            aria-controls={`panel-${entry.id}`}
            onClick={() => setTab(entry.id)}
            className="ds-btn"
            style={{
              borderColor: tab === entry.id ? "var(--accent)" : "transparent",
              color: tab === entry.id ? "var(--text)" : "var(--text-dim)",
              background: tab === entry.id ? "var(--accent-glow)" : "transparent",
            }}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {loading ? (
          <LoadingState label="Loading detection data…" />
        ) : tab === "rules" ? (
          <RulesTab data={quality} />
        ) : tab === "attack" ? (
          <AttackTab data={coverage} days={Math.max(days, 90)} />
        ) : (
          <AccuracyTab data={accuracy} />
        )}
      </div>
    </Page>
  );
}

/* ─── Rules ─── */

function RulesTab({ data }: { data: DetectionQualityResponse | null }) {
  if (!data || !data.rules.length) {
    return (
      <EmptyState
        title="No alerts carrying a detection rule id in this window"
        hint={
          <>
            Rule quality is measured from <code>rule.id</code> on ingested alerts. Analyst-pasted
            alerts have none and are counted as unattributed.
          </>
        }
      />
    );
  }

  return (
    <div style={{ display: "grid", gap: "var(--space-4)" }}>
      <MetricStrip
        metrics={[
          { label: "Rules seen", value: data.rules_seen },
          { label: "Alerts", value: data.alerts_total },
          {
            label: "Unattributed",
            value: data.unattributed_alerts,
            hint: "no rule id",
            status: data.unattributed_alerts ? "warning" : "neutral",
          },
          { label: "Scoring floor", value: `${data.min_alerts_to_score} alerts`, hint: "below this, counts only" },
        ]}
      />

      <div style={{ display: "grid", gap: "var(--space-2)" }}>
        {data.rules.map((rule) => (
          <Card key={rule.rule_id}>
            <div style={{ display: "flex", alignItems: "baseline", gap: "var(--space-3)", flexWrap: "wrap" }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", ...MONO }}>
                {rule.rule_id}
              </span>
              <span style={{ fontSize: "var(--font-meta)", color: "var(--text-dim)" }}>{rule.rule_name || "—"}</span>
              <span style={{ marginLeft: "auto", fontSize: "var(--font-micro)", color: "var(--text-muted)", ...MONO }}>
                {rule.alerts} alert{rule.alerts !== 1 ? "s" : ""}
              </span>
            </div>

            <div style={{ display: "flex", gap: "var(--space-5)", marginTop: "var(--space-3)", flexWrap: "wrap" }}>
              <Metric label="Noise" value={pct(rule.noise_rate)} color={rateColor(rule.noise_rate)} />
              <Metric
                label="Actionable"
                value={pct(rule.actionable_rate)}
                color={rateColor(rule.actionable_rate, true)}
              />
              <Metric
                label="ATT&CK confirmed"
                value={
                  rule.attack_claims
                    ? `${pct(rule.attack_confirm_rate)} of ${rule.attack_claims}`
                    : "no claims"
                }
                color={rateColor(rule.attack_confirm_rate, true)}
              />
              {rule.fully_excluded_alerts > 0 && (
                <Metric
                  label="Excluded-only alerts"
                  value={String(rule.fully_excluded_alerts)}
                  color="var(--status-warning)"
                />
              )}
              {rule.analyst_feedback.false_positive_rate !== null && (
                <Metric
                  label="Analyst FP rate"
                  value={pct(rule.analyst_feedback.false_positive_rate)}
                  color={rateColor(rule.analyst_feedback.false_positive_rate)}
                />
              )}
            </div>

            <div style={{ marginTop: "var(--space-3)", fontSize: "var(--font-meta)", color: "var(--text-secondary)", lineHeight: 1.6 }}>
              {rule.assessment}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function Metric({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div>
      <div style={LABEL}>{label.toUpperCase()}</div>
      <div style={{ fontSize: 14, fontWeight: 700, color, marginTop: 2, ...MONO }}>{value}</div>
    </div>
  );
}

/* ─── ATT&CK coverage ─── */

function AttackTab({ data, days }: { data: AttackCoverageResponse | null; days: number }) {
  if (!data || !data.runs_assessed) {
    return (
      <EmptyState
        title="No assessed runs in this window yet"
        hint="Coverage is built from alert runs that carried an ATT&CK mapping or produced technique evidence."
      />
    );
  }

  return (
    <div style={{ display: "grid", gap: "var(--space-5)" }}>
      <MetricStrip
        metrics={[
          { label: "Runs assessed", value: data.runs_assessed },
          { label: "Techniques seen", value: data.techniques_seen },
          {
            label: "Unvalidated mappings",
            value: data.unvalidated_mappings.length,
            hint: "claimed, never confirmed",
            status: data.unvalidated_mappings.length ? "warning" : "success",
          },
          {
            label: "Undetected behaviour",
            value: data.undetected_behaviour.length,
            hint: "observed, never claimed",
            status: data.undetected_behaviour.length ? "danger" : "success",
          },
        ]}
      />

      {/* Gaps first: a technique nothing claims is the finding on this page. */}
      {data.undetected_behaviour.length > 0 && (
        <TechniqueList
          title="Observed but never claimed by a detection"
          hint="Evidence showed these; no rule said they would. Detection gaps."
          rows={data.undetected_behaviour}
        />
      )}
      {data.unvalidated_mappings.length > 0 && (
        <TechniqueList
          title="Claimed but never corroborated"
          hint="Rules assert these; the evidence has not yet borne one out. Rows marked 'not evidenceable here' are ones this platform could never confirm, whatever it collected."
          rows={data.unvalidated_mappings}
        />
      )}

      <Section title="By tactic" hint="Select a tactic to list the alerts whose assessment touched it.">
        <div className="ds-rows">
          {data.tactics.map((tactic) => (
            <TacticRow key={tactic.tactic} tactic={tactic} days={days} />
          ))}
        </div>
      </Section>

      {data.blind_spots.length > 0 && (
        <Section title="Blind spots" hint="Tactics this platform could evidence but has never once seen.">
          <div className="ds-rows">
            {data.blind_spots.map((spot) => (
              <div key={spot.tactic} className="ds-row" style={{ fontSize: "var(--font-meta)" }}>
                <span style={{ color: "var(--text)" }}>{spot.tactic}</span>
                <span style={{ marginLeft: "auto", color: "var(--text-muted)", ...MONO }}>
                  {spot.techniques_we_could_evidence} technique
                  {spot.techniques_we_could_evidence === 1 ? "" : "s"} we could detect
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

/* ─── One tactic, and the alerts underneath it ─── */

// Hardcoded hexes replaced with the semantic tokens, so a "confirmed" here is
// the same green as a passing collector anywhere else in the product.
const STATUS_STYLE: Record<string, { label: string; color: string }> = {
  confirmed: { label: "confirmed", color: "var(--status-success)" },
  not_corroborated: { label: "not corroborated", color: "var(--status-warning)" },
  refuted: { label: "refuted", color: "var(--status-danger)" },
  observed: { label: "observed, unclaimed", color: "var(--status-info)" },
  ai_suggested: { label: "AI-suggested", color: "var(--purple)" },
};

const VERDICT_COLOR: Record<string, string> = {
  malicious: "var(--status-danger)",
  suspicious: "var(--status-warning)",
  benign: "var(--status-success)",
  clean: "var(--status-success)",
};

function formatWhen(iso: string | null): string {
  if (!iso) return "—";
  const when = new Date(iso);
  return Number.isNaN(when.getTime()) ? "—" : when.toLocaleString();
}

/**
 * A tactic row that opens into its alerts.
 *
 * Fetched on first open rather than with the coverage roll-up: most rows are
 * never opened, and every open one costs a scan of the window's runs.
 */
function TacticRow({
  tactic,
  days,
}: {
  tactic: AttackCoverageResponse["tactics"][number];
  days: number;
}) {
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<TacticAlert[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The window is part of the query, so a window change invalidates what was
  // loaded — otherwise a reopened row would show the previous window's alerts.
  useEffect(() => {
    setAlerts(null);
    setError(null);
  }, [days, tactic.tactic]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (!next || alerts || loading) return;
    setLoading(true);
    setError(null);
    api
      .getTacticAlerts({ tactic: tactic.tactic, days, limit: 100 })
      .then((response) => {
        setAlerts(response.alerts);
        setTotal(response.total);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load alerts"))
      .finally(() => setLoading(false));
  };

  return (
    <div style={{ borderBottom: "1px solid var(--panel-divider-soft)" }}>
      <button
        onClick={toggle}
        aria-expanded={open}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "var(--space-3)",
          width: "100%",
          padding: "var(--space-2) 0",
          background: "transparent",
          border: "none",
          fontSize: "var(--font-meta)",
          textAlign: "left",
          cursor: "pointer",
          fontFamily: "inherit",
          color: "inherit",
        }}
      >
        <span style={{ color: "var(--text-muted)", width: 10, ...MONO }} aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
        <span style={{ flex: 1, color: "var(--text)", minWidth: 0 }}>{tactic.tactic}</span>
        <span style={{ color: "var(--text-dim)", ...MONO }}>{tactic.techniques} techniques</span>
        <span style={{ color: "var(--text-dim)", ...MONO }}>{tactic.claimed} claimed</span>
        <span style={{ color: "var(--status-success)", ...MONO }}>{tactic.confirmed} confirmed</span>
      </button>

      {open && (
        <div style={{ padding: "0 0 var(--space-3) 22px" }}>
          {loading ? (
            <div style={{ display: "flex", padding: "var(--space-3)" }}>
              <Spinner />
            </div>
          ) : error ? (
            <div style={{ fontSize: "var(--font-meta)", color: "var(--status-danger)" }} role="alert">
              {error}
            </div>
          ) : !alerts || alerts.length === 0 ? (
            <div style={{ fontSize: "var(--font-meta)", color: "var(--text-dim)" }}>
              No alerts in the last {days} days carried a technique in this tactic.
            </div>
          ) : (
            <>
              <div style={{ fontSize: "var(--font-micro)", color: "var(--text-muted)", marginBottom: "var(--space-2)" }}>
                {total} alert{total !== 1 ? "s" : ""} · last {days}d
                {alerts.length < total && ` · showing first ${alerts.length}`}
              </div>
              {alerts.map((alert) => (
                <TacticAlertRow key={alert.run_id} alert={alert} />
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function TacticAlertRow({ alert }: { alert: TacticAlert }) {
  return (
    <div style={{ padding: "var(--space-2) 0", borderTop: "1px solid var(--panel-divider-soft)" }}>
      <div style={{ display: "flex", gap: "var(--space-3)", alignItems: "baseline", flexWrap: "wrap", fontSize: "var(--font-meta)" }}>
        <a
          href={`/alert-investigations/${alert.run_id}`}
          style={{ color: "var(--accent)", fontWeight: 600 }}
        >
          {alert.title || alert.run_id.slice(0, 8)}
        </a>
        {alert.overall_verdict && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: VERDICT_COLOR[alert.overall_verdict] || "var(--text-muted)",
              ...MONO,
            }}
          >
            {alert.overall_verdict.toUpperCase()}
            {alert.highest_risk_score !== null && ` · ${alert.highest_risk_score}`}
          </span>
        )}
        <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 10, ...MONO }}>
          {formatWhen(alert.created_at)}
        </span>
      </div>

      {alert.detection_rule_id && (
        <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2, ...MONO }}>
          {alert.detection_rule_id}
          {alert.detection_rule_name ? ` · ${alert.detection_rule_name}` : ""}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 4, flexWrap: "wrap" }}>
        {alert.techniques.map((technique) => {
          const style = STATUS_STYLE[technique.status] || {
            label: technique.status,
            color: "var(--text-muted)",
          };
          return (
            <span
              key={technique.id}
              title={technique.explanation || undefined}
              style={{
                fontSize: 10,
                padding: "2px 6px",
                border: `1px solid ${style.color}`,
                borderRadius: "var(--radius-sm)",
                color: style.color,
                ...MONO,
              }}
            >
              {technique.id}
              {technique.name ? ` ${technique.name}` : ""} · {style.label}
              {/* Without this, "not corroborated" reads as a failed check rather
                  than one this platform was never able to run. */}
              {!technique.evidenceable && (
                <span style={{ color: "var(--text-muted)" }}> · not evidenceable here</span>
              )}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function TechniqueList({
  title,
  hint,
  rows,
}: {
  title: string;
  hint: string;
  rows: AttackCoverageResponse["techniques"];
}) {
  return (
    <Section title={title} hint={hint}>
      <div className="ds-rows">
      {rows.map((row) => (
        <div
          key={row.id}
          className="ds-row"
          style={{ fontSize: "var(--font-meta)", flexWrap: "wrap" }}
        >
          <a
            href={row.url || "#"}
            target="_blank"
            rel="noreferrer"
            style={{ color: "var(--accent)", fontWeight: 700, ...MONO }}
          >
            {row.id}
          </a>
          <span style={{ color: "var(--text)" }}>{row.name || "—"}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
            {row.tactics.join(" · ")}
          </span>
          {!row.evidenceable && (
            <span
              title="Outside this platform's evidence whitelist — nothing collected here could confirm it either way."
              style={{ color: "var(--text-muted)", fontSize: 10, ...MONO }}
            >
              not evidenceable here
            </span>
          )}
          {row.deprecated && (
            <span
              title="ATT&CK has retired this technique; the detection's mapping predates that."
              style={{ color: "var(--status-warning)", fontSize: "var(--font-micro)", ...MONO }}
            >
              retired by ATT&CK
            </span>
          )}
          <span style={{ marginLeft: "auto", color: "var(--text-dim)", ...MONO }}>
            {row.claimed} claimed · {row.confirmed} confirmed · {row.observed} observed
            {row.ai_suggested > 0 && ` · ${row.ai_suggested} AI-suggested`}
          </span>
        </div>
      ))}
      </div>
    </Section>
  );
}

/* ─── Platform accuracy ─── */

function AccuracyTab({ data }: { data: FeedbackAccuracy | null }) {
  if (!data) return null;
  return (
    <div style={{ display: "grid", gap: "var(--space-5)" }}>
      {/* `note` already says how many were judged, so the metric no longer
          repeats it underneath. */}
      <MetricStrip
        metrics={[
          { label: "Agreement", value: pct(data.agreement_rate), hint: data.note },
          { label: "Agreed", value: data.agreed, status: "success" },
          { label: "Disagreed", value: data.disagreed, status: data.disagreed ? "warning" : "neutral" },
          { label: "Unclear", value: data.unclear, hint: "not counted either way" },
        ]}
      />

      <div style={{ display: "grid", gap: "var(--space-5)", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
        <Bucket
          title="Missed by the platform"
          hint="Called benign here; the analyst says it was real. The expensive direction."
          rows={data.missed_by_platform}
          color="var(--status-danger)"
        />
        <Bucket
          title="Over-flagged by the platform"
          hint="Called malicious or suspicious here; the analyst says it was not."
          rows={data.over_flagged_by_platform}
          color="var(--status-warning)"
        />
      </div>
    </div>
  );
}

function Bucket({
  title,
  hint,
  rows,
  color,
}: {
  title: string;
  hint: string;
  rows: FeedbackAccuracy["missed_by_platform"];
  color: string;
}) {
  return (
    <Section title={<span style={{ color }}>{title}</span>} hint={hint}>
      {rows.length === 0 ? (
        <EmptyState title="None recorded." />
      ) : (
        <div className="ds-rows">
          {rows.map((row) => (
            <div key={row.id} className="ds-row" style={{ fontSize: "var(--font-meta)", flexWrap: "wrap" }}>
              <a
                href={
                  row.subject_type === "investigation"
                    ? `/investigations/${row.subject_id}`
                    : `/alert-investigations/${row.subject_id}`
                }
                style={{ color: "var(--accent)", ...MONO }}
              >
                {row.subject_id.slice(0, 8)}
              </a>
              <span style={{ color: "var(--text-muted)" }}>
                platform said {row.platform_classification || "—"}
              </span>
              {row.note && <span style={{ color: "var(--text-dim)", flexBasis: "100%" }}>{row.note}</span>}
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}
