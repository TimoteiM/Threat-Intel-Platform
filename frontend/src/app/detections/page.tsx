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
} from "@/lib/types";
import Spinner from "@/components/shared/Spinner";

const WINDOWS = [7, 30, 90];

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

function rateColor(rate: number | null, invert = false): string {
  if (rate === null) return "var(--text-muted)";
  const bad = invert ? rate < 0.3 : rate >= 0.8;
  const mid = invert ? rate < 0.6 : rate >= 0.5;
  return bad ? "#ef4444" : mid ? "#f59e0b" : "#10b981";
}

function pct(rate: number | null): string {
  return rate === null ? "—" : `${Math.round(rate * 100)}%`;
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div style={{ ...CARD, flex: 1, minWidth: 150 }}>
      <div style={LABEL}>{label.toUpperCase()}</div>
      <div style={{ fontSize: 24, fontWeight: 700, color: "var(--text)", marginTop: 6, ...MONO }}>
        {value}
      </div>
      {hint && <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
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

  return (
    <div style={{ paddingTop: 20, paddingBottom: 40, maxWidth: 1280 }}>
      <div className="animate-in" style={{ marginBottom: 16 }}>
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
          DETECTION QUALITY
        </div>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          What each rule is worth, measured from what its alerts turned out to be
        </div>
      </div>

      {/* Tabs + window */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, alignItems: "center", flexWrap: "wrap" }}>
        {(["rules", "attack", "accuracy"] as const).map((key) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            style={{
              padding: "6px 14px",
              background: tab === key ? "var(--bg-hover)" : "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: tab === key ? "var(--text)" : "var(--text-dim)",
              fontSize: 10,
              fontWeight: 700,
              cursor: "pointer",
              letterSpacing: "0.06em",
              ...MONO,
            }}
          >
            {key === "rules" ? "RULES" : key === "attack" ? "ATT&CK COVERAGE" : "PLATFORM ACCURACY"}
          </button>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          {WINDOWS.map((value) => (
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
      ) : tab === "rules" ? (
        <RulesTab data={quality} />
      ) : tab === "attack" ? (
        <AttackTab data={coverage} />
      ) : (
        <AccuracyTab data={accuracy} />
      )}
    </div>
  );
}

/* ─── Rules ─── */

function RulesTab({ data }: { data: DetectionQualityResponse | null }) {
  if (!data || !data.rules.length) {
    return (
      <div
        style={{
          ...CARD,
          textAlign: "center",
          color: "var(--text-dim)",
          fontSize: 12,
          borderStyle: "dashed",
        }}
      >
        No alerts carrying a detection rule id in this window. Rule quality is measured from
        <code style={{ margin: "0 4px" }}>rule.id</code> on ingested alerts — analyst-pasted alerts
        have none, and are counted as unattributed.
      </div>
    );
  }

  return (
    <>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Stat label="Rules seen" value={data.rules_seen} />
        <Stat label="Alerts" value={data.alerts_total} />
        <Stat
          label="Unattributed"
          value={data.unattributed_alerts}
          hint="alerts with no rule id"
        />
        <Stat
          label="Scoring floor"
          value={`${data.min_alerts_to_score} alerts`}
          hint="below this, counts only"
        />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {data.rules.map((rule) => (
          <div key={rule.rule_id} style={CARD}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", ...MONO }}>
                {rule.rule_id}
              </span>
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{rule.rule_name || "—"}</span>
              <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-muted)", ...MONO }}>
                {rule.alerts} alert{rule.alerts !== 1 ? "s" : ""}
              </span>
            </div>

            <div style={{ display: "flex", gap: 18, marginTop: 10, flexWrap: "wrap" }}>
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
                  color="#f59e0b"
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

            <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>
              {rule.assessment}
            </div>
          </div>
        ))}
      </div>
    </>
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

function AttackTab({ data }: { data: AttackCoverageResponse | null }) {
  if (!data || !data.runs_assessed) {
    return (
      <div style={{ ...CARD, textAlign: "center", color: "var(--text-dim)", fontSize: 12, borderStyle: "dashed" }}>
        No assessed runs in this window yet. Coverage is built from alert runs that carried an ATT&CK
        mapping or produced technique evidence.
      </div>
    );
  }

  return (
    <>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Stat label="Runs assessed" value={data.runs_assessed} />
        <Stat label="Techniques seen" value={data.techniques_seen} />
        <Stat
          label="Unvalidated mappings"
          value={data.unvalidated_mappings.length}
          hint="claimed, never confirmed"
        />
        <Stat
          label="Undetected behaviour"
          value={data.undetected_behaviour.length}
          hint="observed, never claimed"
        />
      </div>

      {data.undetected_behaviour.length > 0 && (
        <Section
          title="Observed but never claimed by a detection"
          hint="Evidence showed these; no rule said they would. Detection gaps."
          rows={data.undetected_behaviour}
        />
      )}
      {data.unvalidated_mappings.length > 0 && (
        <Section
          title="Claimed but never corroborated"
          hint="Rules assert these; the evidence has not yet borne one out. Not proof the mapping is wrong — but nothing has validated it."
          rows={data.unvalidated_mappings}
        />
      )}

      <div style={{ ...CARD, marginTop: 12 }}>
        <div style={{ ...LABEL, marginBottom: 10 }}>BY TACTIC</div>
        {data.tactics.map((tactic) => (
          <div
            key={tactic.tactic}
            style={{
              display: "flex",
              gap: 12,
              padding: "6px 0",
              borderBottom: "1px solid var(--border)",
              fontSize: 11,
            }}
          >
            <span style={{ flex: 1, color: "var(--text)" }}>{tactic.tactic}</span>
            <span style={{ color: "var(--text-dim)", ...MONO }}>{tactic.techniques} techniques</span>
            <span style={{ color: "var(--text-dim)", ...MONO }}>{tactic.claimed} claimed</span>
            <span style={{ color: "#10b981", ...MONO }}>{tactic.confirmed} confirmed</span>
          </div>
        ))}
      </div>

      {data.blind_spots.length > 0 && (
        <div style={{ ...CARD, marginTop: 12 }}>
          <div style={{ ...LABEL, marginBottom: 8 }}>BLIND SPOTS</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>
            Tactics this platform could evidence but has never once seen:
          </div>
          {data.blind_spots.map((spot) => (
            <div key={spot.tactic} style={{ fontSize: 11, color: "var(--text)", padding: "3px 0" }}>
              {spot.tactic}{" "}
              <span style={{ color: "var(--text-muted)" }}>
                — {spot.techniques_we_could_evidence} technique(s) we could detect
              </span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function Section({
  title,
  hint,
  rows,
}: {
  title: string;
  hint: string;
  rows: AttackCoverageResponse["techniques"];
}) {
  return (
    <div style={{ ...CARD, marginBottom: 12 }}>
      <div style={{ ...LABEL, marginBottom: 4 }}>{title.toUpperCase()}</div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 10 }}>{hint}</div>
      {rows.map((row) => (
        <div
          key={row.id}
          style={{
            display: "flex",
            gap: 12,
            padding: "6px 0",
            borderBottom: "1px solid var(--border)",
            fontSize: 11,
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <a
            href={row.url || "#"}
            target="_blank"
            rel="noreferrer"
            style={{ color: "#818cf8", fontWeight: 700, ...MONO }}
          >
            {row.id}
          </a>
          <span style={{ color: "var(--text)" }}>{row.name || "—"}</span>
          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>{row.tactic}</span>
          <span style={{ marginLeft: "auto", color: "var(--text-dim)", ...MONO }}>
            {row.claimed} claimed · {row.confirmed} confirmed · {row.observed} observed
            {row.ai_suggested > 0 && ` · ${row.ai_suggested} AI-suggested`}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ─── Platform accuracy ─── */

function AccuracyTab({ data }: { data: FeedbackAccuracy | null }) {
  if (!data) return null;
  return (
    <>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Stat label="Agreement" value={pct(data.agreement_rate)} hint={`${data.judged} judged`} />
        <Stat label="Agreed" value={data.agreed} />
        <Stat label="Disagreed" value={data.disagreed} />
        <Stat label="Unclear" value={data.unclear} hint="not counted either way" />
      </div>

      <div style={{ ...CARD, marginBottom: 12, fontSize: 12, color: "var(--text-dim)" }}>{data.note}</div>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <Bucket
          title="Missed by the platform"
          hint="Called benign here; the analyst says it was real. The expensive direction."
          rows={data.missed_by_platform}
          color="#ef4444"
        />
        <Bucket
          title="Over-flagged by the platform"
          hint="Called malicious or suspicious here; the analyst says it was not."
          rows={data.over_flagged_by_platform}
          color="#f59e0b"
        />
      </div>
    </>
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
    <div style={{ ...CARD, flex: 1, minWidth: 320 }}>
      <div style={{ ...LABEL, color, marginBottom: 4 }}>{title.toUpperCase()}</div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 10 }}>{hint}</div>
      {rows.length === 0 ? (
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>None recorded.</div>
      ) : (
        rows.map((row) => (
          <div key={row.id} style={{ fontSize: 11, padding: "5px 0", borderBottom: "1px solid var(--border)" }}>
            <a
              href={
                row.subject_type === "investigation"
                  ? `/investigations/${row.subject_id}`
                  : `/alert-investigations/${row.subject_id}`
              }
              style={{ color: "#818cf8", ...MONO }}
            >
              {row.subject_id.slice(0, 8)}
            </a>
            <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>
              platform said {row.platform_classification || "—"}
            </span>
            {row.note && (
              <div style={{ color: "var(--text-dim)", marginTop: 2 }}>{row.note}</div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
