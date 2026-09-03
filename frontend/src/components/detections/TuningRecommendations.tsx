"use client";

/**
 * Rules this platform has investigated enough times to say are not worth
 * investigating again — and the narrowest way to say so.
 *
 * Every alert behind these numbers was already run through the collectors, so
 * the conditions are derived from what the alerts actually contained rather
 * than proposed from their names. Two rules of the surface follow from that:
 * the replay line is shown before the action, never after it, and the condition
 * an analyst is about to commit to is written out in full. Nothing here mutes a
 * rule on a single click.
 */

import React, { useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import type { TuningCondition, TuningRecommendation, TuningResponse } from "@/lib/types";
import { EmptyState, LoadingState, Section } from "@/components/ui/Primitives";

const MONO: React.CSSProperties = {
  fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)",
};

function FieldChips({ fields }: { fields: Record<string, string> }) {
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {Object.entries(fields).map(([name, value]) => (
        <span
          key={name}
          style={{
            ...MONO, fontSize: 10.5, padding: "2px 7px", borderRadius: 5,
            border: "1px solid var(--panel-divider)", background: "var(--bg-elevated)",
            color: "var(--text-secondary)",
          }}
        >
          <span style={{ color: "var(--text-muted)" }}>{name}</span>
          {" = "}
          <span style={{ color: "var(--text)" }}>{value}</span>
        </span>
      ))}
    </div>
  );
}


/** Recommendations keyed by rule id, so a rule row can find its own. */
export function useTuningRecommendations(days: number) {
  const [byRule, setByRule] = useState<Record<string, TuningRecommendation>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getTuningRecommendations({ days: Math.max(days, 90) })
      .then((result) => {
        if (cancelled) return;
        const map: Record<string, TuningRecommendation> = {};
        for (const item of result.recommendations) map[item.rule_id] = item;
        setByRule(map);
      })
      .catch(() => !cancelled && setByRule({}))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [days]);

  return { byRule, loading };
}

export function RuleTuningPanel({
  item,
  onApplied,
  collapsible = false,
}: {
  item: TuningRecommendation;
  onApplied?: (ruleId: string) => void;
  /** Rendered as a closed summary line that opens on click. Used on the rule
   *  list, where the recommendation belongs to a rule the analyst is already
   *  reading rather than to a separate section they have to go and find. */
  collapsible?: boolean;
}) {
  const [open, setOpen] = useState(!collapsible);
  const [chosen, setChosen] = useState(0);
  const [showWazuh, setShowWazuh] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const condition: TuningCondition | undefined = item.conditions[chosen] || item.proposed;

  if (!item.recommendable || !condition) {
    return (
      <div
        style={{
          border: "1px solid var(--panel-divider)", borderRadius: 10,
          padding: "12px 14px", display: "grid", gap: 6,
        }}
      >
        <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
          <span style={{ ...MONO, fontSize: 12, color: "var(--text-muted)" }}>{item.rule_id}</span>
          <span style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>{item.rule_name}</span>
          <span style={{ marginLeft: "auto", ...MONO, fontSize: 11, color: "var(--status-warning)" }}>
            not recommendable
          </span>
        </div>
        <p style={{ margin: 0, fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
          {item.blocked_reason}
        </p>
      </div>
    );
  }

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const expires = new Date();
      expires.setDate(expires.getDate() + (item.expires_in_days || 90));
      await api.createAlertExclusion({
        match_fields: condition.match_fields,
        reason: `${item.reason} · condition covers ${condition.covered} of ${item.noise} and would have silenced 0 actionable alerts`,
        expires_at: expires.toISOString(),
      });
      setDone(`Added — expires ${expires.toLocaleDateString()}`);
      onApplied?.(item.rule_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the exclusion");
    } finally {
      setBusy(false);
    }
  };

  if (collapsible && !open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        style={{
          width: "100%", textAlign: "left", cursor: "pointer",
          marginTop: "var(--space-3)", padding: "8px 12px", borderRadius: 8,
          border: "1px solid var(--panel-divider-strong)",
          background: "var(--bg-elevated)", color: "var(--text-secondary)",
          fontSize: 11.5, fontFamily: "inherit",
          display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap",
        }}
      >
        <span style={{ color: "var(--status-warning)" }}>▸ Recommended exclusion</span>
        <span style={{ ...MONO, fontSize: 11, color: "var(--text)" }}>
          {condition.scope}
        </span>
        <span style={{ marginLeft: "auto", ...MONO, fontSize: 10.5, color: "var(--text-muted)" }}>
          silences {condition.covered} · 0 actionable
        </span>
      </button>
    );
  }

  return (
    <div
      style={{
        border: "1px solid var(--panel-divider)", borderRadius: 10,
        padding: "13px 15px", display: "grid", gap: 10,
        marginTop: collapsible ? "var(--space-3)" : 0,
      }}
    >
      <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
        {collapsible ? (
          <button
            type="button"
            onClick={() => setOpen(false)}
            style={{
              background: "none", border: "none", padding: 0, cursor: "pointer",
              color: "var(--status-warning)", fontSize: 12, fontFamily: "inherit",
            }}
          >
            ▾ Recommended exclusion
          </button>
        ) : (
          <>
            <span style={{ ...MONO, fontSize: 12, color: "var(--accent)" }}>{item.rule_id}</span>
            <strong style={{ fontSize: 12.5, color: "var(--text)", fontWeight: 600 }}>
              {item.rule_name}
            </strong>
          </>
        )}
        <span style={{ marginLeft: "auto", ...MONO, fontSize: 11, color: "var(--text-muted)" }}>
          {item.noise} noise / {item.alerts} alerts
          {item.hosts ? ` · ${item.hosts} host${item.hosts === 1 ? "" : "s"}` : ""}
        </span>
      </div>

      {/* The replay comes before the action, not after it. */}
      <div
        style={{
          background: "var(--bg-elevated)", borderRadius: 7, padding: "9px 12px",
          fontSize: 11.5, color: "var(--text-secondary)", lineHeight: 1.55,
        }}
      >
        Applying this would have silenced{" "}
        <strong style={{ color: "var(--text)" }}>{condition.covered}</strong> of this
        rule&apos;s {item.noise} unactioned alerts over the last{" "}
        {item.replay?.window_days ?? 90} days, and{" "}
        <strong style={{ color: "var(--status-success)" }}>0</strong> that concluded
        malicious or suspicious. Candidates that would have silenced even one
        actionable alert are discarded, not listed.
        {condition.notes.map((note) => (
          <div key={note} style={{ marginTop: 5, color: "var(--status-warning)" }}>
            {note}
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gap: 6 }}>
        <span style={{ fontSize: 10.5, color: "var(--text-muted)", letterSpacing: 0.4 }}>
          CONDITION — all fields must match
        </span>
        <FieldChips fields={condition.match_fields} />
      </div>

      {item.conditions.length > 1 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>Narrower / broader:</span>
          {item.conditions.map((option, index) => (
            <button
              key={option.scope}
              type="button"
              onClick={() => setChosen(index)}
              title={option.scope}
              style={{
                ...MONO, fontSize: 10, padding: "3px 8px", borderRadius: 5, cursor: "pointer",
                border: `1px solid ${index === chosen ? "var(--accent)" : "var(--panel-divider)"}`,
                background: index === chosen ? "rgba(96,165,250,0.12)" : "var(--panel-card-bg)",
                color: "var(--text-secondary)", maxWidth: 260,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}
            >
              {option.scope} · {option.covered}/{item.noise}
            </button>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button
          type="button"
          onClick={apply}
          disabled={busy || !!done}
          style={{
            fontSize: 11.5, padding: "6px 12px", borderRadius: 7, cursor: done ? "default" : "pointer",
            border: "1px solid var(--panel-divider-strong)",
            background: done ? "var(--panel-card-bg)" : "var(--bg-elevated)",
            color: done ? "var(--status-success)" : "var(--text)",
          }}
        >
          {done ? done : busy ? "Adding…" : `Suppress here (expires in ${item.expires_in_days ?? 90}d)`}
        </button>
        <button
          type="button"
          onClick={() => setShowWazuh((open) => !open)}
          style={{
            fontSize: 11.5, padding: "6px 12px", borderRadius: 7, cursor: "pointer",
            border: "1px solid var(--panel-divider)", background: "var(--panel-card-bg)",
            color: "var(--text-secondary)",
          }}
        >
          {showWazuh ? "Hide" : "Fix at source"} — Wazuh rule
        </button>
        {error && (
          <span style={{ fontSize: 11, color: "var(--status-danger)" }}>{error}</span>
        )}
      </div>

      {showWazuh && (
        <div style={{ display: "grid", gap: 6 }}>
          <span style={{ fontSize: 10.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
            Paste into <code>local_rules.xml</code>. Level 0 stops the alerting without
            dropping the event, so it stays searchable in the archive. This platform
            never writes to Wazuh — it has no credentials there and should not acquire
            any in order to silence detections.
          </span>
          <pre
            style={{
              ...MONO, fontSize: 10.5, margin: 0, padding: "10px 12px", borderRadius: 7,
              background: "var(--bg-elevated)", border: "1px solid var(--panel-divider)",
              color: "var(--text-secondary)", overflowX: "auto", lineHeight: 1.5,
            }}
          >
            {item.wazuh_rule}
          </pre>
          <button
            type="button"
            onClick={() => {
              navigator.clipboard?.writeText(item.wazuh_rule || "");
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1800);
            }}
            style={{
              justifySelf: "start", fontSize: 11, padding: "4px 10px", borderRadius: 6,
              border: "1px solid var(--panel-divider)", background: "var(--panel-card-bg)",
              color: "var(--text-secondary)", cursor: "pointer",
            }}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}
    </div>
  );
}

export default function TuningRecommendations({ days }: { days: number }) {
  const [data, setData] = useState<TuningResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [applied, setApplied] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .getTuningRecommendations({ days: Math.max(days, 90) })
      .then((result) => !cancelled && setData(result))
      .catch(() => !cancelled && setData(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [days]);

  const recommendable = useMemo(
    () => (data?.recommendations || []).filter((item) => item.recommendable),
    [data],
  );

  if (loading) return <LoadingState label="Replaying every rule against its own history…" />;
  if (!data || data.recommendations.length === 0) {
    return (
      <Section
        title="Tuning"
        hint="Rules the platform has investigated enough times to judge."
      >
        <EmptyState
          title="No rule qualifies for tuning"
          hint="A recommendation needs a rule with enough alerts to judge, none of which concluded malicious or suspicious."
        />
      </Section>
    );
  }

  return (
    <Section
      title="Tuning candidates"
      hint={`${recommendable.length} rule(s) have never produced an actionable verdict — ${data.alerts_silenceable} alerts of pure drain${applied.length ? `, ${applied.length} suppressed` : ""}. Every condition below was replayed against the rule's whole history before being offered.`}
    >
      <div style={{ display: "grid", gap: 10 }}>
        {/* Applied rows stay in place rather than vanishing: the confirmation
            names the expiry date, and removing the row would take that with it. */}
        {data.recommendations.map((item) => (
          <RuleTuningPanel
            key={item.rule_id}
            item={item}
            onApplied={(ruleId) => setApplied((current) => [...current, ruleId])}
          />
        ))}
      </div>
    </Section>
  );
}
