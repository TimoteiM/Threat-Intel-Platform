"use client";

/**
 * The investigation as an ordered list of claims, each with its evidence.
 *
 * Three rules this component exists to hold, all of them rules about what it
 * must not do:
 *
 * 1. **A chain that did not record fully is never presented as the
 *    investigation.** `incomplete` renders above everything, naming which
 *    steps failed to record and why. A silent short chain is worse than a
 *    visible gap — a recorder that drops three of eight steps and renders as
 *    a complete five-step chain is the defect this record exists to close.
 * 2. **A step that could not be asked is rendered, not dropped.** A 403, a
 *    `no_field_map`, an `out_of_scope` — all appear as *No claim* with their
 *    reason. Dropping them silently shortens the investigation and nobody
 *    can tell.
 * 3. **The steps are the evidence; the summary is derived.** The summary sits
 *    above them labelled as such, and any entity or quantity it states that
 *    no step recorded is marked in place, so it cannot be read as a finding.
 *
 * A step whose kind has no template renders raw JSON on purpose. An
 * unregistered kind must look wrong rather than plausible.
 */

import React, { useCallback, useEffect, useState } from "react";

import {
  getInvestigationRecordByOrigin,
  type InvestigationRecordView,
  type InvestigationStepView,
} from "@/lib/api";
import { durationFromMs } from "@/lib/time";

const MONO = "var(--font-mono)";

function Chip({ children, tone = "neutral" }: {
  children: React.ReactNode;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const color = {
    neutral: "var(--text-muted)",
    good: "var(--success)",
    warn: "var(--warning)",
    bad: "var(--danger)",
  }[tone];
  return (
    <span style={{
      display: "inline-block", padding: "1px 6px", borderRadius: 4,
      fontSize: 10.5, border: `1px solid ${color}`, color, whiteSpace: "nowrap",
    }}>
      {children}
    </span>
  );
}

function Step({ step }: { step: InvestigationStepView }) {
  const noClaim = Boolean(step.absence_kind);
  const costEntries = Object.entries(step.cost || {}).filter(([, v]) => Boolean(v));
  return (
    <li style={{
      listStyle: "none",
      display: "grid",
      gridTemplateColumns: "26px 1fr",
      gap: 10,
      padding: "12px 0",
      borderBottom: "1px solid var(--panel-divider-strong)",
    }}>
      <div style={{
        fontFamily: MONO, fontSize: 12, color: "var(--text-muted)",
        fontVariantNumeric: "tabular-nums", paddingTop: 1,
      }}>
        {step.ordinal}
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 3 }}>
          {step.question}
        </div>

        {noClaim ? (
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--warning)" }}>
              No claim
            </div>
            <p style={{ margin: "3px 0 0", fontSize: 12.5, lineHeight: 1.6, color: "var(--text-dim)" }}>
              {step.absence_reason}
            </p>
          </div>
        ) : step.templated ? (
          <p style={{ margin: 0, fontSize: 13, lineHeight: 1.65, color: "var(--text)" }}>
            {step.text}
          </p>
        ) : (
          <div>
            <div style={{ fontSize: 11, color: "var(--danger)", marginBottom: 4 }}>
              This step kind has no template, so its raw fields are shown.
            </div>
            <pre style={{
              margin: 0, fontFamily: MONO, fontSize: 11, lineHeight: 1.5,
              color: "var(--text-dim)", background: "var(--bg-input)",
              padding: 8, borderRadius: 4, overflowX: "auto",
            }}>{step.text}</pre>
          </div>
        )}

        <div style={{
          marginTop: 6, display: "flex", flexWrap: "wrap", gap: 6,
          alignItems: "center",
        }}>
          {noClaim && <Chip tone="warn">{step.absence_kind?.replace(/_/g, " ")}</Chip>}
          {step.source && <Chip>{step.source}</Chip>}
          {step.verdict && (
            <Chip tone={step.verdict === "clean" || step.verdict === "none" ? "neutral" : "warn"}>
              {step.verdict}
            </Chip>
          )}
          {costEntries.map(([k, v]) => (
            <Chip key={k} tone="warn">{String(v)} {k.replace(/_/g, " ")}</Chip>
          ))}
          {costEntries.length === 0 && !noClaim && <Chip tone="good">no external cost</Chip>}
          {step.duration_ms !== null && <Chip>{durationFromMs(step.duration_ms)}</Chip>}
          {step.response_truncated && (
            <Chip tone="warn">
              response excerpt truncated{step.response_bytes ? ` (${step.response_bytes.toLocaleString()} bytes seen)` : ""}
            </Chip>
          )}
        </div>
      </div>
    </li>
  );
}

export default function InvestigationChain({
  surface, originId,
}: { surface: string; originId: string }) {
  const [record, setRecord] = useState<InvestigationRecordView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setMissing(false);
    try {
      setRecord(await getInvestigationRecordByOrigin(surface, originId));
    } catch (e: any) {
      const message = String(e?.message ?? e);
      // A record that does not exist is different from one that could not be
      // loaded, and the second must not render as "this investigation had no
      // steps".
      if (message.includes("404") || /no investigation record/i.test(message)) {
        setMissing(true);
      } else {
        setError(message);
      }
      setRecord(null);
    } finally {
      setLoading(false);
    }
  }, [surface, originId]);

  useEffect(() => { void load(); }, [load]);

  if (loading) {
    return <p style={{ fontSize: 12.5, color: "var(--text-muted)" }}>Loading the investigation…</p>;
  }
  if (missing) {
    return (
      <p style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--text-muted)" }}>
        No investigation record was written for this run. Records are written
        when an investigation completes, so runs from before this existed do
        not have one — that is an absence of a record, not an investigation
        with no steps.
      </p>
    );
  }
  if (error || !record) {
    return (
      <p style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--warning)" }}>
        The investigation record could not be loaded: {error}. This is a
        failure to read it, not a report that it has no steps.
      </p>
    );
  }

  const c = record.counters;
  return (
    <section style={{
      border: "1px solid var(--border)", borderRadius: 8,
      background: "var(--surface)", padding: 16,
    }}>
      <header style={{
        display: "flex", flexWrap: "wrap", alignItems: "baseline",
        justifyContent: "space-between", gap: 8, marginBottom: 12,
      }}>
        <h3 style={{
          margin: 0, fontSize: 12, fontWeight: 600, letterSpacing: 0.5,
          textTransform: "uppercase", color: "var(--text-dim)",
        }}>
          The investigation
        </h3>
        <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
          {c.steps_run} steps · {c.steps_escalated} with an external cost ·{" "}
          {c.model_calls} model call{c.model_calls === 1 ? "" : "s"}
        </span>
      </header>

      {/* Rule 1. Above everything, and the chain is not the investigation. */}
      {record.incomplete && (
        <div style={{
          border: "1px solid var(--warning)", borderRadius: 6,
          padding: "10px 12px", marginBottom: 12, background: "var(--bg-input)",
        }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--warning)" }}>
            This chain is incomplete — it is not the whole investigation
          </div>
          <p style={{ margin: "4px 0 6px", fontSize: 12, lineHeight: 1.6, color: "var(--text-dim)" }}>
            {record.incomplete_steps.length} step
            {record.incomplete_steps.length === 1 ? "" : "s"} ran but could not
            be recorded, so what follows is shorter than what happened.
          </p>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: "var(--text-muted)" }}>
            {record.incomplete_steps.map((s) => (
              <li key={`${s.ordinal}-${s.kind}`}>
                step {s.ordinal} ({s.kind}): {s.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Rule 3. Derived, labelled, and unverified claims marked. */}
      {record.summary && (
        <div style={{ marginBottom: 14 }}>
          <div style={{
            fontSize: 10.5, letterSpacing: 0.4, textTransform: "uppercase",
            color: "var(--text-muted)", marginBottom: 4,
          }}>
            Summary — derived from the steps below, which are the evidence
          </div>
          <p style={{ margin: 0, fontSize: 13, lineHeight: 1.65, color: "var(--text)" }}>
            {record.summary}
          </p>
          {(record.summary_unverified_entities.length > 0 ||
            record.summary_unverified_numerals.length > 0) && (
            <p style={{ margin: "6px 0 0", fontSize: 11.5, lineHeight: 1.6, color: "var(--warning)" }}>
              Not supported by any step below, so not evidence:{" "}
              {[...record.summary_unverified_entities,
                ...record.summary_unverified_numerals].join(", ")}
            </p>
          )}
        </div>
      )}

      <ul style={{ margin: 0, padding: 0 }}>
        {record.steps.map((s) => <Step key={s.ordinal} step={s} />)}
      </ul>

      <footer style={{
        marginTop: 10, fontSize: 11, lineHeight: 1.55, color: "var(--text-muted)",
      }}>
        Every sentence above comes from a template over recorded fields, not
        from a model. Attribution: {record.actor.kind.replace(/_/g, " ")}
        {record.actor.recorded ? ` (${record.actor.recorded})` : ""}.
      </footer>
    </section>
  );
}
