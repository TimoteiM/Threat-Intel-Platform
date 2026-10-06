"use client";

/**
 * Was the platform right about this alert?
 *
 * The feedback API and the accuracy report have existed all along, and nothing
 * called them: four judgements across 14,541 alert runs. Every accuracy figure
 * the platform shows — and every claim we could make to a client about how
 * often it is right — rests on those four.
 *
 * This is the smallest thing that fixes it: one question, three answers, on
 * the page an analyst is already looking at when they know the answer. The
 * note is optional because a required field is how feedback stops being given.
 */

import React, { useEffect, useState } from "react";
import { getAnalystFeedbackFor, submitAnalystFeedback } from "@/lib/api";

type Verdict = "true_positive" | "false_positive" | "unclear";

const CHOICES: Array<{ id: Verdict; label: string; hint: string; tone: string }> = [
  {
    id: "true_positive",
    label: "True positive",
    hint: "Real activity worth the alert.",
    tone: "var(--status-critical)",
  },
  {
    id: "false_positive",
    label: "False positive",
    hint: "Benign. The rule or the platform was wrong.",
    tone: "var(--status-ok, var(--status-info))",
  },
  {
    id: "unclear",
    label: "Unclear",
    hint: "Not enough evidence either way — recorded as such, not guessed.",
    tone: "var(--text-muted)",
  },
];

export default function AnalystVerdictControl({
  subjectType,
  subjectId,
}: {
  subjectType: "alert_run" | "investigation";
  subjectId: string;
}) {
  const [current, setCurrent] = useState<Verdict | null>(null);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAnalystFeedbackFor(subjectType, subjectId)
      .then((data) => {
        if (cancelled || !data?.feedback) return;
        setCurrent((data.feedback.verdict as Verdict) ?? null);
        setNote(data.feedback.note || "");
      })
      .catch(() => {
        /* No judgement yet is the normal case, not an error worth showing. */
      });
    return () => {
      cancelled = true;
    };
  }, [subjectType, subjectId]);

  const record = async (verdict: Verdict) => {
    setSaving(true);
    setMessage(null);
    try {
      const result = await submitAnalystFeedback({
        subject_type: subjectType,
        subject_id: subjectId,
        verdict,
        note: note.trim() || undefined,
      });
      setCurrent(verdict);
      setMessage(
        result.replaced_previous
          ? "Recorded — this replaces your earlier judgement."
          : "Recorded. This is what the accuracy report is measured against.",
      );
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Could not record that.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
        Your call on what the platform concluded. Nothing else measures whether it was
        right, so an unanswered alert is an unmeasured one.
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {CHOICES.map((choice) => {
          const active = current === choice.id;
          return (
            <button
              key={choice.id}
              type="button"
              disabled={saving}
              aria-pressed={active}
              title={choice.hint}
              onClick={() => record(choice.id)}
              style={{
                border: `1px solid ${active ? choice.tone : "var(--border)"}`,
                background: active ? "var(--accent-glow, transparent)" : "transparent",
                color: active ? choice.tone : "var(--text-dim)",
                borderRadius: 999,
                padding: "6px 14px",
                fontSize: 12.5,
                fontWeight: active ? 700 : 500,
                cursor: saving ? "default" : "pointer",
              }}
            >
              {choice.label}
            </button>
          );
        })}
      </div>

      <input
        type="text"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Why, in a few words (optional)"
        aria-label="Note on this judgement"
        style={{
          borderRadius: 10,
          border: "1px solid var(--panel-divider-strong, var(--border))",
          background: "var(--panel-card-bg, transparent)",
          color: "var(--text-strong, var(--text))",
          padding: "6px 10px",
          fontSize: 12.5,
        }}
      />

      {message && (
        <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{message}</div>
      )}
    </div>
  );
}
