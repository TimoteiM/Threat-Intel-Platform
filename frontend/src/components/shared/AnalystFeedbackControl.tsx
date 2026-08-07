"use client";

/**
 * The analyst's call on what the platform concluded.
 *
 * Without this the decision engine cannot be measured: every tuning decision is
 * a guess about whether a classification was right. One click records it; the
 * note is optional because a required note is a reason not to click at all.
 *
 * The current judgement is loaded on mount so the control shows state rather
 * than asking the same question twice, and re-submitting replaces it — an
 * analyst changing their mind is a correction, not a second data point.
 */

import React, { useEffect, useState } from "react";
import * as api from "@/lib/api";
import type { AnalystFeedback } from "@/lib/types";

type Verdict = AnalystFeedback["verdict"];

const OPTIONS: Array<{ verdict: Verdict; label: string; color: string; hint: string }> = [
  {
    verdict: "true_positive",
    label: "TRUE POSITIVE",
    color: "#ef4444",
    hint: "The threat was real",
  },
  {
    verdict: "false_positive",
    label: "FALSE POSITIVE",
    color: "#10b981",
    hint: "Not a threat",
  },
  { verdict: "unclear", label: "UNCLEAR", color: "#64748b", hint: "Could not determine" },
];

export default function AnalystFeedbackControl({
  subjectType,
  subjectId,
  compact = false,
}: {
  subjectType: "investigation" | "alert_run";
  subjectId: string;
  compact?: boolean;
}) {
  const [current, setCurrent] = useState<AnalystFeedback | null>(null);
  const [note, setNote] = useState("");
  const [showNote, setShowNote] = useState(false);
  const [saving, setSaving] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getAnalystFeedbackFor(subjectType, subjectId)
      .then((result) => {
        if (cancelled) return;
        setCurrent(result.feedback);
        setNote(result.feedback?.note || "");
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [subjectType, subjectId]);

  const submit = async (verdict: Verdict) => {
    setSaving(verdict);
    setError(null);
    try {
      const saved = await api.submitAnalystFeedback({
        subject_type: subjectType,
        subject_id: subjectId,
        verdict,
        note: note.trim() || undefined,
      });
      setCurrent(saved);
      setShowNote(false);
    } catch (err: any) {
      setError(err?.message || "Could not save feedback");
    } finally {
      setSaving(null);
    }
  };

  return (
    <div
      style={{
        padding: compact ? "10px 12px" : 16,
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div
        style={{
          fontSize: 9,
          fontWeight: 700,
          color: "var(--text-muted)",
          letterSpacing: "0.08em",
          fontFamily: "var(--font-mono)",
          marginBottom: 8,
        }}
      >
        WAS THIS RIGHT?
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {OPTIONS.map((option) => {
          const selected = current?.verdict === option.verdict;
          return (
            <button
              key={option.verdict}
              onClick={() => submit(option.verdict)}
              disabled={saving !== null}
              title={option.hint}
              style={{
                padding: "6px 12px",
                background: selected ? `${option.color}22` : "transparent",
                border: `1px solid ${selected ? option.color : "var(--border)"}`,
                borderRadius: "var(--radius-sm)",
                color: selected ? option.color : "var(--text-dim)",
                fontSize: 10,
                fontWeight: 700,
                cursor: saving ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.06em",
                opacity: saving && saving !== option.verdict ? 0.5 : 1,
              }}
            >
              {saving === option.verdict ? "SAVING…" : option.label}
            </button>
          );
        })}
        <button
          onClick={() => setShowNote((value) => !value)}
          style={{
            padding: "6px 10px",
            background: "transparent",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            color: "var(--text-dim)",
            fontSize: 10,
            cursor: "pointer",
            fontFamily: "var(--font-mono)",
          }}
        >
          {showNote ? "HIDE NOTE" : note ? "EDIT NOTE" : "+ NOTE"}
        </button>
      </div>

      {showNote && (
        <textarea
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Optional — what made this right or wrong? Saved with your next click."
          rows={2}
          style={{
            width: "100%",
            marginTop: 8,
            padding: "8px 12px",
            background: "var(--bg-input)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            color: "var(--text)",
            fontSize: 12,
            fontFamily: "var(--font-mono)",
            outline: "none",
            resize: "vertical",
          }}
        />
      )}

      {current && (
        <div style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}>
          Recorded {current.updated_at || current.created_at
            ? new Date(current.updated_at || current.created_at!).toLocaleString()
            : "just now"}
          {current.platform_classification &&
            ` · the platform said ${current.platform_classification}`}
          {current.note && ` · "${current.note}"`}
        </div>
      )}

      {error && (
        <div style={{ marginTop: 8, fontSize: 10, color: "#ef4444", fontFamily: "var(--font-mono)" }}>
          {error}
        </div>
      )}
    </div>
  );
}
