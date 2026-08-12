"use client";

/**
 * One metric.
 *
 * Was a bordered gradient card per scalar, ending in a glowing dot, the word
 * "Stable" and the label "Console signal" — three pieces of decoration around
 * one number, none of them telling the analyst anything. The trend defaulted to
 * `flat`, so "Stable" was printed on values nobody had compared to anything.
 *
 * Now: label, number, optional caption. No border, no gradient. The trend only
 * appears when a caller actually passes one, and "Console signal" is gone.
 */

import React from "react";
import type { ConsoleTone } from "@/components/ui/ConsoleModule";

interface SignalCardProps {
  label: React.ReactNode;
  value: React.ReactNode;
  caption?: React.ReactNode;
  badge?: React.ReactNode;
  tone?: ConsoleTone;
  accent?: string;
  compact?: boolean;
  trend?: "up" | "down" | "flat";
  style?: React.CSSProperties;
  className?: string;
}

export default function SignalCard({
  label,
  value,
  caption,
  badge,
  tone = "info",
  accent,
  compact = false,
  trend = "flat",
  style,
  className,
}: SignalCardProps) {
  const color = accent || toneColor(tone);

  return (
    <div className={className} style={{ minWidth: 0, display: "grid", gap: 2, ...style }}>
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", minWidth: 0 }}>
        <span
          style={{
            fontSize: "var(--font-micro)",
            fontWeight: 700,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--text-muted)",
          }}
        >
          {label}
        </span>
        {badge}
      </div>

      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: compact ? 18 : 22,
          lineHeight: 1.15,
          fontWeight: 700,
          color: tone === "neutral" || !accent ? "var(--text-strong)" : color,
          overflowWrap: "anywhere",
        }}
      >
        {value}
      </div>

      {caption ? (
        <div style={{ fontSize: "var(--font-micro)", lineHeight: 1.5, color: "var(--text-dim)" }}>{caption}</div>
      ) : null}

      {trend !== "flat" ? (
        <div style={{ fontSize: "var(--font-micro)", color, fontWeight: 600 }}>
          {trend === "up" ? "↑ Rising" : "↓ Falling"}
        </div>
      ) : null}
    </div>
  );
}

function toneColor(tone: ConsoleTone) {
  switch (tone) {
    case "success":
      return "var(--status-success)";
    case "warning":
      return "var(--status-warning)";
    case "danger":
      return "var(--status-danger)";
    case "neutral":
      return "var(--status-neutral)";
    default:
      return "var(--status-info)";
  }
}
