"use client";

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
  const colors = resolveToneColor(tone, accent);

  return (
    <article
      className={className}
      style={{
        position: "relative",
        overflow: "hidden",
        borderRadius: 18,
        border: `1px solid ${colors.border}`,
        background: "var(--panel-card-bg)",
        boxShadow: "var(--panel-shadow-card)",
        padding: compact ? 14 : 18,
        ...style,
      }}
    >
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          background: `radial-gradient(120px circle at 16% 0%, ${colors.glow}, transparent 60%)`,
          pointerEvents: "none",
        }}
      />
      <div style={{ position: "relative", zIndex: 1, display: "grid", gap: 10 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
          <div style={{ minWidth: 0 }}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: "var(--text-dim)",
                marginBottom: 8,
              }}
            >
              {label}
            </div>
            <div
              style={{
                fontFamily: "var(--font-display)",
                fontSize: compact ? 24 : 30,
                lineHeight: 1.08,
                fontWeight: 700,
                letterSpacing: "-0.03em",
                color: "var(--text-strong)",
                wordBreak: "break-word",
              }}
            >
              {value}
            </div>
          </div>
          {badge ? <div>{badge}</div> : null}
        </div>

        {caption ? (
          <div style={{ fontSize: 13, lineHeight: 1.65, color: "var(--text-secondary)" }}>{caption}</div>
        ) : null}

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 11,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              color: colors.accent,
              fontWeight: 700,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: colors.accent,
                boxShadow: `0 0 0 5px ${colors.glow}`,
              }}
            />
            {trendLabel(trend)}
          </span>
          <span style={{ fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.04em" }}>Console signal</span>
        </div>
      </div>
    </article>
  );
}

function resolveToneColor(tone: ConsoleTone, accent?: string) {
  if (accent) {
    return {
      accent,
      glow: hexToRgba(accent, 0.16),
      border: hexToRgba(accent, 0.30),
    };
  }

  switch (tone) {
    case "success":
      return { accent: "var(--green)", glow: "rgba(56, 217, 169, 0.16)", border: "rgba(56, 217, 169, 0.30)" };
    case "warning":
      return { accent: "var(--yellow)", glow: "rgba(251, 191, 36, 0.16)", border: "rgba(251, 191, 36, 0.30)" };
    case "danger":
      return { accent: "var(--red)", glow: "rgba(251, 113, 133, 0.16)", border: "rgba(251, 113, 133, 0.30)" };
    case "neutral":
      return { accent: "var(--text-muted)", glow: "rgba(120, 145, 178, 0.10)", border: "rgba(120, 145, 178, 0.16)" };
    case "info":
    default:
      return { accent: "var(--accent)", glow: "rgba(102, 168, 255, 0.16)", border: "rgba(102, 168, 255, 0.30)" };
  }
}

function trendLabel(trend: "up" | "down" | "flat") {
  switch (trend) {
    case "up":
      return "Elevated";
    case "down":
      return "Cooling";
    default:
      return "Stable";
  }
}

function hexToRgba(hex: string, alpha: number) {
  const normalized = hex.replace("#", "");
  if (normalized.length !== 6) return hex;
  const r = Number.parseInt(normalized.slice(0, 2), 16);
  const g = Number.parseInt(normalized.slice(2, 4), 16);
  const b = Number.parseInt(normalized.slice(4, 6), 16);
  if ([r, g, b].some((n) => Number.isNaN(n))) return hex;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
