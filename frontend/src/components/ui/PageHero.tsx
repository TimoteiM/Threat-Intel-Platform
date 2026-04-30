"use client";

import React from "react";
import type { ConsoleTone } from "@/components/ui/ConsoleModule";

interface PageHeroProps {
  eyebrow?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  status?: React.ReactNode;
  badges?: React.ReactNode;
  stats?: React.ReactNode;
  actions?: React.ReactNode;
  tone?: ConsoleTone;
  accent?: string;
  style?: React.CSSProperties;
  className?: string;
}

export default function PageHero({
  eyebrow,
  title,
  description,
  status,
  badges,
  stats,
  actions,
  tone = "info",
  accent,
  style,
  className,
}: PageHeroProps) {
  const colors = resolveToneColor(tone, accent);

  return (
    <section
      className={className}
      style={{
        position: "relative",
        overflow: "hidden",
        borderRadius: 26,
        border: `1px solid ${colors.border}`,
        background: "var(--panel-card-bg)",
        boxShadow: "var(--panel-shadow-hero)",
        padding: 24,
        ...style,
      }}
    >
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(900px circle at 6% 0%, rgba(102, 168, 255, 0.18), transparent 40%), radial-gradient(700px circle at 92% 8%, rgba(251, 191, 36, 0.08), transparent 34%)",
          pointerEvents: "none",
        }}
      />
      <div style={{ position: "relative", zIndex: 1, display: "grid", gap: 22 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 18, alignItems: "flex-start", flexWrap: "wrap" }}>
          <div style={{ minWidth: 0, flex: "1 1 460px" }}>
            {eyebrow ? (
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 800,
                  letterSpacing: "0.18em",
                  textTransform: "uppercase",
                  color: colors.eyebrow,
                  marginBottom: 10,
                }}
              >
                {eyebrow}
              </div>
            ) : null}
            <div
              style={{
                fontFamily: "var(--font-display)",
                fontSize: 38,
                lineHeight: 1.06,
                letterSpacing: "-0.04em",
                fontWeight: 700,
                color: "var(--text-strong)",
                wordBreak: "break-word",
              }}
            >
              {title}
            </div>
            {description ? (
              <div
                style={{
                  marginTop: 14,
                  maxWidth: 900,
                  fontSize: 15,
                  lineHeight: 1.75,
                  color: "var(--text-secondary)",
                }}
              >
                {description}
              </div>
            ) : null}
          </div>

          {status || actions || badges ? (
            <div style={{ display: "grid", justifyItems: "end", gap: 10, flex: "0 0 auto" }}>
              {status ? <div>{status}</div> : null}
              {badges ? <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "flex-end", gap: 8 }}>{badges}</div> : null}
              {actions ? <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "flex-end", gap: 10 }}>{actions}</div> : null}
            </div>
          ) : null}
        </div>

        {stats ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 14 }}>{stats}</div>
        ) : null}
      </div>
    </section>
  );
}

function resolveToneColor(tone: ConsoleTone, accent?: string) {
  if (accent) {
    return {
      eyebrow: "var(--text-dim)",
      border: hexToRgba(accent, 0.24),
    };
  }

  switch (tone) {
    case "success":
      return { eyebrow: "var(--tone-success-eyebrow)", border: "rgba(56, 217, 169, 0.24)" };
    case "warning":
      return { eyebrow: "var(--tone-warning-eyebrow)", border: "rgba(251, 191, 36, 0.24)" };
    case "danger":
      return { eyebrow: "var(--tone-danger-eyebrow)", border: "rgba(251, 113, 133, 0.24)" };
    case "neutral":
      return { eyebrow: "var(--text-muted)", border: "rgba(120, 145, 178, 0.16)" };
    case "info":
    default:
      return { eyebrow: "var(--tone-info-eyebrow)", border: "rgba(102, 168, 255, 0.26)" };
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
