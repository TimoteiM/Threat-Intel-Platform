"use client";

import React from "react";

export type ConsoleTone = "neutral" | "info" | "success" | "warning" | "danger";
export type ConsoleModuleVariant = "solid" | "glass" | "outline" | "dense";

interface ConsoleModuleProps {
  title?: React.ReactNode;
  eyebrow?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
  tone?: ConsoleTone;
  variant?: ConsoleModuleVariant;
  accent?: string;
  compact?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export default function ConsoleModule({
  title,
  eyebrow,
  description,
  actions,
  footer,
  children,
  tone = "info",
  variant = "solid",
  accent,
  compact = false,
  className,
  style,
}: ConsoleModuleProps) {
  const toneColor = resolveToneColor(tone, accent);
  const surface = resolveSurface(variant);
  const padding = compact ? 16 : 20;

  return (
    <section
      className={className}
      style={{
        position: "relative",
        overflow: "hidden",
        borderRadius: 22,
        border: `1px solid ${variant === "outline" ? toneColor.border : "var(--panel-divider-strong)"}`,
        background: surface.background,
        boxShadow: surface.shadow,
        ...style,
      }}
    >
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          background: `linear-gradient(180deg, ${toneColor.glow} 0%, transparent 28%)`,
          pointerEvents: "none",
        }}
      />
      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: "auto 0 0 0",
          height: 2,
          background: `linear-gradient(90deg, transparent, ${toneColor.accent}, transparent)`,
          opacity: 0.9,
          pointerEvents: "none",
        }}
      />

      {(title || eyebrow || description || actions) && (
        <header
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
            padding: `${padding}px ${padding}px ${compact ? 14 : 16}px`,
            borderBottom: "1px solid var(--panel-divider)",
          }}
        >
          <div style={{ minWidth: 0 }}>
            {eyebrow ? (
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.14em",
                  textTransform: "uppercase",
                  color: toneColor.eyebrow,
                  marginBottom: title ? 8 : 0,
                }}
              >
                {eyebrow}
              </div>
            ) : null}
            {title ? (
              <div
                style={{
                  fontFamily: "var(--font-display)",
                  fontSize: compact ? 20 : 24,
                  fontWeight: 700,
                  lineHeight: 1.15,
                  color: "var(--text-strong)",
                  letterSpacing: "-0.02em",
                }}
              >
                {title}
              </div>
            ) : null}
            {description ? (
              <div
                style={{
                  marginTop: title ? 8 : 0,
                  fontSize: 13,
                  lineHeight: 1.7,
                  color: "var(--text-secondary)",
                  maxWidth: 860,
                }}
              >
                {description}
              </div>
            ) : null}
          </div>
          {actions ? <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>{actions}</div> : null}
        </header>
      )}

      <div
        style={{
          position: "relative",
          zIndex: 1,
          padding: padding,
        }}
      >
        {children}
      </div>

      {footer ? (
        <footer
          style={{
            position: "relative",
            zIndex: 1,
            padding: `0 ${padding}px ${padding}px`,
          }}
        >
          <div style={{ borderTop: "1px solid var(--panel-divider)", paddingTop: 14 }}>{footer}</div>
        </footer>
      ) : null}
    </section>
  );
}

function resolveToneColor(tone: ConsoleTone, accent?: string) {
  if (accent) {
    return {
      accent,
      glow: hexToRgba(accent, 0.18),
      border: hexToRgba(accent, 0.28),
      eyebrow: "var(--text-dim)",
    };
  }

  switch (tone) {
    case "success":
      return { accent: "var(--green)", glow: "rgba(56, 217, 169, 0.12)", border: "rgba(56, 217, 169, 0.28)", eyebrow: "var(--tone-success-eyebrow)" };
    case "warning":
      return { accent: "var(--yellow)", glow: "rgba(251, 191, 36, 0.12)", border: "rgba(251, 191, 36, 0.28)", eyebrow: "var(--tone-warning-eyebrow)" };
    case "danger":
      return { accent: "var(--red)", glow: "rgba(251, 113, 133, 0.12)", border: "rgba(251, 113, 133, 0.28)", eyebrow: "var(--tone-danger-eyebrow)" };
    case "neutral":
      return { accent: "var(--text-muted)", glow: "rgba(120, 145, 178, 0.08)", border: "rgba(120, 145, 178, 0.18)", eyebrow: "var(--text-muted)" };
    case "info":
    default:
      return { accent: "var(--accent)", glow: "rgba(102, 168, 255, 0.14)", border: "rgba(102, 168, 255, 0.28)", eyebrow: "var(--tone-info-eyebrow)" };
  }
}

function resolveSurface(variant: ConsoleModuleVariant) {
  switch (variant) {
    case "glass":
      return {
        background: "var(--panel-glass-bg)",
        shadow: "var(--panel-shadow-glass)",
      };
    case "outline":
      return {
        background: "var(--panel-outline-bg)",
        shadow: "none",
      };
    case "dense":
      return {
        background: "var(--panel-dense-bg)",
        shadow: "var(--panel-shadow-soft)",
      };
    case "solid":
    default:
      return {
        background: "var(--panel-solid-bg)",
        shadow: "var(--panel-shadow-module)",
      };
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
