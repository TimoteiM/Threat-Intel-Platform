"use client";

/**
 * A content section.
 *
 * This was the application's default container: a 22px-radius panel with a
 * gradient wash, a glowing accent bar, a heavy shadow and a 24px display title.
 * Eighteen files render it, several of them nested two deep, which is most of
 * why the product read as boxes-inside-boxes with no hierarchy.
 *
 * It is now a heading plus its content. `variant="outline"` and `"solid"` keep
 * a light border for sections that really are distinct objects; `"glass"` and
 * `"dense"` are borderless, separated by space alone. The API is unchanged so
 * every existing call site keeps working.
 */

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
  // Only the bordered variants pay for a box. The rest are separated by space,
  // which is what stops sections nesting into a stack of frames.
  const bordered = variant === "solid" || variant === "outline";
  const padding = bordered ? (compact ? "var(--space-3)" : "var(--space-4)") : 0;

  return (
    <section
      className={className}
      style={{
        borderRadius: bordered ? "var(--shell-radius-lg)" : 0,
        border: bordered ? "1px solid var(--panel-divider-strong)" : "none",
        background: bordered ? "var(--shell-surface)" : "transparent",
        padding,
        display: "grid",
        // An `auto` grid track is sized by its widest item's max-content, so a
        // single unwrappable string — a 255-character alert title — stretches
        // the column past the container and every sibling row with it.
        // `minmax(0, 1fr)` caps the track at the container width.
        gridTemplateColumns: "minmax(0, 1fr)",
        gap: "var(--space-3)",
        minWidth: 0,
        ...style,
      }}
    >
      {(title || eyebrow || description || actions) && (
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: "var(--space-3)",
            flexWrap: "wrap",
          }}
        >
          <div style={{ minWidth: 0 }}>
            {eyebrow ? (
              <div
                style={{
                  fontSize: "var(--font-micro)",
                  fontWeight: 700,
                  letterSpacing: "0.1em",
                  textTransform: "uppercase",
                  color: eyebrowColor(tone, accent),
                  marginBottom: 2,
                }}
              >
                {eyebrow}
              </div>
            ) : null}
            {title ? (
              <h2
                style={{
                  fontSize: "var(--font-section-title)",
                  fontWeight: 700,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  lineHeight: 1.3,
                  color: "var(--text-secondary)",
                  margin: 0,
                }}
              >
                {title}
              </h2>
            ) : null}
            {description ? (
              <div
                style={{
                  marginTop: 2,
                  fontSize: "var(--font-micro)",
                  lineHeight: 1.6,
                  color: "var(--text-muted)",
                  maxWidth: "76ch",
                }}
              >
                {description}
              </div>
            ) : null}
          </div>
          {actions ? (
            <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", flexWrap: "wrap" }}>
              {actions}
            </div>
          ) : null}
        </div>
      )}

      <div style={{ minWidth: 0 }}>{children}</div>

      {footer ? (
        <div style={{ borderTop: "1px solid var(--panel-divider-soft)", paddingTop: "var(--space-3)" }}>{footer}</div>
      ) : null}
    </section>
  );
}

function eyebrowColor(tone: ConsoleTone, accent?: string) {
  if (accent) return accent;
  switch (tone) {
    case "success":
      return "var(--tone-success-eyebrow)";
    case "warning":
      return "var(--tone-warning-eyebrow)";
    case "danger":
      return "var(--tone-danger-eyebrow)";
    case "neutral":
      return "var(--text-muted)";
    default:
      return "var(--tone-info-eyebrow)";
  }
}
