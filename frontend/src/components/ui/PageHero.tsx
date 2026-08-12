"use client";

/**
 * The page header.
 *
 * This was a 26px-radius panel with two radial gradients, a hero shadow and a
 * 38px display title — roughly a fifth of a laptop viewport spent before the
 * first piece of information. It is now a title, a line of context and the
 * page's actions over a divider, and the space goes to the content.
 *
 * The props are unchanged so every page that already renders one keeps working;
 * `stats` now lays out as an inline metric strip rather than a grid of cards.
 */

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
  return (
    <header className={className} style={{ display: "grid", gap: "var(--space-3)", ...style }}>
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "var(--space-4)",
          flexWrap: "wrap",
          paddingBottom: "var(--space-3)",
          borderBottom: "1px solid var(--panel-divider)",
        }}
      >
        <div style={{ minWidth: 0, flex: "1 1 420px" }}>
          {eyebrow ? (
            <div
              style={{
                fontSize: "var(--font-micro)",
                fontWeight: 700,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                color: eyebrowColor(tone, accent),
                marginBottom: 4,
              }}
            >
              {eyebrow}
            </div>
          ) : null}

          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
            <h1
              style={{
                fontFamily: "var(--font-display)",
                fontSize: "var(--font-page-title)",
                lineHeight: 1.2,
                letterSpacing: "-0.01em",
                fontWeight: 700,
                color: "var(--text-strong)",
                margin: 0,
                overflowWrap: "anywhere",
                minWidth: 0,
              }}
            >
              {title}
            </h1>
            {status}
          </div>

          {description ? (
            <div
              style={{
                marginTop: 4,
                maxWidth: "76ch",
                fontSize: "var(--font-meta)",
                lineHeight: 1.6,
                color: "var(--text-dim)",
              }}
            >
              {description}
            </div>
          ) : null}

          {badges ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--space-2)", marginTop: "var(--space-2)" }}>
              {badges}
            </div>
          ) : null}
        </div>

        {actions ? (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--space-2)", flex: "0 0 auto" }}>{actions}</div>
        ) : null}
      </div>

      {stats ? (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "var(--space-5) var(--space-6)",
            paddingBottom: "var(--space-3)",
            borderBottom: "1px solid var(--panel-divider-soft)",
          }}
        >
          {stats}
        </div>
      ) : null}
    </header>
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
