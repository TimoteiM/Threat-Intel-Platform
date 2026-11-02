"use client";

/**
 * Metadata as aligned label/value pairs.
 *
 * This was one bordered, shadowed card per field — the literal "one card per
 * metadata field" pattern. Twelve fields meant twelve boxes, which made a
 * record id look as important as a verdict.
 *
 * Now a definition list: labels small and muted, values readable, alignment
 * doing the work the borders were doing. Same props, so call sites are
 * untouched; `tone` now colours the value rather than framing it.
 */

import React from "react";
import type { ConsoleTone } from "@/components/ui/ConsoleModule";

export interface MetadataItem {
  label: React.ReactNode;
  value?: React.ReactNode;
  hint?: React.ReactNode;
  tone?: ConsoleTone;
  span?: number;
  mono?: boolean;
}

interface MetadataGridProps {
  items: MetadataItem[];
  title?: React.ReactNode;
  eyebrow?: React.ReactNode;
  description?: React.ReactNode;
  columns?: number;
  compact?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export default function MetadataGrid({
  items,
  title,
  eyebrow,
  description,
  columns,
  compact = false,
  className,
  style,
}: MetadataGridProps) {
  return (
    <section className={className} style={{ display: "grid", gap: "var(--space-3)", ...style }}>
      {title || eyebrow || description ? (
        <div style={{ display: "grid", gap: 2 }}>
          {eyebrow ? (
            <div
              style={{
                fontSize: "var(--font-micro)",
                fontWeight: 700,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                color: "var(--text-muted)",
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
                color: "var(--text-secondary)",
                margin: 0,
              }}
            >
              {title}
            </h2>
          ) : null}
          {description ? (
            <div style={{ fontSize: "var(--font-micro)", lineHeight: 1.6, color: "var(--text-muted)", maxWidth: "76ch" }}>
              {description}
            </div>
          ) : null}
        </div>
      ) : null}

      <dl
        className="ds-meta"
        style={{
          gridTemplateColumns: columns
            ? `repeat(${columns}, minmax(0, 1fr))`
            : `repeat(auto-fit, minmax(${compact ? 160 : 200}px, 1fr))`,
        }}
      >
        {items.map((item, index) => {
          const value = normalizeValue(item.value);
          return (
            <div
              key={`${String(item.label)}-${index}`}
              style={{ gridColumn: item.span ? `span ${item.span}` : "auto", minWidth: 0 }}
            >
              <dt className="ds-meta__label">{item.label}</dt>
              <dd
                className="ds-meta__value"
                style={{
                  fontFamily: item.mono ? "var(--font-mono)" : "var(--font-sans)",
                  color: valueColor(item.tone),
                  whiteSpace: valueNeedsWrap(value) ? "pre-wrap" : "normal",
                }}
              >
                {value}
              </dd>
              {item.hint ? (
                <div style={{ marginTop: 2, fontSize: "var(--font-micro)", color: "var(--text-muted)" }}>{item.hint}</div>
              ) : null}
            </div>
          );
        })}
      </dl>
    </section>
  );
}

function normalizeValue(value: React.ReactNode) {
  if (value === null || value === undefined || value === "") return "—";
  if (React.isValidElement(value)) return value;
  if (Array.isArray(value)) {
    if (!value.length) return "—";
    return value.map((item) => (typeof item === "string" ? item : String(item))).join(", ");
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function valueNeedsWrap(value: React.ReactNode) {
  return typeof value === "string" && value.length > 80;
}

function valueColor(tone?: ConsoleTone) {
  switch (tone) {
    case "success":
      return "var(--status-success)";
    case "warning":
      return "var(--status-warning)";
    case "danger":
      return "var(--status-danger)";
    default:
      return "var(--text)";
  }
}
