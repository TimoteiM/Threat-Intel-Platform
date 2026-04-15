"use client";

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
    <section className={className} style={{ display: "grid", gap: compact ? 12 : 16, ...style }}>
      {title || eyebrow || description ? (
        <div style={{ display: "grid", gap: 8 }}>
          {eyebrow ? (
            <div style={eyebrowStyle}>
              {eyebrow}
            </div>
          ) : null}
          {title ? <div style={titleStyle}>{title}</div> : null}
          {description ? <div style={descriptionStyle}>{description}</div> : null}
        </div>
      ) : null}

      <div
        style={{
          display: "grid",
          gap: 12,
          gridTemplateColumns: columns ? `repeat(${columns}, minmax(0, 1fr))` : "repeat(auto-fit, minmax(220px, 1fr))",
        }}
      >
        {items.map((item, index) => {
          const toneColor = toneColorFor(item.tone || "neutral");
          const value = normalizeValue(item.value);
          return (
            <div
              key={`${String(item.label)}-${index}`}
              style={{
                gridColumn: item.span ? `span ${item.span}` : "auto",
                borderRadius: 18,
                border: "1px solid rgba(120, 145, 178, 0.16)",
                background: "linear-gradient(180deg, rgba(16, 26, 44, 0.92), rgba(11, 17, 29, 0.98))",
                padding: compact ? 14 : 16,
                boxShadow: "0 14px 30px rgba(3, 8, 20, 0.18)",
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 800,
                  letterSpacing: "0.14em",
                  textTransform: "uppercase",
                  color: toneColor.label,
                  marginBottom: 10,
                }}
              >
                {item.label}
              </div>
              <div
                style={{
                  fontFamily: item.mono ? "var(--font-mono)" : "var(--font-display)",
                  fontSize: compact ? 14 : 15,
                  lineHeight: 1.6,
                  color: "var(--text-strong)",
                  wordBreak: "break-word",
                  whiteSpace: valueNeedsWrap(value) ? "pre-wrap" : "normal",
                }}
              >
                {value}
              </div>
              {item.hint ? <div style={{ marginTop: 8, fontSize: 12, lineHeight: 1.6, color: "var(--text-muted)" }}>{item.hint}</div> : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function normalizeValue(value: React.ReactNode) {
  if (value === null || value === undefined || value === "") return "-";
  if (React.isValidElement(value)) return value;
  if (Array.isArray(value)) {
    if (!value.length) return "-";
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

function toneColorFor(tone: ConsoleTone) {
  switch (tone) {
    case "success":
      return { label: "#9bf0d8" };
    case "warning":
      return { label: "#fde68a" };
    case "danger":
      return { label: "#fda4af" };
    case "info":
      return { label: "#bfdbfe" };
    case "neutral":
    default:
      return { label: "var(--text-dim)" };
  }
}

const eyebrowStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.16em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
};

const titleStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: 20,
  fontWeight: 700,
  color: "var(--text-strong)",
  letterSpacing: "-0.02em",
};

const descriptionStyle: React.CSSProperties = {
  fontSize: 13,
  lineHeight: 1.7,
  color: "var(--text-secondary)",
};
