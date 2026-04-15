"use client";

import React from "react";
import type { ConsoleTone } from "@/components/ui/ConsoleModule";

interface StatusPillProps {
  children: React.ReactNode;
  tone?: ConsoleTone;
  size?: "sm" | "md";
  outline?: boolean;
  mono?: boolean;
  icon?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export default function StatusPill({
  children,
  tone = "neutral",
  size = "md",
  outline = false,
  mono = false,
  icon,
  className,
  style,
}: StatusPillProps) {
  const colors = toneColors(tone);
  const compact = size === "sm";

  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        borderRadius: 999,
        padding: compact ? "4px 9px" : "6px 11px",
        border: `1px solid ${outline ? colors.border : colors.borderStrong}`,
        background: outline ? "transparent" : colors.background,
        color: colors.foreground,
        fontSize: compact ? 10 : 11,
        fontWeight: 700,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        lineHeight: 1,
        whiteSpace: "nowrap",
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        boxShadow: outline ? "none" : "0 10px 24px rgba(3, 8, 20, 0.18)",
        ...style,
      }}
    >
      {icon ? <span style={{ display: "inline-flex", alignItems: "center" }}>{icon}</span> : null}
      <span>{children}</span>
    </span>
  );
}

function toneColors(tone: ConsoleTone) {
  switch (tone) {
    case "success":
      return {
        foreground: "#9bf0d8",
        background: "rgba(56, 217, 169, 0.12)",
        border: "rgba(56, 217, 169, 0.34)",
        borderStrong: "rgba(56, 217, 169, 0.42)",
      };
    case "warning":
      return {
        foreground: "#fde68a",
        background: "rgba(251, 191, 36, 0.12)",
        border: "rgba(251, 191, 36, 0.34)",
        borderStrong: "rgba(251, 191, 36, 0.42)",
      };
    case "danger":
      return {
        foreground: "#fda4af",
        background: "rgba(251, 113, 133, 0.12)",
        border: "rgba(251, 113, 133, 0.34)",
        borderStrong: "rgba(251, 113, 133, 0.42)",
      };
    case "info":
      return {
        foreground: "#bfdbfe",
        background: "rgba(102, 168, 255, 0.12)",
        border: "rgba(102, 168, 255, 0.34)",
        borderStrong: "rgba(102, 168, 255, 0.42)",
      };
    case "neutral":
    default:
      return {
        foreground: "var(--text-secondary)",
        background: "rgba(120, 145, 178, 0.08)",
        border: "rgba(120, 145, 178, 0.24)",
        borderStrong: "rgba(120, 145, 178, 0.34)",
      };
  }
}
