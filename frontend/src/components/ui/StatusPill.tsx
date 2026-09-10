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
        gap: 6,
        // A drop shadow on a 20px pill is noise at any density, and there are
        // often four of them in a row.
        borderRadius: "var(--shell-radius-xs)",
        padding: compact ? "2px 7px" : "3px 8px",
        border: `1px solid ${outline ? colors.border : colors.borderStrong}`,
        background: outline ? "transparent" : colors.background,
        color: colors.foreground,
        fontSize: compact ? 10 : "var(--font-micro)",
        fontWeight: 700,
        letterSpacing: "0.04em",
        lineHeight: 1.5,
        whiteSpace: "nowrap",
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
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
        foreground: "#8ff0d0",
        background: "rgba(43, 212, 160, 0.12)",
        border: "rgba(43, 212, 160, 0.34)",
        borderStrong: "rgba(43, 212, 160, 0.42)",
      };
    case "warning":
      return {
        foreground: "#ffcf8a",
        background: "rgba(242, 169, 60, 0.12)",
        border: "rgba(242, 169, 60, 0.34)",
        borderStrong: "rgba(242, 169, 60, 0.42)",
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
        foreground: "#a9cbff",
        background: "rgba(91, 157, 255, 0.12)",
        border: "rgba(91, 157, 255, 0.34)",
        borderStrong: "rgba(91, 157, 255, 0.42)",
      };
    // The one tone that borrows the signature accent rather than a status
    // colour — for "this is the brand-relevant thing happening now" states
    // (an active run, a reused verdict), kept apart from info/success/etc.
    case "accent":
      return {
        foreground: "#d5c9ff",
        background: "rgba(139, 123, 255, 0.14)",
        border: "rgba(139, 123, 255, 0.38)",
        borderStrong: "rgba(139, 123, 255, 0.48)",
      };
    case "neutral":
    default:
      return {
        foreground: "var(--text-secondary)",
        background: "rgba(150, 145, 190, 0.08)",
        border: "rgba(150, 145, 190, 0.24)",
        borderStrong: "rgba(150, 145, 190, 0.34)",
      };
  }
}
