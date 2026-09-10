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
        foreground: "#86e6ac",
        background: "rgba(46, 204, 113, 0.12)",
        border: "rgba(46, 204, 113, 0.34)",
        borderStrong: "rgba(46, 204, 113, 0.42)",
      };
    case "warning":
      return {
        foreground: "#f7c48d",
        background: "rgba(240, 160, 80, 0.12)",
        border: "rgba(240, 160, 80, 0.34)",
        borderStrong: "rgba(240, 160, 80, 0.42)",
      };
    case "danger":
      return {
        foreground: "#f5a48f",
        background: "rgba(240, 112, 80, 0.12)",
        border: "rgba(240, 112, 80, 0.34)",
        borderStrong: "rgba(240, 112, 80, 0.42)",
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
        foreground: "#c3cdff",
        background: "rgba(79, 110, 247, 0.14)",
        border: "rgba(79, 110, 247, 0.38)",
        borderStrong: "rgba(79, 110, 247, 0.48)",
      };
    case "neutral":
    default:
      return {
        foreground: "var(--text-secondary)",
        background: "rgba(126, 134, 170, 0.08)",
        border: "rgba(126, 134, 170, 0.24)",
        borderStrong: "rgba(126, 134, 170, 0.34)",
      };
  }
}
