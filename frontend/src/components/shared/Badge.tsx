"use client";

import React from "react";

interface BadgeProps {
  label: string;
  color: string;
  bg?: string;
  size?: "sm" | "md";
}

export default function Badge({ label, color, bg, size = "sm" }: BadgeProps) {
  const padding = size === "sm" ? "2px 8px" : "4px 12px";
  const fontSize = size === "sm" ? 9 : 11;

  return (
    <span
      style={{
        fontSize,
        fontWeight: 700,
        padding,
        background: bg || `${color}15`,
        color,
        borderRadius: "var(--radius-sm)",
        letterSpacing: "0.1em",
        textTransform: "uppercase" as const,
        fontFamily: "var(--font-mono)",
        display: "inline-block",
      }}
    >
      {label}
    </span>
  );
}
