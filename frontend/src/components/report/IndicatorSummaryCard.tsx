"use client";

/**
 * "What the sources found" — the factual counterpart to the AI narrative.
 *
 * The AI reads the alert text alone and runs in parallel with the collectors, so
 * it can name a hash but never say what VirusTotal thought of it. These lines
 * come from the collector findings themselves: detections, the file the hash
 * refers to, whether it is signed, sandbox verdicts, feed listings.
 */

import React from "react";

import type { AlertIndicatorSummary } from "@/lib/types";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
  not_investigated: "#64748b",
};

export default function IndicatorSummaryCard({ summary }: { summary?: AlertIndicatorSummary | null }) {
  if (!summary?.indicators?.length) return null;

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div
        style={{
          fontSize: 12.5,
          lineHeight: 1.65,
          color: "var(--text)",
          fontFamily: "var(--font-sans)",
          padding: "10px 12px",
          borderRadius: 10,
          background: "var(--bg-input)",
          border: "1px solid var(--border)",
        }}
      >
        {summary.headline}
      </div>

      <div style={{ display: "grid", gap: 6 }}>
        {summary.indicators.map((indicator, i) => {
          const color = VERDICT_COLORS[String(indicator.classification || "").toLowerCase()] || "#94a3b8";
          return (
            <div
              key={`${indicator.value}:${i}`}
              style={{
                display: "flex",
                gap: 10,
                alignItems: "baseline",
                padding: "7px 10px",
                borderRadius: 8,
                borderLeft: `3px solid ${color}`,
                background: "var(--bg-input)",
                border: "1px solid var(--border)",
                borderLeftWidth: 3,
                borderLeftColor: color,
              }}
            >
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 800,
                  letterSpacing: "0.05em",
                  textTransform: "uppercase",
                  color,
                  fontFamily: "var(--font-sans)",
                  minWidth: 62,
                  flexShrink: 0,
                }}
              >
                {indicator.classification || "—"}
              </span>
              <span
                style={{
                  fontSize: 11.5,
                  lineHeight: 1.6,
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-sans)",
                  overflowWrap: "anywhere",
                }}
              >
                {indicator.line}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
