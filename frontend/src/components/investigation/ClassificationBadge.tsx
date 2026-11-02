"use client";

import React from "react";
import { Classification, Confidence } from "@/lib/types";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

interface Props {
  classification: Classification;
  confidence: Confidence;
  riskScore?: number;
}

export default function ClassificationBadge({ classification, confidence, riskScore }: Props) {
  const config = CLASSIFICATION_CONFIG[classification] || CLASSIFICATION_CONFIG.inconclusive;
  const pct = riskScore != null ? Math.max(0, Math.min(100, riskScore)) : null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 20,
        padding: "18px 22px",
        background: config.bg,
        border: `1px solid ${config.color}30`,
        borderLeft: `3px solid ${config.color}`,
        borderRadius: "var(--shell-radius-lg)",
        marginBottom: 24,
      }}
      className="animate-in"
    >
      <div
        style={{
          width: 56,
          height: 56,
          flexShrink: 0,
          borderRadius: "var(--shell-radius-md)",
          background: `${config.color}14`,
          border: `1px solid ${config.color}45`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 20,
          fontWeight: 700,
          color: config.color,
          fontFamily: "var(--font-mono)",
          letterSpacing: "-0.02em",
        }}
      >
        {riskScore ?? "?"}
      </div>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          style={{
            fontSize: 16,
            fontWeight: 700,
            color: config.color,
            letterSpacing: "0.03em",
            fontFamily: "var(--font-sans)",
          }}
        >
          {config.label}
        </div>
        <div style={{
          fontSize: 12, color: "var(--text-dim)", marginTop: 3,
          fontFamily: "var(--font-sans)",
        }}>
          Confidence: <span style={{ color: "var(--text)", fontWeight: 500 }}>{confidence}</span>
          {riskScore != null && <> · Risk score {riskScore}/100</>}
        </div>
        {pct != null && (
          <div
            aria-hidden="true"
            style={{
              marginTop: 8,
              height: 3,
              borderRadius: 999,
              background: "rgba(126, 134, 170, 0.16)",
              overflow: "hidden",
              maxWidth: 220,
            }}
          >
            <div
              style={{
                width: `${pct}%`,
                height: "100%",
                background: config.color,
                borderRadius: 999,
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
