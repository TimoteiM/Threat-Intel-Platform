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

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 16,
        padding: "20px 24px",
        background: config.bg,
        border: `1px solid ${config.color}33`,
        borderRadius: "var(--radius-lg)",
        marginBottom: 24,
      }}
      className="animate-in"
    >
      <div
        style={{
          width: 60,
          height: 60,
          borderRadius: "var(--radius-lg)",
          background: `${config.color}12`,
          border: `2px solid ${config.color}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 22,
          fontWeight: 800,
          color: config.color,
          fontFamily: "var(--font-mono)",
        }}
      >
        {riskScore ?? "?"}
      </div>
      <div>
        <div
          style={{
            fontSize: 18,
            fontWeight: 800,
            color: config.color,
            letterSpacing: "0.1em",
            fontFamily: "var(--font-mono)",
          }}
        >
          {config.label}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
          Confidence: <span style={{ color: "var(--text)" }}>{confidence}</span>
          {riskScore != null && <> · Risk Score: {riskScore}/100</>}
        </div>
      </div>
    </div>
  );
}
