"use client";

import React from "react";
import { CollectedEvidence } from "@/lib/types";
import { SEVERITY_COLORS } from "@/lib/constants";

interface Props {
  evidence: CollectedEvidence;
}

export default function SignalsTab({ evidence }: Props) {
  const signals = Array.isArray(evidence?.signals) ? evidence.signals : [];
  const dataGaps = Array.isArray(evidence?.data_gaps) ? evidence.data_gaps : [];

  return (
    <div>
      <Section title="SIGNALS (investigative clues — not conclusions)">
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {signals.length === 0 ? (
            <div style={{ fontSize: 12, color: "var(--text-dim)", padding: 20 }}>
              No signals detected.
            </div>
          ) : (
            signals.map((sig: any, i: number) => {
              const color = SEVERITY_COLORS[sig?.severity] || SEVERITY_COLORS.info;
              return (
                <div
                  key={sig?.id || i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 12px",
                    background: "var(--bg-input)",
                    borderRadius: "var(--radius-sm)",
                    borderLeft: `3px solid ${color}`,
                  }}
                >
                  <span style={{
                    fontSize: 9, fontWeight: 700, color,
                    letterSpacing: "0.1em", minWidth: 50,
                    textTransform: "uppercase",
                  }}>
                    {sig?.severity || "info"}
                  </span>
                  <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                    {sig?.description || "Unknown signal"}
                  </span>
                  <span style={{
                    fontSize: 10, color: "var(--text-muted)",
                    marginLeft: "auto", whiteSpace: "nowrap",
                  }}>
                    {sig?.category || ""}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </Section>

      {dataGaps.length > 0 && (
        <Section title="DATA GAPS">
          {dataGaps.map((gap: any, i: number) => (
            <div
              key={gap?.id || i}
              style={{
                padding: "10px 14px",
                background: "rgba(239,68,68,0.04)",
                border: "1px solid rgba(239,68,68,0.12)",
                borderRadius: "var(--radius-sm)",
                marginBottom: 8,
              }}
            >
              <div style={{ fontSize: 12, color: "var(--red)", fontWeight: 600 }}>
                {gap?.description || "Unknown gap"}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
                Impact: {gap?.impact || "Unknown"}
              </div>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{
        fontSize: 11, fontWeight: 700, color: "var(--accent)",
        letterSpacing: "0.08em", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid var(--border)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}