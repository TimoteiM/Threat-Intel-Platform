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
  // Derived on read by the API from each collector's own `meta.status`, so it
  // is present on historical verdicts too. On 2026-09-15, nine of eighteen
  // sources were unavailable and the page said nothing.
  const coverage: any = (evidence as any)?.source_coverage ?? null;
  const unavailable: any[] = Array.isArray(coverage?.sources)
    ? coverage.sources.filter((s: any) => s?.state === "failed")
    : [];
  const notAsked: string[] = Array.isArray(coverage?.not_attempted_sources)
    ? coverage.not_attempted_sources
    : [];

  return (
    <div>
      {coverage && (
        <Section title="Source coverage for this verdict">
          <div
            style={{
              padding: "10px 14px",
              background:
                unavailable.length > 0
                  ? "rgba(240,112,80,0.04)"
                  : "rgba(80,200,140,0.04)",
              border:
                unavailable.length > 0
                  ? "1px solid rgba(240,112,80,0.12)"
                  : "1px solid rgba(80,200,140,0.12)",
              borderRadius: "var(--radius-sm)",
              marginBottom: 8,
            }}
          >
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: unavailable.length > 0 ? "var(--red)" : "var(--text)",
              }}
            >
              {coverage.headline || "Source coverage unknown"}
            </div>
            {unavailable.length > 0 && (
              <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                {unavailable.map((s: any, i: number) => (
                  <div key={s?.source || i} style={{ fontSize: 11 }}>
                    <span style={{ color: "var(--red)", fontWeight: 600 }}>
                      {s?.source}
                    </span>
                    <span style={{ color: "var(--text-dim)" }}>
                      {" — "}
                      {s?.absence?.reason || s?.detail || "did not answer"}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {notAsked.length > 0 && (
              <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                Not asked (outside this run&apos;s selection, so not a gap):{" "}
                {notAsked.join(", ")}
              </div>
            )}
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
              A source that did not answer is not a source that found nothing.
              An empty result from an unavailable source carries no information
              about this observable.
            </div>
          </div>
        </Section>
      )}
      <Section title="Signals (investigative clues, not conclusions)">
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
                    fontSize: 10, fontWeight: 600, color,
                    letterSpacing: "0.02em", minWidth: 50,
                    textTransform: "uppercase",
                    fontFamily: "var(--font-sans)",
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
        <Section title="Data Gaps">
          {dataGaps.map((gap: any, i: number) => (
            <div
              key={gap?.id || i}
              style={{
                padding: "10px 14px",
                background: "rgba(240,112,80,0.04)",
                border: "1px solid rgba(240,112,80,0.12)",
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
        fontSize: 13, fontWeight: 600, color: "var(--accent)",
        letterSpacing: "0.01em", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-sans)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}