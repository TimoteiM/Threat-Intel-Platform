"use client";

import React from "react";
import { AnalystReport } from "@/lib/types";
import { SEVERITY_COLORS } from "@/lib/constants";
import Badge from "@/components/shared/Badge";

interface Props {
  report: AnalystReport;
}

export default function FindingsTab({ report }: Props) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const keyEvidence = Array.isArray(report?.key_evidence) ? report.key_evidence : [];
  const contradicting = Array.isArray(report?.contradicting_evidence) ? report.contradicting_evidence : [];

  return (
    <div>
      <Section title="ANALYST FINDINGS">
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {findings.length === 0 ? (
            <div style={{ fontSize: 12, color: "var(--text-dim)", padding: 20 }}>
              No findings generated.
            </div>
          ) : (
            findings.map((f: any, i: number) => {
              const color = SEVERITY_COLORS[f?.severity] || SEVERITY_COLORS.info;
              return (
                <div
                  key={f?.id || i}
                  style={{
                    padding: "16px 20px",
                    background: "var(--bg-input)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius)",
                    borderLeft: `3px solid ${color}`,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                    <Badge label={f?.severity || "info"} color={color} />
                    <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>
                      {f?.title || "Untitled finding"}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                    {f?.description || ""}
                  </div>
                  {f?.ttp && (
                    <div style={{ fontSize: 10, color: "var(--purple)", marginTop: 8 }}>
                      TTP: {f.ttp}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </Section>

      <Section title="KEY EVIDENCE">
        <RefList items={keyEvidence} color="var(--green)" />
      </Section>

      {contradicting.length > 0 && (
        <Section title="CONTRADICTING EVIDENCE">
          <RefList items={contradicting} color="var(--yellow)" />
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

function RefList({ items, color }: { items: any[]; color: string }) {
  if (!items || items.length === 0) {
    return <div style={{ fontSize: 12, color: "var(--text-dim)" }}>None</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {items.map((item: any, i: number) => (
        <div
          key={i}
          style={{
            padding: "6px 12px",
            background: "var(--bg-input)",
            borderRadius: "var(--radius-sm)",
            fontSize: 12,
            color,
            fontFamily: "var(--font-mono)",
          }}
        >
          ▸ {typeof item === "string" ? item : JSON.stringify(item)}
        </div>
      ))}
    </div>
  );
}