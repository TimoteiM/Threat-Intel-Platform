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

  // Build ATT&CK coverage from findings
  const tacticMap: Record<string, { id: string; name: string; finding: string }[]> = {};
  for (const f of findings) {
    if (f?.ttp && f?.ttp_tactic) {
      if (!tacticMap[f.ttp_tactic]) tacticMap[f.ttp_tactic] = [];
      tacticMap[f.ttp_tactic].push({
        id: f.ttp,
        name: f.ttp_name || f.ttp,
        finding: f.title || f.id,
      });
    }
  }

  return (
    <div>
      <Section title="Analyst Findings">
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
                    <div style={{
                      display: "flex", alignItems: "center", gap: 8,
                      marginTop: 10, flexWrap: "wrap",
                    }}>
                      {f.ttp_url ? (
                        <a
                          href={f.ttp_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            fontSize: 11, fontWeight: 600,
                            color: "#a78bfa",
                            textDecoration: "none",
                            padding: "3px 8px",
                            background: "rgba(167,139,250,0.10)",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid rgba(167,139,250,0.25)",
                            fontFamily: "var(--font-mono)",
                          }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(167,139,250,0.20)"; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(167,139,250,0.10)"; }}
                        >
                          {f.ttp}
                        </a>
                      ) : (
                        <span style={{
                          fontSize: 11, fontWeight: 600,
                          color: "#a78bfa",
                          padding: "3px 8px",
                          background: "rgba(167,139,250,0.10)",
                          borderRadius: "var(--radius-sm)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {f.ttp}
                        </span>
                      )}
                      {f.ttp_name && (
                        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                          {f.ttp_name}
                        </span>
                      )}
                      {f.ttp_tactic && (
                        <span style={{
                          fontSize: 9, fontWeight: 600,
                          color: "var(--text-muted)",
                          padding: "2px 6px",
                          background: "var(--bg-elevated)",
                          borderRadius: "var(--radius-sm)",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          fontFamily: "var(--font-sans)",
                        }}>
                          {f.ttp_tactic}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </Section>

      <Section title="Key Evidence">
        <RefList items={keyEvidence} color="var(--green)" />
      </Section>

      {contradicting.length > 0 && (
        <Section title="Contradicting Evidence">
          <RefList items={contradicting} color="var(--yellow)" />
        </Section>
      )}

      {/* ATT&CK Coverage */}
      {Object.keys(tacticMap).length > 0 && (
        <Section title="MITRE ATT&CK Coverage">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {Object.entries(tacticMap).map(([tactic, techniques]) => (
              <div key={tactic} style={{
                padding: "12px 16px",
                background: "var(--bg-input)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
              }}>
                <div style={{
                  fontSize: 11, fontWeight: 700, color: "#a78bfa",
                  textTransform: "uppercase", letterSpacing: "0.04em",
                  marginBottom: 8, fontFamily: "var(--font-sans)",
                }}>
                  {tactic}
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {techniques.map((t, i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", gap: 8,
                      fontSize: 11,
                    }}>
                      <span style={{
                        fontWeight: 600, color: "#a78bfa",
                        fontFamily: "var(--font-mono)", minWidth: 80,
                      }}>
                        {t.id}
                      </span>
                      <span style={{ color: "var(--text-secondary)" }}>
                        {t.name}
                      </span>
                      <span style={{
                        fontSize: 10, color: "var(--text-muted)",
                        marginLeft: "auto",
                      }}>
                        {t.finding}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
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
