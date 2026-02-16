"use client";

import React from "react";
import { AnalystReport } from "@/lib/types";
import { ACTION_CONFIG } from "@/lib/constants";
import ClassificationBadge from "@/components/investigation/ClassificationBadge";

interface Props {
  report: AnalystReport;
}

export default function ExecutiveSummaryTab({ report }: Props) {
  const actionKey = report?.recommended_action || "monitor";
  const actionConfig = ACTION_CONFIG[actionKey] || ACTION_CONFIG.monitor;
  const steps = Array.isArray(report?.recommended_steps) ? report.recommended_steps : [];

  return (
    <div>
      <ClassificationBadge
        classification={report?.classification || "inconclusive"}
        confidence={report?.confidence || "low"}
        riskScore={report?.risk_score}
      />

      <Section title="PRIMARY REASONING">
        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8 }}>
          {report?.primary_reasoning || "No reasoning provided."}
        </p>
      </Section>

      <Section title="RECOMMENDED ACTION">
        <div style={{
          display: "inline-flex", alignItems: "center", gap: 10,
          padding: "12px 20px",
          background: `${actionConfig.color}0a`,
          border: `1px solid ${actionConfig.color}33`,
          borderRadius: "var(--radius)",
        }}>
          <span style={{ fontSize: 20 }}>{actionConfig.icon}</span>
          <span style={{
            fontSize: 14, fontWeight: 800, color: actionConfig.color,
            letterSpacing: "0.1em", textTransform: "uppercase",
          }}>
            {actionKey}
          </span>
        </div>

        {steps.length > 0 && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
            {steps.map((step: any, i: number) => (
              <div key={i} style={{ display: "flex", gap: 10, fontSize: 12, color: "var(--text-secondary)" }}>
                <span style={{ color: "var(--text-muted)", minWidth: 20 }}>{i + 1}.</span>
                {typeof step === "string" ? step : JSON.stringify(step)}
              </div>
            ))}
          </div>
        )}
      </Section>

      {(report?.legitimate_explanation || report?.malicious_explanation) && (
        <Section title="HYPOTHESIS COMPARISON">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <HypothesisCard
              type="legitimate"
              color="var(--green)"
              text={report?.legitimate_explanation || "Not provided."}
            />
            <HypothesisCard
              type="malicious"
              color="var(--red)"
              text={report?.malicious_explanation || "Not provided."}
            />
          </div>
        </Section>
      )}

      {report?.risk_rationale && (
        <Section title="RISK RATIONALE">
          <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7 }}>
            {report.risk_rationale}
          </p>
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

function HypothesisCard({ type, color, text }: { type: "legitimate" | "malicious"; color: string; text: string }) {
  return (
    <div style={{
      padding: 20,
      background: `${color}06`,
      border: `1px solid ${color}18`,
      borderRadius: "var(--radius)",
    }}>
      <div style={{ fontSize: 10, fontWeight: 700, color, letterSpacing: "0.08em", marginBottom: 10 }}>
        {type === "legitimate" ? "✓ LEGITIMATE HYPOTHESIS" : "✗ MALICIOUS HYPOTHESIS"}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7 }}>{text}</div>
    </div>
  );
}