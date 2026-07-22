"use client";

import React from "react";
import { FinalRiskEvidence } from "@/lib/types";
import styles from "./FinalRiskExplainer.module.css";

const COMPONENTS: Record<string, { label: string; short: string; description: string; color: string }> = {
  lexical_score: { label: "URL structure", short: "Lexical", description: "Suspicious patterns in the written URL.", color: "#60a5fa" },
  behavior_score: { label: "Observed behavior", short: "Behavior", description: "Redirects, cloaking, forms, and destination changes.", color: "#a78bfa" },
  content_ml_score: { label: "Content signals", short: "Content ML", description: "Social engineering, urgency, impersonation, and BEC language.", color: "#f59e0b" },
  attachment_score: { label: "Attachment analysis", short: "Attachment", description: "Static file characteristics such as macros and suspicious structure.", color: "#fb923c" },
  sandbox_score: { label: "Sandbox behavior", short: "Sandbox", description: "Behavior observed during dynamic AnyRun analysis.", color: "#fb7185" },
  infrastructure_score: { label: "Infrastructure & reputation", short: "Infrastructure", description: "Threat vendors, feeds, domain age, IP, and hosting context.", color: "#38bdf8" },
  opencti_score: { label: "OpenCTI intelligence", short: "OpenCTI", description: "Known intelligence relationships, reports, indicators, and campaigns.", color: "#2dd4bf" },
};

function clamp(value: number, min = 0, max = 1) { return Math.min(max, Math.max(min, value)); }
function riskTone(score: number) {
  if (score < 35) return { label: "Low", color: "#38d9a9", summary: "Technical signals currently indicate limited risk." };
  if (score < 70) return { label: "Medium", color: "#fbbf24", summary: "Technical signals warrant analyst review and corroboration." };
  return { label: "High", color: "#fb7185", summary: "Multiple or authoritative technical signals indicate elevated risk." };
}

export default function FinalRiskExplainer({ risk }: { risk: FinalRiskEvidence }) {
  const score = Math.max(0, Math.min(100, Number(risk?.risk_score || 0)));
  const tone = riskTone(score);
  const components = Object.entries(risk?.components || {}).map(([key, raw]) => {
    const value = clamp(Number(raw || 0));
    const weight = clamp(Number(risk?.weights?.[key] || 0));
    return { key, value, weight, points: value * weight * 100, copy: COMPONENTS[key] || { label: key.replaceAll("_", " "), short: key, description: "A normalized technical risk signal.", color: "#94a3b8" } };
  }).sort((a, b) => b.points - a.points);
  const weightedTotal = components.reduce((sum, item) => sum + item.points, 0);
  const floorApplied = score > Math.round(weightedTotal) + 1;
  const strongest = components.filter((item) => item.value >= .55);

  return (
    <div className={styles.wrap} style={{ "--risk-color": tone.color } as React.CSSProperties}>
      <div className={styles.hero}>
        <div className={styles.scoreBlock}>
          <div className={styles.scoreRing} style={{ "--score-angle": `${score * 3.6}deg` } as React.CSSProperties}>
            <div><strong>{Math.round(score)}</strong><span>/ 100</span></div>
          </div>
          <div className={styles.level}>{tone.label} risk</div>
        </div>
        <div className={styles.heroCopy}>
          <div className={styles.eyebrow}>Composite technical assessment</div>
          <h4>{tone.summary}</h4>
          <p>This score combines seven independent technical signal families. Each component is normalized to 0–100, multiplied by its configured weight, and then added to the total.</p>
          <div className={styles.heroMeta}>
            <div><span>Confidence</span><strong>{String(risk?.confidence || "unknown")}</strong><small>Based on the number of strong supporting signals</small></div>
            <div><span>Strong signals</span><strong>{strongest.length} of {components.length}</strong><small>Components at or above 55%</small></div>
            <div><span>Weighted sum</span><strong>{weightedTotal.toFixed(1)} pts</strong><small>{floorApplied ? "Before trusted-intelligence floor" : "Matches the displayed composite"}</small></div>
          </div>
        </div>
      </div>

      <div className={styles.explanation}>
        <div className={styles.infoIcon}>i</div>
        <div><strong>This is a blended technical score—not another probability.</strong><p>A component at 80% with a 15% weight contributes 12 points. A zero can mean no risk was observed or that the relevant evidence was unavailable; corroborate it with the collector section.</p></div>
      </div>

      <div className={styles.sectionHeader}>
        <div><strong>How the score was assembled</strong><span>Sorted by actual point contribution to the final score.</span></div>
        <span>Signal × weight = points</span>
      </div>
      <div className={styles.components}>
        {components.map((item) => (
          <div className={styles.component} key={item.key}>
            <div className={styles.componentTitle}>
              <span className={styles.componentIcon} style={{ color: item.copy.color, background: `${item.copy.color}17` }}>{item.copy.short.slice(0, 1)}</span>
              <div><strong>{item.copy.label}</strong><span>{item.copy.description}</span></div>
              <b style={{ color: item.copy.color }}>{item.points.toFixed(1)} pts</b>
            </div>
            <div className={styles.barLabels}><span>Signal strength <b>{Math.round(item.value * 100)}%</b></span><span>Weight <b>{Math.round(item.weight * 100)}%</b></span></div>
            <div className={styles.bar}><span style={{ width: `${item.value * 100}%`, background: item.copy.color }} /></div>
            <div className={styles.formula}>{Math.round(item.value * 100)} × {Math.round(item.weight * 100)}% = <b>{item.points.toFixed(1)} points</b></div>
          </div>
        ))}
      </div>

      <div className={styles.sumLine}>
        <span>Weighted technical sum</span><i />
        <strong>{weightedTotal.toFixed(1)}</strong>
        {floorApplied && <><span className={styles.floorArrow}>→</span><strong className={styles.floorScore}>{Math.round(score)}</strong><em>trusted intelligence floor applied</em></>}
      </div>

      {!!risk?.rationale?.length && (
        <div className={styles.rationale}>
          <div className={styles.sectionHeader}><div><strong>Why the engine reached this level</strong><span>Decision-relevant findings generated by the aggregation rules.</span></div></div>
          <div className={styles.reasons}>
            {risk.rationale.map((reason, index) => <div key={`${reason}-${index}`}><span>{index + 1}</span><p>{reason}</p></div>)}
          </div>
        </div>
      )}
    </div>
  );
}
