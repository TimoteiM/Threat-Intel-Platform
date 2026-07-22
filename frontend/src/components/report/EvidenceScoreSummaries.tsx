"use client";

import React from "react";
import { ContentMLEvidence, URLBehaviorEvidence } from "@/lib/types";
import styles from "./EvidenceScoreSummaries.module.css";

const CONTENT_SIGNALS = [
  ["social_engineering_probability", "Social engineering", "Language designed to influence the recipient into taking an action."],
  ["urgency_probability", "Urgency", "Pressure, deadlines, or consequences intended to reduce careful review."],
  ["impersonation_probability", "Impersonation", "Language or metadata suggesting the sender is posing as a trusted identity."],
  ["bec_probability", "Business email compromise", "Patterns associated with payment, mailbox, executive, or supplier fraud."],
] as const;

function clamp(value: number) { return Math.max(0, Math.min(1, value)); }
function tone(value: number) {
  if (value < .35) return { label: "Low", color: "#38d9a9" };
  if (value < .7) return { label: "Medium", color: "#fbbf24" };
  return { label: "High", color: "#fb7185" };
}

export function ContentMLSummary({ content }: { content: ContentMLEvidence }) {
  const signals = CONTENT_SIGNALS.map(([key, label, description]) => ({ key, label, description, value: clamp(Number(content?.[key] || 0)) }));
  const average = signals.reduce((sum, item) => sum + item.value, 0) / signals.length;
  const averageTone = tone(average);
  return (
    <div className={styles.module}>
      <div className={styles.summary} style={{ "--tone": averageTone.color } as React.CSSProperties}>
        <div className={styles.summaryScore}><strong>{Math.round(average * 100)}%</strong><span>combined signal</span></div>
        <div><div className={styles.eyebrow}>Language and metadata assessment</div><h4>{averageTone.label} content-based risk</h4><p>The engine averages four specialized indicators. This section measures suspicious communication patterns; it does not determine whether the sender or destination is malicious by itself.</p></div>
        <div className={styles.weight}><span>Final-risk weight</span><strong>12%</strong><small>≈ {(average * 12).toFixed(1)} points from these signals</small></div>
      </div>
      <div className={styles.cards}>
        {signals.map((item) => {
          const itemTone = tone(item.value);
          return <div className={styles.card} key={item.key}>
            <div className={styles.cardTop}><strong>{item.label}</strong><span style={{ color: itemTone.color }}>{Math.round(item.value * 100)}% · {itemTone.label}</span></div>
            <p>{item.description}</p>
            <div className={styles.bar}><span style={{ width: `${item.value * 100}%`, background: itemTone.color }} /></div>
          </div>;
        })}
      </div>
      {!!content?.top_content_terms?.length && <div className={styles.terms}><span>Influential terms</span>{content.top_content_terms.slice(0, 10).map((term) => <i key={term}>{term}</i>)}</div>}
    </div>
  );
}

export function URLBehaviorSummary({ behavior }: { behavior: URLBehaviorEvidence }) {
  const score = clamp(Number(behavior?.behavior_score || 0));
  const scoreTone = tone(score);
  const indicators = [
    { label: "User-agent cloaking", active: !!behavior?.ua_cloaking_detected, detail: "Different visitors received different behavior." },
    { label: "Credential form", active: !!behavior?.credential_form_present, detail: "A form capable of collecting credentials was observed." },
    { label: "Cross-domain hops", active: !!behavior?.multiple_domain_hops, detail: "The navigation crossed multiple domain boundaries." },
    { label: "Redirect chain", active: Number(behavior?.redirect_count || 0) > 0, detail: `${Number(behavior?.redirect_count || 0)} redirect${Number(behavior?.redirect_count || 0) === 1 ? "" : "s"} observed.` },
  ];
  const activeCount = indicators.filter((item) => item.active).length;
  return (
    <div className={styles.module}>
      <div className={styles.summary} style={{ "--tone": scoreTone.color } as React.CSSProperties}>
        <div className={styles.summaryScore}><strong>{Math.round(score * 100)}%</strong><span>behavior score</span></div>
        <div><div className={styles.eyebrow}>Observed navigation and page behavior</div><h4>{scoreTone.label} behavioral risk</h4><p>{activeCount ? `${activeCount} behavior indicator${activeCount === 1 ? " was" : "s were"} observed.` : "No high-value behavior indicators were observed."} Behavioral evidence is stronger than URL appearance because it describes what the destination actually did during collection.</p></div>
        <div className={styles.weight}><span>Final-risk weight</span><strong>16%</strong><small>≈ {(score * 16).toFixed(1)} points from behavior</small></div>
      </div>
      <div className={styles.cards}>
        {indicators.map((item) => <div className={`${styles.indicator} ${item.active ? styles.active : styles.inactive}`} key={item.label}>
          <span>{item.active ? "!" : "✓"}</span><div><strong>{item.label}</strong><p>{item.active ? item.detail : `Not detected. ${item.detail}`}</p></div><b>{item.active ? "Observed" : "Clear"}</b>
        </div>)}
      </div>
      {behavior?.final_url && <div className={styles.destination}><span>Final destination</span><code title={behavior.final_url}>{behavior.final_url}</code></div>}
      {!!behavior?.suspicious_post_endpoints?.length && <div className={styles.destination}><span>Suspicious POST endpoints</span><code>{behavior.suspicious_post_endpoints.join(" · ")}</code></div>}
    </div>
  );
}
