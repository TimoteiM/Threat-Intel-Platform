"use client";

import React, { useEffect, useState } from "react";
import * as api from "@/lib/api";
import InvestigationCaseChat from "./InvestigationCaseChat";

const panel: React.CSSProperties = { background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 18 };
const muted: React.CSSProperties = { color: "var(--text-secondary)", fontSize: 12, lineHeight: 1.6 };
const button: React.CSSProperties = { border: "1px solid var(--border)", borderRadius: 7, background: "var(--bg-elevated)", color: "var(--text)", padding: "8px 12px", cursor: "pointer", fontWeight: 650, fontSize: 12 };

function verdictTone(verdict: unknown): { color: string; background: string } {
  switch (String(verdict || "").toLowerCase()) {
    case "benign":
      return { color: "#34d399", background: "rgba(52,211,153,.12)" };
    case "suspicious":
      return { color: "#fbbf24", background: "rgba(251,191,36,.12)" };
    case "malicious":
      return { color: "#fb7185", background: "rgba(239,68,68,.12)" };
    default:
      return { color: "#94a3b8", background: "rgba(148,163,184,.12)" };
  }
}

function RefPills({ refs }: { refs?: string[] }) {
  // Evidence paths remain in the structured response for grounding, audit,
  // exports, and future drill-downs. Raw implementation paths such as
  // `evidence.vt.total_vendors` are intentionally not rendered in the analyst
  // narrative because they add visual noise without explaining the evidence.
  if (!refs?.length) return null;
  return null;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <section style={panel}><h3 style={{ margin: "0 0 13px", fontSize: 14, color: "var(--text)" }}>{title}</h3>{children}</section>;
}

export default function AICaseStoryTab({ investigationId, initialStory }: { investigationId: string; initialStory?: any }) {
  const [story, setStory] = useState<any>(initialStory || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (initialStory) setStory(initialStory);
  }, [initialStory]);

  async function generate() {
    setLoading(true); setError("");
    try { setStory(await api.generateCaseStory(investigationId)); }
    catch (e: any) { setError(e?.message || "Case Story generation failed"); }
    finally { setLoading(false); }
  }
  if (!story) return <div style={{ ...panel, padding: 32, textAlign: "center", background: "linear-gradient(135deg, var(--bg-card), rgba(59,130,246,.08))" }}>
    <div style={{ fontSize: 11, letterSpacing: ".12em", color: "var(--accent)", fontWeight: 800 }}>AI CASE STORY</div>
    <h2 style={{ margin: "10px 0 8px", fontSize: 22 }}>Turn the evidence into one SOC-ready investigation story</h2>
    <p style={{ ...muted, maxWidth: 720, margin: "0 auto 18px" }}>This older investigation does not have a saved Case Story. You can generate and cache one on demand.</p>
    <button style={{ ...button, background: "var(--accent)", color: "white", minWidth: 190 }} onClick={generate} disabled={loading}>{loading ? "Building Case Story…" : "Generate for this older case"}</button>
    {error && <div style={{ color: "var(--red)", marginTop: 14, fontSize: 12 }}>{error}</div>}
  </div>;

  const storyTone = verdictTone(story.verdict);

  return <div style={{ display: "grid", gap: 14 }}>
    <div style={{ ...panel, background: "linear-gradient(135deg, var(--bg-card), rgba(59,130,246,.10))", borderLeft: "3px solid var(--accent)" }}>
      <div style={{ display: "flex", gap: 14, justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap" }}>
        <div><div style={{ fontSize: 10, color: "var(--accent)", fontWeight: 800, letterSpacing: ".1em" }}>AI CASE STORY · {story.model}</div><h2 style={{ margin: "7px 0", fontSize: 21 }}>{story.headline}</h2><div style={muted}>{story.generated_at ? new Date(story.generated_at).toLocaleString() : ""}</div></div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}><strong style={{ fontSize: 26 }}>{story.risk_score}</strong><span style={{ padding: "6px 9px", borderRadius: 6, background: storyTone.background, color: storyTone.color, fontWeight: 800, fontSize: 12 }}>{story.verdict}</span><span style={muted}>{story.confidence} confidence</span></div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 16, marginTop: 18 }}><div><b style={{ fontSize: 12 }}>What happened</b><p style={muted}>{story.what_happened}</p></div><div><b style={{ fontSize: 12 }}>Why it matters</b><p style={muted}>{story.why_it_matters}</p></div></div>
    </div>

    <Section title="Why this exact score"><p style={{ ...muted, marginTop: 0 }}>{story.score_explanation}</p><div style={{ display: "grid", gap: 8 }}>{story.score_components?.map((item: any, i: number) => <div key={i} style={{ padding: 11, background: "var(--bg-elevated)", borderRadius: 7, border: "1px solid var(--border)" }}><div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}><b style={{ fontSize: 12 }}>{item.label}</b><span style={{ color: "var(--accent)", fontSize: 11, fontWeight: 700 }}>{item.effect}</span></div><div style={muted}>{item.explanation}</div><RefPills refs={item.evidence_refs} /></div>)}</div></Section>

    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(330px,1fr))", gap: 14 }}>
      <Section title="Decisive evidence">{story.strongest_evidence?.map((item: any, i: number) => <div key={i} style={{ padding: "10px 0", borderTop: i ? "1px solid var(--border)" : undefined }}><b style={{ fontSize: 12 }}>{item.title}</b><div style={muted}>{item.explanation}</div><RefPills refs={item.evidence_refs} /></div>)}</Section>
      <Section title="Contradictions & benign signals">{story.contradicting_evidence?.length ? story.contradicting_evidence.map((item: any, i: number) => <div key={i} style={{ padding: "10px 0", borderTop: i ? "1px solid var(--border)" : undefined }}><b style={{ fontSize: 12 }}>{item.title}</b><div style={muted}>{item.explanation}</div><RefPills refs={item.evidence_refs} /></div>) : <div style={muted}>No meaningful contradictory evidence was identified.</div>}</Section>
    </div>

    <Section title="Attack & investigation story"><div style={{ display: "grid", gap: 0 }}>{story.timeline?.map((event: any, i: number) => <div key={i} style={{ display: "grid", gridTemplateColumns: "28px 1fr", gap: 10 }}><div style={{ display: "flex", alignItems: "center", flexDirection: "column" }}><span style={{ width: 10, height: 10, borderRadius: 99, background: event.phase === "observed" ? "var(--accent)" : event.phase === "inferred" ? "#f59e0b" : "#34d399", marginTop: 4 }} />{i < story.timeline.length - 1 && <span style={{ width: 1, minHeight: 55, background: "var(--border)" }} />}</div><div style={{ paddingBottom: 15 }}><b style={{ fontSize: 12 }}>{event.label}</b><span style={{ ...muted, marginLeft: 8, textTransform: "uppercase", fontSize: 9 }}>{event.phase}</span><div style={muted}>{event.description}</div><RefPills refs={event.evidence_refs} /></div></div>)}</div></Section>

    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(330px,1fr))", gap: 14 }}>
      <Section title="Visual assessment"><p style={muted}>{story.visual_assessment?.summary}</p>{story.visual_assessment?.observations?.map((x: string) => <div key={x} style={{ ...muted, marginTop: 5 }}>• {x}</div>)}<RefPills refs={story.visual_assessment?.evidence_refs} /></Section>
      <Section title="Changes & campaign correlation"><b style={{ fontSize: 11 }}>Since the previous run</b>{story.changes_since_last_run?.length ? story.changes_since_last_run.map((x: string) => <div key={x} style={{ ...muted, marginTop: 5 }}>• {x}</div>) : <div style={muted}>No prior run or material change is available.</div>}<b style={{ display: "block", fontSize: 11, marginTop: 14 }}>Related campaign assessment</b><p style={muted}>{story.campaign_assessment}</p></Section>
    </div>

    <Section title="Prioritized SOC actions"><div style={{ display: "grid", gap: 8 }}>{story.recommended_actions?.map((item: any, i: number) => <div key={i} style={{ display: "grid", gridTemplateColumns: "38px 1fr", gap: 10, padding: 10, background: "var(--bg-elevated)", borderRadius: 7 }}><b style={{ color: item.priority === "P1" ? "#fb7185" : item.priority === "P2" ? "#fbbf24" : "#60a5fa" }}>{item.priority}</b><div><b style={{ fontSize: 12 }}>{item.action}</b><div style={muted}>{item.rationale}</div><RefPills refs={item.evidence_refs} /></div></div>)}</div>{story.data_gaps?.length > 0 && <div style={{ marginTop: 14 }}><b style={{ fontSize: 11 }}>Data gaps</b>{story.data_gaps.map((x: string) => <div key={x} style={muted}>• {x}</div>)}</div>}</Section>

    <InvestigationCaseChat investigationId={investigationId} />

  </div>;
}
