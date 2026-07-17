"use client";

import React from "react";
import { AnalystReport } from "@/lib/types";
import { SEVERITY_COLORS } from "@/lib/constants";
import Badge from "@/components/shared/Badge";

interface Props {
  report: AnalystReport;
  evidence?: Record<string, any> | null;
}

export default function FindingsTab({ report, evidence }: Props) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const keyEvidence = Array.isArray(report?.key_evidence) ? report.key_evidence : [];
  const contradicting = Array.isArray(report?.contradicting_evidence) ? report.contradicting_evidence : [];
  const braveOsint = evidence?.brave_osint || null;
  const braveHits = Array.isArray(braveOsint?.top_hits) ? braveOsint.top_hits : [];
  const braveScore = typeof braveOsint?.score === "number" ? braveOsint.score : 0;
  const braveRiskLevel = String(braveOsint?.risk_level || "").toLowerCase();
  const braveHasSignal = !!(
    braveOsint &&
    (braveRiskLevel === "high" ||
      braveRiskLevel === "medium" ||
      braveScore >= 40 ||
      braveHits.length >= 2)
  );
  const braveSeverity =
    braveOsint?.risk_level === "high"
      ? "high"
      : braveOsint?.risk_level === "medium"
        ? "medium"
        : "info";
  const braveColor = SEVERITY_COLORS[braveSeverity] || SEVERITY_COLORS.info;

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
      {braveHasSignal && (
        <Section title="Brave OSINT Highlights">
          <div
            style={{
              padding: "16px 20px",
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              borderLeft: `3px solid ${braveColor}`,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
              <Badge label={braveSeverity} color={braveColor} />
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>
                Public OSINT enrichment
              </span>
              <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                Score {typeof braveOsint?.score === "number" ? `${braveOsint.score}/100` : "n/a"}
              </span>
            </div>

            {braveOsint?.summary && (
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
                {braveOsint.summary}
              </div>
            )}

            {braveHits.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {braveHits.slice(0, 3).map((hit: any, i: number) => (
                  <a
                    key={`${hit?.url || "hit"}-${i}`}
                    href={hit?.url || "#"}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: "block",
                      padding: "10px 12px",
                      background: "var(--bg-card)",
                      border: "1px solid var(--border)",
                      borderRadius: "var(--radius-sm)",
                      textDecoration: "none",
                    }}
                  >
                    <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text)", marginBottom: 4 }}>
                      {hit?.title || hit?.url || "Relevant Brave OSINT result"}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>
                      {hit?.source || "Unknown source"}
                      {typeof hit?.score === "number" ? ` · score ${hit.score}` : ""}
                    </div>
                    {hit?.description && (
                      <div style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.5 }}>
                        {hit.description}
                      </div>
                    )}
                  </a>
                ))}
              </div>
            )}
          </div>
        </Section>
      )}

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
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
                    <Badge label={f?.severity || "info"} color={color} />
                    <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>
                      {f?.title || "Untitled finding"}
                    </span>
                  </div>
                  {f?.description && (
                    <div
                      style={{
                        fontSize: 12,
                        color: "var(--text-secondary)",
                        lineHeight: 1.65,
                        whiteSpace: "pre-line",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {String(f.description).replace(/\s+\*\s+/g, "\n• ")}
                    </div>
                  )}
                  {Array.isArray(f?.evidence_refs) && f.evidence_refs.length > 0 && (
                    <FindingEvidenceRefs refs={f.evidence_refs} evidence={evidence || undefined} />
                  )}
                  {f?.ttp && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                      {f.ttp_url ? (
                        <a
                          href={f.ttp_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            fontSize: 11,
                            fontWeight: 600,
                            color: "#a78bfa",
                            textDecoration: "none",
                            padding: "3px 8px",
                            background: "rgba(167,139,250,0.10)",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid rgba(167,139,250,0.25)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {f.ttp}
                        </a>
                      ) : (
                        <span
                          style={{
                            fontSize: 11,
                            fontWeight: 600,
                            color: "#a78bfa",
                            padding: "3px 8px",
                            background: "rgba(167,139,250,0.10)",
                            borderRadius: "var(--radius-sm)",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {f.ttp}
                        </span>
                      )}
                      {f.ttp_name && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{f.ttp_name}</span>}
                      {f.ttp_tactic && (
                        <span
                          style={{
                            fontSize: 9,
                            fontWeight: 600,
                            color: "var(--text-muted)",
                            padding: "2px 6px",
                            background: "var(--bg-elevated)",
                            borderRadius: "var(--radius-sm)",
                            textTransform: "uppercase",
                            letterSpacing: "0.04em",
                            fontFamily: "var(--font-sans)",
                          }}
                        >
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
        <RefList items={keyEvidence} color="var(--green)" report={report} evidence={evidence || undefined} />
      </Section>

      {contradicting.length > 0 && (
        <Section title="Contradicting Evidence">
          <RefList items={contradicting} color="var(--yellow)" report={report} evidence={evidence || undefined} />
        </Section>
      )}

      {Object.keys(tacticMap).length > 0 && (
        <Section title="MITRE ATT&CK Coverage">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {Object.entries(tacticMap).map(([tactic, techniques]) => (
              <div
                key={tactic}
                style={{
                  padding: "12px 16px",
                  background: "var(--bg-input)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                }}
              >
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: "#a78bfa",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    marginBottom: 8,
                    fontFamily: "var(--font-sans)",
                  }}
                >
                  {tactic}
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {techniques.map((t, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
                      <span style={{ fontWeight: 600, color: "#a78bfa", fontFamily: "var(--font-mono)", minWidth: 80 }}>
                        {t.id}
                      </span>
                      <span style={{ color: "var(--text-secondary)" }}>{t.name}</span>
                      <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>{t.finding}</span>
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
      <div
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: "var(--accent)",
          letterSpacing: "0.01em",
          marginBottom: 14,
          paddingBottom: 8,
          borderBottom: "1px solid var(--border)",
          fontFamily: "var(--font-sans)",
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function FindingEvidenceRefs({ refs, evidence }: { refs: string[]; evidence?: Record<string, any> }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          marginBottom: 6,
        }}
      >
        Supporting evidence
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {refs.map((ref, index) => {
          const evidencePath = extractEvidencePath(String(ref)) || String(ref);
          const resolved = evidence ? resolveByPath(evidence, evidencePath) : undefined;
          const relevant = summarizeRelevantEvidence(evidencePath, resolved);
          return (
            <details key={`${ref}-${index}`} style={{ maxWidth: "100%" }}>
              <summary
                style={{
                  cursor: "pointer",
                  listStyle: "none",
                  padding: "4px 8px",
                  borderRadius: "var(--radius-sm)",
                  border: "1px solid var(--border)",
                  background: "var(--bg-card)",
                  color: "var(--accent)",
                  fontSize: 10,
                  fontFamily: "var(--font-mono)",
                  overflowWrap: "anywhere",
                }}
              >
                {ref}
              </summary>
              <div
                style={{
                  margin: "6px 0 0",
                  padding: "10px 12px",
                  maxWidth: "min(760px, 80vw)",
                  maxHeight: 280,
                  overflow: "auto",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                }}
              >
                {resolved === undefined ? (
                  <span style={{ color: "var(--text-dim)", fontSize: 10 }}>
                    Evidence path is referenced by the finding but no direct value is available in this report payload.
                  </span>
                ) : (
                  <RelevantEvidence value={relevant} />
                )}
              </div>
            </details>
          );
        })}
      </div>
    </div>
  );
}

function RefList({
  items,
  color,
  report,
  evidence,
}: {
  items: any[];
  color: string;
  report: AnalystReport;
  evidence?: Record<string, any>;
}) {
  const [openIdx, setOpenIdx] = React.useState<number | null>(null);
  if (!items || items.length === 0) {
    return <div style={{ fontSize: 12, color: "var(--text-dim)" }}>None</div>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {items.map((item: any, i: number) => (
        <div key={i}>
          <button
            type="button"
            onClick={() => setOpenIdx((prev) => (prev === i ? null : i))}
            style={{
              width: "100%",
              textAlign: "left",
              padding: "6px 12px",
              background: "var(--bg-input)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border)",
              fontSize: 12,
              color,
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            {'>'} {typeof item === "string" ? item : JSON.stringify(item)}
          </button>
          {openIdx === i && <EvidenceDetail item={item} report={report} evidence={evidence} />}
        </div>
      ))}
    </div>
  );
}

function EvidenceDetail({
  item,
  report,
  evidence,
}: {
  item: any;
  report: AnalystReport;
  evidence?: Record<string, any>;
}) {
  const text = typeof item === "string" ? item : JSON.stringify(item);
  const extractedPath = extractEvidencePath(text);
  const resolvedValue = extractedPath && evidence ? resolveByPath(evidence, extractedPath) : undefined;
  const linkedFindings = (Array.isArray(report.findings) ? report.findings : []).filter((f: any) => {
    const refs = Array.isArray(f?.evidence_refs) ? f.evidence_refs : [];
    return refs.includes(extractedPath || text);
  });

  return (
    <div
      style={{
        marginTop: 4,
        padding: "10px 12px",
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        fontSize: 11,
        color: "var(--text-secondary)",
      }}
    >
      <div style={{ marginBottom: 6, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
        Reference: {extractedPath || "free-text evidence item"}
      </div>
      {resolvedValue !== undefined ? (
        <pre
          style={{
            margin: 0,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            fontFamily: "var(--font-mono)",
            color: "var(--text)",
          }}
        >
          {typeof resolvedValue === "string" ? resolvedValue : JSON.stringify(resolvedValue, null, 2)}
        </pre>
      ) : (
        <div style={{ color: "var(--text-dim)" }}>No direct evidence path mapping available for this entry.</div>
      )}
      {linkedFindings.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ color: "var(--accent)", marginBottom: 4 }}>Linked findings:</div>
          {linkedFindings.map((f: any, idx: number) => (
            <div key={idx} style={{ fontSize: 11 }}>
              - {f?.title || "Untitled finding"}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function extractEvidencePath(text: string): string | null {
  const trimmed = String(text || "").trim();
  if (!trimmed) return null;
  const m = trimmed.match(/[a-z_]+(?:\.[a-z0-9_]+){1,}/i);
  return m ? m[0] : null;
}

function resolveByPath(obj: any, path: string): any {
  if (!obj || !path) return undefined;
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur: any = obj;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = cur[part];
  }
  return cur;
}

const OMIT_EVIDENCE_KEYS = new Set([
  "screenshots",
  "screenshot",
  "behavior_graph",
  "graph",
  "html",
  "html_report",
  "raw_html",
  "report_links",
  "api_key_slot",
  "cache_hit",
]);

const IMPORTANT_EVIDENCE_KEYS = [
  "verdict",
  "classification",
  "threat_score",
  "risk_score",
  "risk_level",
  "confidence",
  "threat_names",
  "threatName",
  "tags",
  "phishing_indicators",
  "malicious_count",
  "suspicious_count",
  "total_vendors",
  "behavior_counts",
  "network_threats",
  "analysis_id",
  "analysis_link",
  "permanentUrl",
  "mode",
  "source",
  "summary",
  "score",
  "label",
  "top_features",
];

function summarizeRelevantEvidence(path: string, value: any): any {
  if (value === undefined || value === null) return value;

  if (path === "hybrid_analysis.items" && Array.isArray(value)) {
    return value.slice(0, 4).map((item: any) => {
      const raw = item?.raw_summary || {};
      const behavior = raw?.behavior_details || {};
      return compactEvidence({
        verdict: item?.verdict,
        threat_score: item?.threat_score,
        threat_names: item?.threat_names?.length ? item.threat_names : raw?.threatName,
        tags: item?.tags?.length ? item.tags : raw?.tags,
        mode: raw?.mode,
        analysis_id: item?.analysis_id,
        analysis_link: item?.analysis_link || raw?.permanentUrl,
        behavior_counts: raw?.behavior_counts,
        network_threats: Array.isArray(behavior?.network_threats)
          ? behavior.network_threats.slice(0, 5)
          : undefined,
      });
    });
  }

  return compactEvidence(value);
}

function compactEvidence(value: any, depth = 0): any {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") {
    if (value.startsWith("data:image/") || value.length > 4000) {
      return `[large content omitted: ${value.length.toLocaleString()} characters]`;
    }
    return value.length > 600 ? `${value.slice(0, 600)}…` : value;
  }
  if (typeof value !== "object") return value;
  if (depth >= 4) return "[nested details omitted]";
  if (Array.isArray(value)) {
    const compacted = value
      .slice(0, 8)
      .map((item) => compactEvidence(item, depth + 1))
      .filter((item) => item !== undefined);
    if (value.length > 8) compacted.push(`[${value.length - 8} additional items omitted]`);
    return compacted;
  }

  const entries = Object.entries(value).filter(([key, item]) => (
    !OMIT_EVIDENCE_KEYS.has(key) &&
    item !== null &&
    item !== undefined &&
    item !== "" &&
    (!Array.isArray(item) || item.length > 0) &&
    (typeof item !== "object" || Array.isArray(item) || Object.keys(item as object).length > 0)
  ));
  entries.sort(([a], [b]) => {
    const ai = IMPORTANT_EVIDENCE_KEYS.indexOf(a);
    const bi = IMPORTANT_EVIDENCE_KEYS.indexOf(b);
    return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
  });

  const out: Record<string, any> = {};
  for (const [key, item] of entries.slice(0, 18)) {
    const compacted = compactEvidence(item, depth + 1);
    if (compacted !== undefined) out[key] = compacted;
  }
  if (entries.length > 18) out._omitted = `${entries.length - 18} lower-priority fields`;
  return out;
}

function RelevantEvidence({ value }: { value: any }) {
  if (value === null || value === undefined) {
    return <span style={{ color: "var(--text-dim)", fontSize: 10 }}>No relevant value available.</span>;
  }
  if (typeof value !== "object") {
    return <span style={{ color: "var(--text)", fontSize: 11, overflowWrap: "anywhere" }}>{String(value)}</span>;
  }

  const rows = Array.isArray(value) ? value.map((item, index) => [String(index + 1), item]) : Object.entries(value);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {rows.map(([key, item]: any) => (
        <div key={key} style={{ display: "grid", gridTemplateColumns: "minmax(110px, 180px) minmax(0, 1fr)", gap: 10 }}>
          <span style={{ color: "var(--accent)", fontSize: 10, fontWeight: 700, fontFamily: "var(--font-mono)", overflowWrap: "anywhere" }}>
            {Array.isArray(value) ? `Result ${key}` : String(key).replaceAll("_", " ")}
          </span>
          {typeof item === "object" && item !== null ? (
            <pre style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: "var(--text-secondary)", fontSize: 10, fontFamily: "var(--font-mono)" }}>
              {JSON.stringify(item, null, 2)}
            </pre>
          ) : (
            <span style={{ color: "var(--text)", fontSize: 10, fontFamily: "var(--font-mono)", overflowWrap: "anywhere" }}>
              {String(item)}
            </span>
          )}
        </div>
      ))}
      <div style={{ color: "var(--text-muted)", fontSize: 9, fontStyle: "italic", marginTop: 2 }}>
        Relevant fields only; large raw artifacts and low-signal metadata are omitted.
      </div>
    </div>
  );
}
