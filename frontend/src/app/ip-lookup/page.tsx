"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import * as api from "@/lib/api";

// ─── Score helpers ───
function scoreColor(score: number | null | undefined): string {
  if (score == null) return "var(--text-muted)";
  if (score >= 75) return "var(--red)";
  if (score >= 25) return "var(--yellow)";
  return "var(--green)";
}

function scoreLabel(score: number | null | undefined): string {
  if (score == null) return "NO DATA";
  if (score >= 75) return "HIGH RISK";
  if (score >= 25) return "SUSPICIOUS";
  if (score > 0)   return "LOW RISK";
  return "CLEAN";
}

// ─── Main Page ───
export default function IPLookupPage() {
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const inputRef = useRef<HTMLInputElement>(null);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getIPLookupHistory(50, 0);
      setHistory(data);
    } catch {
      // history is best-effort
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  async function handleLookup(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = ip.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.lookupIP(trimmed);
      setResult(data);
      // Prepend to history list without a full reload
      setHistory((prev) => [
        {
          id: data.id,
          ip: data.ip,
          abuse_score: data.abuseipdb?.abuse_confidence_score ?? null,
          isp: data.abuseipdb?.isp ?? null,
          country_code: data.abuseipdb?.country_code ?? null,
          threatfox_count: data.threatfox?.length ?? 0,
          queried_at: data.queried_at,
        },
        ...prev,
      ]);
    } catch (err: any) {
      setError(err?.message || "Lookup failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleHistoryClick(item: any) {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getIPLookup(item.id);
      setResult(data);
      setIp(data.ip);
    } catch (err: any) {
      setError(err?.message || "Failed to load lookup");
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    try {
      await api.deleteIPLookup(id);
      setHistory((prev) => prev.filter((h) => h.id !== id));
      if (result?.id === id) setResult(null);
    } catch {
      // ignore
    }
  }

  return (
    <div style={{ paddingTop: 32, paddingBottom: 64 }}>

      {/* Page title */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{
          fontSize: 22, fontWeight: 700, color: "var(--text)",
          fontFamily: "var(--font-sans)", margin: 0, letterSpacing: "-0.01em",
        }}>
          IP Reputation Lookup
        </h1>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 5, fontFamily: "var(--font-sans)" }}>
          Check any IP against AbuseIPDB (verbose) and ThreatFox. Results are saved to history.
        </p>
      </div>

      {/* Search bar */}
      <form onSubmit={handleLookup} style={{ display: "flex", gap: 10, marginBottom: 28 }}>
        <input
          ref={inputRef}
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="Enter IPv4 or IPv6 address…"
          autoFocus
          style={{
            flex: 1, padding: "10px 16px", fontSize: 14,
            background: "var(--bg-input)", color: "var(--text)",
            border: "1px solid var(--border)", borderRadius: "var(--radius)",
            outline: "none", fontFamily: "var(--font-mono)",
          }}
          onFocus={(e) => { e.currentTarget.style.borderColor = "var(--accent)"; }}
          onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
        />
        <button
          type="submit"
          disabled={loading || !ip.trim()}
          style={{
            padding: "10px 28px", fontSize: 13, fontWeight: 600,
            background: loading ? "var(--bg-elevated)" : "var(--accent)",
            color: loading ? "var(--text-muted)" : "#fff",
            border: "none", borderRadius: "var(--radius)",
            cursor: loading ? "not-allowed" : "pointer",
            fontFamily: "var(--font-sans)", transition: "background 0.15s",
            whiteSpace: "nowrap",
          }}
        >
          {loading ? "Checking…" : "Look up"}
        </button>
      </form>

      {/* Error */}
      {error && (
        <div style={{
          padding: "10px 16px", background: "rgba(239,68,68,0.07)",
          border: "1px solid rgba(239,68,68,0.25)", borderRadius: "var(--radius)",
          fontSize: 12, color: "var(--red)", marginBottom: 20,
        }}>
          {error}
        </div>
      )}

      {/* Two-column layout */}
      <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 20, alignItems: "start" }}>

        {/* ── History sidebar ── */}
        <div style={{
          background: "var(--bg-surface)", border: "1px solid var(--border)",
          borderRadius: "var(--radius)", overflow: "hidden",
          position: "sticky", top: 76,
        }}>
          <div style={{
            padding: "12px 16px", borderBottom: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "space-between",
          }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)", letterSpacing: "0.05em", fontFamily: "var(--font-sans)", textTransform: "uppercase" }}>
              History
            </span>
            <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
              {history.length} lookup{history.length !== 1 ? "s" : ""}
            </span>
          </div>

          {historyLoading ? (
            <div style={{ padding: 20, textAlign: "center", fontSize: 11, color: "var(--text-muted)" }}>Loading…</div>
          ) : history.length === 0 ? (
            <div style={{ padding: "20px 16px", fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", textAlign: "center" }}>
              No lookups yet.<br />Enter an IP above to start.
            </div>
          ) : (
            <div style={{ maxHeight: "calc(100vh - 200px)", overflowY: "auto" }}>
              {history.map((item) => {
                const isActive = result?.id === item.id;
                const color = scoreColor(item.abuse_score);
                return (
                  <div
                    key={item.id}
                    onClick={() => handleHistoryClick(item)}
                    style={{
                      padding: "10px 16px",
                      borderBottom: "1px solid var(--border-dim)",
                      cursor: "pointer",
                      background: isActive ? "var(--accent-glow)" : "transparent",
                      borderLeft: isActive ? "3px solid var(--accent)" : "3px solid transparent",
                      transition: "background 0.1s",
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) e.currentTarget.style.background = "var(--bg-input)";
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                        {item.ip}
                      </span>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        {item.abuse_score != null && (
                          <span style={{
                            fontSize: 10, fontWeight: 700, color, padding: "1px 6px",
                            background: `${color}12`, border: `1px solid ${color}30`,
                            borderRadius: "var(--radius-sm)", fontFamily: "var(--font-mono)",
                          }}>
                            {item.abuse_score}
                          </span>
                        )}
                        <button
                          onClick={(e) => handleDelete(e, item.id)}
                          title="Delete"
                          style={{
                            width: 18, height: 18, lineHeight: "18px", textAlign: "center",
                            fontSize: 12, background: "transparent",
                            border: "none", color: "var(--text-muted)",
                            cursor: "pointer", borderRadius: "var(--radius-sm)",
                            padding: 0,
                          }}
                          onMouseEnter={(e) => { e.currentTarget.style.color = "var(--red)"; }}
                          onMouseLeave={(e) => { e.currentTarget.style.color = "var(--text-muted)"; }}
                        >
                          ×
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                      {item.isp ? `${item.isp}` : "—"}
                      {item.country_code ? ` · ${item.country_code}` : ""}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 4 }}>
                      <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                        {item.queried_at ? new Date(item.queried_at).toLocaleString() : ""}
                      </span>
                      {item.threatfox_count > 0 && (
                        <span style={{
                          fontSize: 9, fontWeight: 700, padding: "1px 5px",
                          background: "rgba(239,68,68,0.1)", color: "var(--red)",
                          border: "1px solid rgba(239,68,68,0.2)", borderRadius: "var(--radius-sm)",
                          fontFamily: "var(--font-sans)",
                        }}>
                          TF:{item.threatfox_count}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* ── Main results ── */}
        <div>
          {!result && !loading && (
            <div style={{
              padding: "48px 32px", textAlign: "center",
              background: "var(--bg-surface)", border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
            }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>🔍</div>
              <div style={{ fontSize: 13, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
                Enter an IP address or click a history item
              </div>
            </div>
          )}
          {result && <IPLookupResult result={result} />}
        </div>
      </div>
    </div>
  );
}

// ─── Result component ───
function IPLookupResult({ result }: { result: any }) {
  const ab = result.abuseipdb;
  const tf: any[] = result.threatfox || [];
  const errs: string[] = result.errors || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* AbuseIPDB not configured */}
      {!ab && errs.some((e: string) => e.includes("AbuseIPDB")) && (
        <Card>
          <div style={{ fontSize: 12, color: "var(--yellow)", padding: "4px 0" }}>
            AbuseIPDB API key not configured — add <code style={{ fontFamily: "var(--font-mono)" }}>ABUSEIPDB_API_KEY</code> to your .env
          </div>
        </Card>
      )}

      {/* Score hero */}
      {ab && (
        <Card>
          <div style={{ display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
            {/* Score gauge */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <ScoreGauge score={ab.abuse_confidence_score} />
              <span style={{
                fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                color: scoreColor(ab.abuse_confidence_score),
                fontFamily: "var(--font-sans)",
              }}>
                {scoreLabel(ab.abuse_confidence_score)}
              </span>
            </div>

            {/* Key meta */}
            <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 12 }}>
              <MetaItem label="IP Address" value={ab.ip} mono />
              <MetaItem label="ISP" value={ab.isp || "N/A"} />
              <MetaItem label="Country" value={ab.country_name || ab.country_code || "N/A"} />
              <MetaItem label="Usage Type" value={ab.usage_type || "N/A"} />
              <MetaItem label="Total Reports" value={String(ab.total_reports)} />
              <MetaItem label="Distinct Reporters" value={String(ab.num_distinct_users)} />
              <MetaItem label="Domain" value={ab.domain || "—"} mono />
              <MetaItem
                label="Last Reported"
                value={ab.last_reported_at ? new Date(ab.last_reported_at).toLocaleDateString() : "Never"}
              />
            </div>

            {/* Flags */}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {ab.is_tor && <Flag label="TOR Exit Node" color="var(--red)" />}
              {ab.is_whitelisted && <Flag label="Whitelisted" color="var(--green)" />}
              {!ab.is_public && <Flag label="Private IP" color="var(--text-muted)" />}
            </div>
          </div>
        </Card>
      )}

      {/* Abuse categories */}
      {ab && ab.category_labels.length > 0 && (
        <Section title="Abuse Categories">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {ab.category_labels.map((label: string, i: number) => (
              <span key={i} style={{
                padding: "4px 12px", fontSize: 11, fontWeight: 600,
                background: "rgba(239,68,68,0.08)", color: "var(--red)",
                border: "1px solid rgba(239,68,68,0.22)", borderRadius: "var(--radius-sm)",
                fontFamily: "var(--font-sans)",
              }}>
                {label}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Hostnames */}
      {ab && ab.hostnames.length > 0 && (
        <Section title="Reverse DNS / Hostnames">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {ab.hostnames.map((h: string, i: number) => (
              <span key={i} style={{
                padding: "3px 10px", fontSize: 11,
                background: "var(--bg-input)", color: "var(--text-secondary)",
                border: "1px solid var(--border-dim)", borderRadius: "var(--radius-sm)",
                fontFamily: "var(--font-mono)",
              }}>{h}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Recent reports */}
      {ab && ab.recent_reports.length > 0 && (
        <Section title={`Recent Reports (${ab.recent_reports.length} of ${ab.total_reports})`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            {ab.recent_reports.map((r: any, i: number) => (
              <div key={i} style={{
                padding: "9px 12px",
                background: i % 2 === 0 ? "var(--bg-input)" : "transparent",
                borderRadius: "var(--radius-sm)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: r.comment ? 5 : 0, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", minWidth: 82 }}>
                    {r.reported_at ? new Date(r.reported_at).toLocaleDateString() : "—"}
                  </span>
                  {r.reporter_country && (
                    <span style={{
                      fontSize: 10, fontWeight: 600, color: "var(--text-dim)",
                      padding: "1px 6px", background: "var(--bg-elevated)", borderRadius: "var(--radius-sm)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {r.reporter_country}
                    </span>
                  )}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {r.category_labels.map((c: string, j: number) => (
                      <span key={j} style={{
                        fontSize: 10, padding: "1px 6px",
                        background: "rgba(239,68,68,0.08)", color: "var(--red)",
                        border: "1px solid rgba(239,68,68,0.18)", borderRadius: "var(--radius-sm)",
                        fontFamily: "var(--font-sans)",
                      }}>{c}</span>
                    ))}
                  </div>
                </div>
                {r.comment && (
                  <div style={{
                    fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)",
                    lineHeight: 1.5, paddingLeft: 90, wordBreak: "break-word",
                  }}>
                    {r.comment}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ThreatFox */}
      {tf.length > 0 && (
        <Section title={`ThreatFox IOC Matches (${tf.length})`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {tf.map((ioc, i) => (
              <div key={i} style={{
                padding: "12px 14px",
                background: "var(--bg-input)", border: "1px solid var(--border)",
                borderRadius: "var(--radius)", borderLeft: "3px solid var(--red)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 5 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                    {ioc.ioc_value}
                  </span>
                  <span style={{
                    fontSize: 10, fontWeight: 600, padding: "2px 8px",
                    background: "rgba(239,68,68,0.1)", color: "var(--red)",
                    border: "1px solid rgba(239,68,68,0.25)", borderRadius: "var(--radius-sm)", fontFamily: "var(--font-sans)",
                  }}>{ioc.threat_type}</span>
                  {ioc.malware && (
                    <span style={{
                      fontSize: 10, fontWeight: 600, padding: "2px 8px",
                      background: "rgba(245,158,11,0.1)", color: "var(--yellow)",
                      border: "1px solid rgba(245,158,11,0.25)", borderRadius: "var(--radius-sm)", fontFamily: "var(--font-sans)",
                    }}>{ioc.malware}</span>
                  )}
                  {ioc.confidence_level != null && (
                    <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto", fontFamily: "var(--font-sans)" }}>
                      Confidence: {ioc.confidence_level}%
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", gap: 14, fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                  {ioc.first_seen && <span>First: {ioc.first_seen.slice(0, 10)}</span>}
                  {ioc.last_seen && <span>Last: {ioc.last_seen.slice(0, 10)}</span>}
                  <span>Type: {ioc.ioc_type}</span>
                </div>
                {ioc.tags.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 8 }}>
                    {ioc.tags.map((t: string, j: number) => (
                      <span key={j} style={{
                        fontSize: 10, padding: "1px 7px",
                        background: "rgba(96,165,250,0.08)", color: "var(--accent)",
                        border: "1px solid rgba(96,165,250,0.2)", borderRadius: "var(--radius-sm)",
                        fontFamily: "var(--font-sans)",
                      }}>{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {tf.length === 0 && ab && (
        <Section title="ThreatFox IOC Matches">
          <div style={{
            padding: "9px 12px", fontSize: 12, color: "var(--green)",
            background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.18)",
            borderRadius: "var(--radius-sm)",
          }}>
            No IOC matches found in ThreatFox for this IP.
          </div>
        </Section>
      )}

      {/* Timestamp */}
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", textAlign: "right" }}>
        Queried {new Date(result.queried_at).toUTCString()} · AbuseIPDB 90-day window
      </div>
    </div>
  );
}

// ─── Score gauge (SVG arc) ───
function ScoreGauge({ score }: { score: number }) {
  const size = 88;
  const r = 34;
  const cx = size / 2;
  const cy = size / 2 + 6;
  const startAngle = -210;
  const totalSweep = 240;
  const sweep = (score / 100) * totalSweep;
  const color = scoreColor(score);

  function polarToXY(angleDeg: number, radius: number) {
    const rad = ((angleDeg - 90) * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  }

  function arcPath(startDeg: number, sweepDeg: number) {
    const start = polarToXY(startDeg, r);
    const end = polarToXY(startDeg + sweepDeg, r);
    const large = sweepDeg > 180 ? 1 : 0;
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 1 ${end.x} ${end.y}`;
  }

  return (
    <svg width={size} height={size} style={{ overflow: "visible" }}>
      <path d={arcPath(startAngle, totalSweep)} fill="none" stroke="var(--bg-elevated)" strokeWidth={8} strokeLinecap="round" />
      {score > 0 && (
        <path d={arcPath(startAngle, sweep)} fill="none" stroke={color} strokeWidth={8} strokeLinecap="round" />
      )}
      <text x={cx} y={cy + 4} textAnchor="middle" fill={color}
        style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)" }}>
        {score}
      </text>
      <text x={cx} y={cy + 18} textAnchor="middle" fill="var(--text-muted)"
        style={{ fontSize: 9, fontFamily: "var(--font-sans)" }}>
        / 100
      </text>
    </svg>
  );
}

// ─── Sub-components ───
function Card({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      padding: "18px 22px",
      background: "var(--bg-surface)", border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
    }}>
      {children}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      padding: "16px 22px",
      background: "var(--bg-surface)", border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
    }}>
      <div style={{
        fontSize: 11, fontWeight: 700, color: "var(--accent)",
        letterSpacing: "0.06em", marginBottom: 12,
        paddingBottom: 8, borderBottom: "1px solid var(--border-dim)",
        textTransform: "uppercase", fontFamily: "var(--font-sans)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function MetaItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginBottom: 2, letterSpacing: "0.03em" }}>
        {label}
      </div>
      <div style={{
        fontSize: 12, fontWeight: 600, color: "var(--text)",
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        wordBreak: "break-all",
      }}>
        {value}
      </div>
    </div>
  );
}

function Flag({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: "3px 10px",
      background: `${color}12`, color,
      border: `1px solid ${color}30`, borderRadius: "var(--radius-sm)",
      fontFamily: "var(--font-sans)", letterSpacing: "0.04em",
    }}>
      {label}
    </span>
  );
}
