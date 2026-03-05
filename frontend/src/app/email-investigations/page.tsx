"use client";

import React, { useEffect, useMemo, useState } from "react";
import {
  getEmailInvestigationRun,
  getEmailInvestigationHistoryItem,
  listEmailInvestigationHistory,
  uploadEmailInvestigation,
} from "@/lib/api";
import type {
  EmailInvestigationHistoryItem,
  EmailInvestigationResponse,
  EmailInvestigationSubmitResponse,
} from "@/lib/types";

export default function EmailInvestigationsPage() {
  const [file, setFile] = useState<File | null>(null);
  const [context, setContext] = useState("");
  const [mlScore, setMlScore] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [loadingHistoryItemId, setLoadingHistoryItemId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [result, setResult] = useState<EmailInvestigationResponse | null>(null);
  const [historyItems, setHistoryItems] = useState<EmailInvestigationHistoryItem[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [includeScreenshots, setIncludeScreenshots] = useState(false);
  const [runAiInterpretation, setRunAiInterpretation] = useState(false);
  const [loadingStartedAt, setLoadingStartedAt] = useState<number | null>(null);
  const [loadingNow, setLoadingNow] = useState<number>(Date.now());

  useEffect(() => {
    if (!loading) return;
    const timer = setInterval(() => setLoadingNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, [loading]);

  const loadingElapsedSec = useMemo(() => {
    if (!loading || !loadingStartedAt) return 0;
    return Math.max(0, Math.floor((loadingNow - loadingStartedAt) / 1000));
  }, [loading, loadingNow, loadingStartedAt]);

  const progressModel = useMemo(() => {
    const steps = [
      { key: "upload", label: "Uploading email file", weight: 1 },
      { key: "parse", label: "Parsing email and extracting indicators", weight: 2 },
      { key: "ip", label: "Checking sender IP in VT and AbuseIPDB", weight: 2 },
      { key: "url", label: "Checking URLs in VirusTotal", weight: 3 },
      { key: "attachment", label: "Checking attachment hashes in VirusTotal", weight: 3 },
      ...(includeScreenshots ? [{ key: "screenshot", label: "Capturing URL destination screenshots", weight: 5 }] : []),
      ...(runAiInterpretation ? [{ key: "ai", label: "Generating final AI interpretation", weight: 6 }] : []),
      { key: "finalize", label: "Finalizing investigation results", weight: 1 },
    ];

    const totalWeight = steps.reduce((sum, s) => sum + s.weight, 0);
    const expectedSeconds = totalWeight * 2.2;
    const progressedWeight = Math.min(totalWeight * 0.95, (loadingElapsedSec / Math.max(1, expectedSeconds)) * totalWeight);
    const percent = Math.max(2, Math.min(95, Math.round((progressedWeight / totalWeight) * 100)));

    let cursor = 0;
    let activeIndex = 0;
    for (let i = 0; i < steps.length; i += 1) {
      cursor += steps[i].weight;
      if (progressedWeight <= cursor) {
        activeIndex = i;
        break;
      }
      activeIndex = i;
    }
    return {
      steps,
      percent,
      activeIndex,
      stageText: steps[activeIndex]?.label || "Running investigation",
    };
  }, [includeScreenshots, runAiInterpretation, loadingElapsedSec]);

  const domainFindings = useMemo(
    () => buildSenderDomainFindings(result),
    [result],
  );
  const urlSummary = useMemo(
    () => buildUrlSummary(result),
    [result],
  );

  async function refreshHistory() {
    setLoadingHistory(true);
    try {
      const res = await listEmailInvestigationHistory({ limit: 20, offset: 0 });
      setHistoryItems((res?.items || []) as EmailInvestigationHistoryItem[]);
    } catch {
      // Keep page usable even if history fetch fails.
    } finally {
      setLoadingHistory(false);
    }
  }

  useEffect(() => {
    refreshHistory();
  }, []);

  async function openHistoryItem(id: string) {
    setLoadingHistoryItemId(id);
    setSelectedHistoryId(id);
    setError("");
    try {
      const item = await getEmailInvestigationHistoryItem(id);
      setResult(item as EmailInvestigationResponse);
    } catch (err: any) {
      setError(err?.message || "Failed to load history item");
    } finally {
      setLoadingHistoryItemId(null);
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setLoadingStartedAt(Date.now());
    setError("");
    setResult(null);
    try {
      const submit = (await uploadEmailInvestigation(file, {
        context: context || undefined,
        max_urls: 20,
        include_url_screenshots: includeScreenshots,
        run_ai: runAiInterpretation,
        ml_phishing_score: mlScore.trim() ? Number(mlScore) : undefined,
      })) as EmailInvestigationSubmitResponse;
      setSelectedHistoryId(submit.run_id || null);

      const pollDeadline = Date.now() + 15 * 60 * 1000;
      let completedRun: EmailInvestigationResponse | null = null;
      while (Date.now() < pollDeadline) {
        const run = (await getEmailInvestigationRun(submit.run_id)) as EmailInvestigationResponse;
        if (run.status === "completed") {
          completedRun = run;
          setResult(run);
          break;
        }
        if (run.status === "failed") {
          throw new Error(run.error || "Email investigation failed");
        }
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      if (!completedRun) {
        const latest = (await getEmailInvestigationRun(submit.run_id)) as EmailInvestigationResponse;
        if (latest.status === "completed") {
          setResult(latest);
        } else {
          throw new Error("Email investigation is still processing. Please refresh history shortly.");
        }
      }

      await refreshHistory();
    } catch (err: any) {
      setError(err?.message || "Upload failed");
    } finally {
      setLoading(false);
      setLoadingStartedAt(null);
    }
  }

  return (
    <div style={{ paddingTop: 24, paddingBottom: 48 }}>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8, color: "var(--text)" }}>
        Email Investigation
      </h1>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginBottom: 20 }}>
        Upload an <code>.eml</code> or <code>.msg</code> file to extract indicators, run investigations, and generate a structured SOC resolution.
      </p>

      <div
        style={{
          background: "linear-gradient(180deg, rgba(96,165,250,0.08), rgba(16,185,129,0.03))",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          padding: 14,
          marginBottom: 18,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 700 }}>
            Email Investigation History
          </div>
          <button
            type="button"
            onClick={refreshHistory}
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
              borderRadius: "var(--radius)",
              fontSize: 11,
              padding: "6px 10px",
              cursor: "pointer",
            }}
          >
            {loadingHistory ? "Refreshing..." : "Refresh"}
          </button>
        </div>
        {!historyItems.length ? (
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No previous email investigations yet.</div>
        ) : (
          <div style={{ display: "grid", gap: 8, maxHeight: 220, overflowY: "auto", paddingRight: 4 }}>
            {historyItems.map((h) => (
              <button
                key={h.id}
                type="button"
                onClick={() => openHistoryItem(h.id)}
                disabled={!!loadingHistoryItemId}
                style={{
                  textAlign: "left",
                  background: selectedHistoryId === h.id ? "rgba(96,165,250,0.12)" : "var(--bg-card)",
                  border: selectedHistoryId === h.id ? "1px solid rgba(96,165,250,0.35)" : "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  padding: 10,
                  cursor: "pointer",
                }}
              >
                <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 600, marginBottom: 3 }}>
                  {h.email_subject || h.filename || "No subject"}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  {h.sender_email || "Unknown sender"} | URLs: {h.urls_count} | Attachments: {h.attachments_count} | Status: {h.status || "unknown"}
                </div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
                  {h.created_at ? new Date(h.created_at).toLocaleString() : "Unknown time"}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      <form
        onSubmit={onSubmit}
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          padding: 16,
          marginBottom: 20,
          display: "grid",
          gap: 12,
        }}
      >
        <input
          type="file"
          accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          style={{ fontSize: 13, color: "var(--text-dim)" }}
        />
        <textarea
          placeholder="Optional investigation context"
          value={context}
          onChange={(e) => setContext(e.target.value)}
          rows={3}
          style={{
            width: "100%",
            resize: "vertical",
            background: "var(--bg-input)",
            border: "1px solid var(--border)",
            color: "var(--text)",
            borderRadius: "var(--radius)",
            padding: 10,
            fontSize: 13,
          }}
        />
        <input
          type="number"
          min="0"
          max="1"
          step="0.001"
          placeholder="Optional ML phishing score (0.000 - 1.000)"
          value={mlScore}
          onChange={(e) => setMlScore(e.target.value)}
          style={{
            background: "var(--bg-input)",
            border: "1px solid var(--border)",
            color: "var(--text)",
            borderRadius: "var(--radius)",
            padding: 10,
            fontSize: 13,
          }}
        />
        <label style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-dim)", fontSize: 12 }}>
          <input
            type="checkbox"
            checked={includeScreenshots}
            onChange={(e) => setIncludeScreenshots(e.target.checked)}
          />
          Capture screenshot for each URL destination (slower)
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-dim)", fontSize: 12 }}>
          <input
            type="checkbox"
            checked={runAiInterpretation}
            onChange={(e) => setRunAiInterpretation(e.target.checked)}
          />
          AI interpretation (GPT-5 mini) - higher cost
        </label>
        <button
          type="submit"
          disabled={!file || loading}
          style={{
            background: "linear-gradient(135deg,#60a5fa,#818cf8)",
            border: "none",
            color: "#fff",
            borderRadius: "var(--radius)",
            fontSize: 13,
            fontWeight: 700,
            padding: "10px 14px",
            cursor: !file || loading ? "not-allowed" : "pointer",
            opacity: !file || loading ? 0.65 : 1,
          }}
        >
          {loading ? "Running investigation..." : "Upload and Analyze"}
        </button>
      </form>

      {error && (
        <div style={{ color: "#f87171", marginBottom: 16, fontSize: 13 }}>
          {error}
        </div>
      )}

      {loading && (
        <div
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
            marginBottom: 16,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>Investigation Progress</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {progressModel.percent}% · {loadingElapsedSec}s
            </span>
          </div>
          <div style={{ height: 10, background: "var(--bg-input)", borderRadius: 999, overflow: "hidden", border: "1px solid var(--border)" }}>
            <div
              style={{
                height: "100%",
                width: `${progressModel.percent}%`,
                background: "linear-gradient(90deg, var(--accent), #34d399)",
                transition: "width 300ms ease",
              }}
            />
          </div>
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text)" }}>{progressModel.stageText}</div>
          <div style={{ marginTop: 10, display: "grid", gap: 5 }}>
            {progressModel.steps.map((step, idx) => (
              <div
                key={step.key}
                style={{
                  fontSize: 12,
                  color: idx < progressModel.activeIndex ? "var(--green)" : idx === progressModel.activeIndex ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                {idx < progressModel.activeIndex ? "[x]" : idx === progressModel.activeIndex ? "[>]" : "[ ]"} {step.label}
              </div>
            ))}
          </div>
        </div>
      )}

      {result && (
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>Summary</div>
            <div style={{ color: "var(--text)", fontSize: 13 }}>
              Subject: <b>{result.email_subject || "N/A"}</b>
            </div>
            <div style={{ color: "var(--text-dim)", fontSize: 12, marginTop: 6 }}>
              Sender: {result.sender_email || "N/A"} | Sender Domain: {result.sender_domain || "N/A"} | Sender IP: {result.sender_ip || "N/A"}
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                URLs: {result.urls_count}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                Attachments: {result.attachments_count}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 999, padding: "4px 8px" }}>
                Resolution: {result.resolution_source}
              </span>
            </div>
          </div>

          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>Indicator Checks</div>
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                Sender domain: {result?.indicator_checks?.sender_domain?.domain || result.sender_domain || "Not present in the provided evidence."}
                {" | "}
                WHOIS registrar: {result?.indicator_checks?.sender_domain?.whois?.registrar || "N/A"}
                {" | "}
                Age days: {result?.indicator_checks?.sender_domain?.whois?.domain_age_days ?? "N/A"}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                WHOIS statuses: {(result?.indicator_checks?.sender_domain?.whois?.statuses || []).length
                  ? (result?.indicator_checks?.sender_domain?.whois?.statuses || []).join(", ")
                  : "Not present in the provided evidence."}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                IP: {result?.indicator_checks?.sender_ip?.ip || "Not present in the provided evidence."}
                {" | "}
                VT malicious/suspicious: {result?.indicator_checks?.sender_ip?.vt?.malicious_count ?? 0}/{result?.indicator_checks?.sender_ip?.vt?.suspicious_count ?? 0}
                {" | "}
                AbuseIPDB score: {result?.indicator_checks?.sender_ip?.abuseipdb?.abuse_confidence_score ?? "N/A"}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                Attachments checked: {result?.indicator_checks?.attachments?.items?.length || 0}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                URLs checked: {result?.indicator_checks?.urls?.length || 0}
              </div>
            </div>
          </div>

          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>Attachment Hash Checks</div>
            {!result?.indicator_checks?.attachments?.items?.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No attachments found.</div>
            ) : (
              <div style={{ display: "grid", gap: 10 }}>
                {result.indicator_checks.attachments.items.map((a: any, idx: number) => (
                  <div key={idx} style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 10 }}>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>
                      File: {a?.filename || "unnamed_attachment"} ({a?.size_bytes ?? 0} bytes)
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)", marginBottom: 4, wordBreak: "break-all" }}>
                      SHA256: {a?.sha256 || "Not present in the provided evidence."}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)", marginBottom: 6, wordBreak: "break-all" }}>
                      MD5: {a?.md5 || "Not present in the provided evidence."}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                      VT verdict: {a?.vt?.verdict || "unknown"} (m={a?.vt?.malicious_count ?? 0}, s={a?.vt?.suspicious_count ?? 0}, total={a?.vt?.total_vendors ?? 0})
                    </div>
                    {a?.vt?.error && (
                      <div style={{ fontSize: 11, color: "#f87171", marginTop: 4 }}>
                        VT error: {a.vt.error}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--accent)",
              letterSpacing: "0.01em",
              marginBottom: 14,
              paddingBottom: 8,
              borderBottom: "1px solid var(--border)",
            }}>
              Analyst Findings (Template Output)
            </div>
            <div
              style={{
                marginBottom: 12,
                padding: "12px 14px",
                background: "var(--bg-input)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
                fontSize: 12,
                lineHeight: 1.7,
                whiteSpace: "pre-wrap",
                color: "var(--text-secondary)",
              }}
            >
              {result?.resolution?.formatted_resolution || "Not present in the provided evidence."}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Supporting evidence details
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
              <span
                style={{
                  fontSize: 11,
                  color:
                    (result?.resolution?.sender_domain_analysis?.classification || "unknown") === "malicious"
                      ? "#ef4444"
                      : (result?.resolution?.sender_domain_analysis?.classification || "unknown") === "suspicious"
                        ? "#f59e0b"
                        : (result?.resolution?.sender_domain_analysis?.classification || "unknown") === "benign"
                          ? "#34d399"
                          : "var(--text-secondary)",
                  border: "1px solid var(--border)",
                  borderRadius: 999,
                  padding: "4px 8px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                }}
              >
                {(result?.resolution?.sender_domain_analysis?.classification || "unknown")}
              </span>
            </div>
            {!domainFindings.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No sender-domain findings returned.</div>
            ) : (
              <div style={{ display: "grid", gap: 8 }}>
                {domainFindings.map((f: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      padding: "14px 16px",
                      background: "var(--bg-input)",
                      border: "1px solid var(--border)",
                      borderRadius: "var(--radius)",
                      borderLeft: `3px solid ${findingSeverityColor(f?.severity)}`,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, gap: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            borderRadius: 999,
                            padding: "2px 8px",
                            color: findingSeverityColor(f?.severity),
                            background: "rgba(96,165,250,0.10)",
                            textTransform: "uppercase",
                          }}
                        >
                          {(f?.severity || "info").toUpperCase()}
                        </span>
                        <div style={{ fontSize: 13, color: "var(--text)", fontWeight: 700 }}>
                          {f?.title || "Untitled finding"}
                        </div>
                      </div>
                      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
                        Sender Domain
                      </div>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                      {f?.description || "Not present in the provided evidence."}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div
              style={{
                marginTop: 10,
                padding: "12px 14px",
                background: "var(--bg-input)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
              }}
            >
              <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>
                URL Summary
              </div>
              <div style={{ display: "grid", gap: 8 }}>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>
                    Overview
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                    {urlSummary.overview}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>
                    Likely Purpose
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                    {urlSummary.purpose.length ? (
                      <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                        {urlSummary.purpose.map((p, i) => (
                          <li key={i}>{p}</li>
                        ))}
                      </ul>
                    ) : (
                      "Not present in the provided evidence."
                    )}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>
                    Destinations
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                    {urlSummary.destinations.length ? (
                      <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                        {urlSummary.destinations.map((d, i) => (
                          <li key={i} style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{d}</li>
                        ))}
                      </ul>
                    ) : (
                      "Not present in the provided evidence."
                    )}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 2 }}>
                    Caution
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                    {urlSummary.caution.length ? (
                      <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                        {urlSummary.caution.map((d, i) => (
                          <li key={i} style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{d}</li>
                        ))}
                      </ul>
                    ) : (
                      "No suspicious or malicious URL destinations identified by VirusTotal."
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: 16,
          }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>URL Reputation and Destination</div>
            {!result?.indicator_checks?.urls?.length ? (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No URLs found.</div>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {result.indicator_checks.urls.map((u: any, idx: number) => {
                  const finalUrl = u?.screenshot?.final_url || "Not present in the provided evidence.";
                  return (
                  <div key={idx} style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 10 }}>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
                      URL: {u.url}
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 8, marginBottom: 8 }}>
                      <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 8, background: "rgba(96,165,250,0.08)" }}>
                        <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>
                          VT verdict
                        </div>
                        <div style={{
                          fontSize: 12,
                          fontWeight: 700,
                          color:
                            (u?.vt?.verdict || "unknown") === "malicious"
                              ? "#ef4444"
                              : (u?.vt?.verdict || "unknown") === "suspicious"
                                ? "#f59e0b"
                                : (u?.vt?.verdict || "unknown") === "clean"
                                  ? "#34d399"
                                  : "var(--text)",
                        }}>
                          {(u?.vt?.verdict || "unknown").toUpperCase()}
                        </div>
                        <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 4 }}>
                          m={u?.vt?.malicious_count ?? 0}, s={u?.vt?.suspicious_count ?? 0}, total={u?.vt?.total_vendors ?? 0}
                        </div>
                      </div>
                      <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 8, background: "rgba(16,185,129,0.05)" }}>
                        <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>
                          Final URL
                        </div>
                        <div style={{ fontSize: 11, color: "var(--text)", wordBreak: "break-all", fontFamily: "var(--font-mono)" }}>
                          {finalUrl}
                        </div>
                      </div>
                    </div>
                    {u?.screenshot?.image_base64 ? (
                      <img
                        src={`data:image/png;base64,${u.screenshot.image_base64}`}
                        alt={`URL screenshot ${idx + 1}`}
                        style={{ maxWidth: "100%", borderRadius: 6, border: "1px solid var(--border)" }}
                      />
                    ) : (
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        Screenshot unavailable: {u?.screenshot?.error || "Not present in the provided evidence."}
                      </div>
                    )}
                  </div>
                )})}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function findingSeverityColor(severity?: string): string {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "#ef4444";
  if (s === "medium") return "#f59e0b";
  if (s === "low") return "#60a5fa";
  return "#94a3b8";
}

function buildSenderDomainFindings(
  result: EmailInvestigationResponse | null,
): Array<{ title: string; severity: string; description: string }> {
  const aiFindings = result?.resolution?.sender_domain_analysis?.findings;
  if (Array.isArray(aiFindings) && aiFindings.length > 0) {
    return aiFindings.map((f: any) => ({
      title: String(f?.title || "Untitled finding"),
      severity: String(f?.severity || "medium").toLowerCase(),
      description: String(f?.description || "Not present in the provided evidence."),
    }));
  }

  const domain = result?.sender_domain || result?.indicator_checks?.sender_domain?.domain || "Not present in the provided evidence.";
  const whois = result?.indicator_checks?.sender_domain?.whois || {};
  const registrar = whois?.registrar || "Not present in the provided evidence.";
  const ageDays = typeof whois?.domain_age_days === "number" ? String(whois.domain_age_days) : "Not present in the provided evidence.";
  const statuses = Array.isArray(whois?.statuses) && whois.statuses.length
    ? whois.statuses.join(", ")
    : "Not present in the provided evidence.";
  const suspiciousUrls = (result?.indicator_checks?.urls || []).filter(
    (u: any) => ["malicious", "suspicious"].includes(String(u?.vt?.verdict || "").toLowerCase()),
  ).length;

  const fallback: Array<{ title: string; severity: string; description: string }> = [
    {
      title: "Sender domain registration context",
      severity: "low",
      description: `Domain: ${domain}. Registrar: ${registrar}. Domain age days: ${ageDays}. WHOIS statuses: ${statuses}.`,
    },
    {
      title: "Sender domain URL risk context",
      severity: suspiciousUrls > 0 ? "medium" : "low",
      description: `URLs analyzed: ${result?.urls_count ?? 0}. Suspicious/malicious URL verdicts: ${suspiciousUrls}.`,
    },
  ];
  return fallback;
}

function buildUrlSummary(result: EmailInvestigationResponse | null): {
  overview: string;
  purpose: string[];
  destinations: string[];
  caution: string[];
} {
  const urls = result?.indicator_checks?.urls || [];
  if (!urls.length) {
    return {
      overview: "No URLs were found in this email.",
      purpose: [],
      destinations: [],
      caution: [],
    };
  }

  const risky = urls.filter((u: any) => ["malicious", "suspicious"].includes(String(u?.vt?.verdict || "").toLowerCase()));
  const clean = urls.filter((u: any) => String(u?.vt?.verdict || "").toLowerCase() === "clean");
  const enriched = urls.map((u: any) => {
    const original = String(u?.url || "").trim();
    const finalUrl = String(u?.screenshot?.final_url || original).trim();
    const verdict = String(u?.vt?.verdict || "unknown").toLowerCase();
    return {
      original,
      finalUrl,
      verdict,
      purpose: inferUrlPurpose(original, finalUrl),
    };
  });

  const purposeCounts = new Map<string, number>();
  for (const item of enriched) {
    purposeCounts.set(item.purpose, (purposeCounts.get(item.purpose) || 0) + 1);
  }

  const purposeList = Array.from(purposeCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([purpose, count]) => `${count} ${count === 1 ? "URL appears to be" : "URLs appear to be"} ${purpose}.`);

  const topPoints = enriched
    .slice(0, 3)
    .map((u) => u.finalUrl)
    .filter(Boolean);

  const riskyList = enriched
    .filter((u) => u.verdict === "malicious" || u.verdict === "suspicious")
    .slice(0, 2)
    .map((u) => u.finalUrl)
    .filter(Boolean);

  return {
    overview: `Analyzed ${urls.length} URL(s): ${clean.length} clean and ${risky.length} suspicious/malicious by VirusTotal.`,
    purpose: purposeList,
    destinations: topPoints,
    caution: riskyList,
  };
}

function inferUrlPurpose(originalUrl: string, finalUrl: string): string {
  const info = parseUrlInfo(finalUrl || originalUrl);
  const host = info.host.toLowerCase();
  const path = info.path.toLowerCase();

  if (host.endsWith("j2.email")) {
    if (path.includes("/unsubscribe") || path.includes("unsubscribe")) {
      return "an email unsubscribe / recipient-preference link (j2.email infrastructure)";
    }
    if (path.startsWith("/t/")) {
      return "an email tracking or campaign-routing link (j2.email infrastructure)";
    }
    return "an email campaign infrastructure link (j2.email)";
  }

  if (host.endsWith("w3.org")) {
    if (path.endsWith(".dtd") || path.includes("/dtd/")) {
      return "a W3C XHTML/HTML DTD technical resource used by markup templates";
    }
    if (path.includes("/tr/")) {
      return "a W3C standards/specification reference page";
    }
    return "a W3C standards resource";
  }

  if (path.endsWith(".pdf")) return "a document/PDF download URL";
  if (path.endsWith(".xml")) return "an XML data/resource URL";
  if (path.includes("login") || path.includes("signin") || path.includes("auth")) {
    return "an authentication or account-access page";
  }
  return "a general web destination";
}

function parseUrlInfo(raw: string): { host: string; path: string } {
  try {
    const url = new URL(raw);
    return { host: url.hostname || "", path: url.pathname || "" };
  } catch {
    return { host: "", path: "" };
  }
}
