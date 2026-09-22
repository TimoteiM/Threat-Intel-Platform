"use client";

/**
 * CAPEv2 detonation for this investigation.
 *
 * The browser only ever talks to the Threat Analyzer backend: it holds no CAPE
 * URL and no CAPE token, and nothing rendered here carries either.
 *
 * Submitting is a deliberate act with a confirmation, because it really does
 * execute the sample on a Windows VM with internet access. The panel then
 * polls our own API — never CAPE — until the analysis reaches a terminal
 * state.
 *
 * Two presentation rules carry over from the backend and matter more than they
 * look. A missing malscore renders as "not scored", never as zero: CAPE omits
 * it routinely, and a 0 would read as clean. And guest-image limitations (the
 * PDF case, where no reader is installed) are shown next to the verdict rather
 * than buried, because an empty report from a file that never opened looks
 * exactly like an empty report from one that did.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "@/lib/api";

const POLL_MS = 6000;

export default function CapeSandboxSection({
  investigationId,
  observableType,
}: {
  investigationId: string;
  observableType?: string | null;
}) {
  const [analysis, setAnalysis] = useState<api.SandboxAnalysisResult | api.SandboxAnalysis | null>(null);
  const [result, setResult] = useState<api.SandboxReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const timer = useRef<number | null>(null);

  const eligible = ["hash", "file"].includes(String(observableType || "").toLowerCase());

  const load = useCallback(async () => {
    try {
      const { items } = await api.listSandboxAnalyses({ investigation_id: investigationId, limit: 1 });
      const latest = items[0] ?? null;
      if (!latest) {
        setAnalysis(null);
        setResult(null);
        return null;
      }
      if (latest.status === "reported") {
        const full = await api.getSandboxResult(latest.id);
        setAnalysis(full);
        setResult(full.result ?? null);
        return full.status;
      }
      setAnalysis(latest);
      return latest.status;
    } catch (err) {
      setError(messageOf(err, "Could not load the sandbox analysis."));
      return null;
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    load();
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [load]);

  // Poll only while something is actually moving. A finished analysis is
  // finished; polling it forever would be a request per tab per six seconds.
  useEffect(() => {
    const status = analysis?.status;
    if (!status || !api.SANDBOX_ACTIVE_STATUSES.includes(status)) return;
    timer.current = window.setTimeout(load, POLL_MS);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [analysis?.status, load]);

  const submit = async (force = false) => {
    setBusy(true);
    setError(null);
    setConfirming(false);
    try {
      const created = await api.submitToSandbox({ investigation_id: investigationId, force_new: force });
      setAnalysis(created);
      setResult(null);
    } catch (err) {
      setError(messageOf(err, "Could not submit this sample to the sandbox."));
    } finally {
      setBusy(false);
    }
  };

  const retry = async () => {
    if (!analysis) return;
    setBusy(true);
    setError(null);
    try {
      setAnalysis(await api.retrySandboxAnalysis(analysis.id));
    } catch (err) {
      setError(messageOf(err, "Could not retry that analysis."));
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <Muted>Checking for a sandbox analysis…</Muted>;

  return (
    <div style={{ display: "grid", gap: 14 }}>
      {error && <Banner tone="danger">{error}</Banner>}

      {!analysis && (
        <div style={{ display: "grid", gap: 10 }}>
          <Muted>
            {eligible
              ? "This sample has not been detonated in the CAPE sandbox."
              : "CAPE detonates files. This observable is not a file or a hash, so there is nothing to submit — " +
                "any CAPE findings for it would appear because another detonated sample contacted it."}
          </Muted>
          {eligible && !confirming && (
            <button type="button" onClick={() => setConfirming(true)} disabled={busy} style={primaryButton(busy)}>
              Submit to sandbox
            </button>
          )}
          {eligible && confirming && (
            <div style={{ display: "grid", gap: 8, border: "1px solid var(--status-warning)",
                          borderRadius: "var(--radius)", padding: "12px 14px" }}>
              <strong style={{ fontSize: 13, color: "var(--text)" }}>Detonate this sample?</strong>
              <p style={{ fontSize: 12, color: "var(--text-dim)", margin: 0, lineHeight: 1.5 }}>
                The file will be <strong>executed</strong> on an isolated Windows analysis machine with
                internet access enabled, so it may contact its real infrastructure. Analysis takes a
                few minutes and the result is evidence for review, not an automatic verdict.
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <button type="button" onClick={() => submit(false)} disabled={busy} style={primaryButton(busy)}>
                  {busy ? "Submitting…" : "Yes, detonate it"}
                </button>
                <button type="button" onClick={() => setConfirming(false)} style={smallButton()}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {analysis && (
        <>
          <Header analysis={analysis} result={result} />

          {analysis.limitations?.length > 0 && (
            <Banner tone="warning">
              {analysis.limitations.map((note, i) => (
                <div key={i} style={{ marginTop: i ? 6 : 0 }}>{note}</div>
              ))}
            </Banner>
          )}

          {analysis.error && <Banner tone="danger">{analysis.error}</Banner>}

          {api.SANDBOX_ACTIVE_STATUSES.includes(analysis.status) && (
            <Muted>
              Analysis in progress — this updates on its own. CAPE typically takes a few minutes.
            </Muted>
          )}

          {["failed", "timed_out", "cancelled"].includes(analysis.status) && (
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" onClick={retry} disabled={busy} style={primaryButton(busy)}>
                {busy ? "Retrying…" : "Retry"}
              </button>
              <button type="button" onClick={() => submit(true)} disabled={busy} style={smallButton()}>
                Detonate again
              </button>
            </div>
          )}

          {result && <Result report={result} />}
        </>
      )}
    </div>
  );
}

function Header({
  analysis,
  result,
}: {
  analysis: api.SandboxAnalysis;
  result: api.SandboxReport | null;
}) {
  const score = analysis.malscore ?? result?.malscore ?? null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 20, alignItems: "flex-start" }}>
      <Fact label="Status" value={<StatusChip status={analysis.status} />} />
      <Fact label="Verdict" value={<VerdictChip verdict={analysis.verdict ?? result?.verdict ?? "unknown"} />} />
      <Fact
        label="Malware score"
        // Never render a missing score as 0 — CAPE omits it routinely and a
        // zero would read as "clean".
        value={score === null || score === undefined
          ? <span style={{ color: "var(--text-muted)" }}>not scored</span>
          : <strong style={{ color: "var(--text)" }}>{score.toFixed(1)} / 10</strong>}
      />
      <Fact label="CAPE task" value={analysis.provider_task_id ?? "—"} mono />
      {analysis.reused_existing && <Fact label="Source" value="Existing CAPE analysis" />}
      {result?.machine && <Fact label="Machine" value={result.machine} mono />}
      {result?.route && <Fact label="Network route" value={result.route} />}
      <Fact label="Submitted" value={formatWhen(analysis.submitted_at || analysis.created_at)} />
      {analysis.completed_at && <Fact label="Completed" value={formatWhen(analysis.completed_at)} />}
      {analysis.requested_by && <Fact label="Requested by" value={analysis.requested_by} />}
    </div>
  );
}

function Result({ report }: { report: api.SandboxReport }) {
  return (
    <div style={{ display: "grid", gap: 14 }}>
      {report.detections.length > 0 && (
        <Block title="Detections">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {report.detections.map((d) => (
              <span key={d} style={chip("var(--status-danger)")}>{d}</span>
            ))}
          </div>
        </Block>
      )}

      {report.signatures.length > 0 && (
        <Block title={`Behavioural signatures (${report.signatures.length})`}>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
            {report.signatures.slice(0, 15).map((s) => (
              <li key={s.name} style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text)" }}>{s.name}</strong>
                {s.description ? ` — ${s.description}` : ""}
                {s.ttps.length > 0 && (
                  <span style={{ color: "var(--text-muted)" }}> [{s.ttps.join(", ")}]</span>
                )}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {(report.network.domains.length > 0 || report.network.destinations.length > 0) && (
        <Block title="Network">
          <ListRow label="Contacted domains" values={report.network.domains} />
          <ListRow label="DNS queries" values={report.network.dns_queries} />
          <ListRow label="Destinations" values={report.network.destinations} />
          <ListRow label="TLS SNI" values={report.network.tls_sni} />
          {report.network.http_requests.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={labelStyle}>HTTP requests</div>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                {report.network.http_requests.slice(0, 10).map((r, i) => (
                  <li key={i} style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                    {r.method} {r.host}{r.uri}{r.status ? ` → ${r.status}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Block>
      )}

      {report.behaviour.process_count > 0 && (
        <Block title={`Behaviour (${report.behaviour.process_count} processes)`}>
          <ListRow label="Commands" values={report.behaviour.commands} mono />
          <ListRow label="Mutexes" values={report.behaviour.mutexes} mono />
          <ListRow label="Files written" values={report.behaviour.files_written} mono />
          <ListRow label="Registry" values={report.behaviour.registry_keys} mono />
        </Block>
      )}

      {report.dropped_files.length > 0 && (
        <Block title={`Dropped and extracted files (${report.dropped_files.length})`}>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 3 }}>
            {report.dropped_files.slice(0, 15).map((f, i) => (
              <li key={i} style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                <span style={{ fontFamily: "var(--font-mono)" }}>{f.name || f.sha256?.slice(0, 16)}</span>
                {f.file_type ? ` — ${f.file_type}` : ""}
                {f.is_cape_payload && (
                  <span style={{ color: "var(--status-warning)" }}>
                    {" "}· CAPE payload{f.cape_type ? ` (${f.cape_type})` : ""}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {report.extracted_configs.length > 0 && (
        <Block title="Extracted configuration">
          <pre style={{ margin: 0, fontSize: 11.5, fontFamily: "var(--font-mono)", color: "var(--text-secondary)",
                        whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 260, overflow: "auto" }}>
            {JSON.stringify(report.extracted_configs, null, 2)}
          </pre>
        </Block>
      )}

      {report.errors.length > 0 && (
        <Block title="Analysis errors">
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {report.errors.map((e, i) => (
              <li key={i} style={{ fontSize: 12, color: "var(--status-warning)" }}>{e}</li>
            ))}
          </ul>
        </Block>
      )}
    </div>
  );
}

// ── small pieces ─────────────────────────────────────────────────────────────

function StatusChip({ status }: { status: string }) {
  const colour =
    status === "reported" ? "var(--status-success)"
      : ["failed", "timed_out", "cancelled"].includes(status) ? "var(--status-danger)"
      : "var(--status-warning)";
  return <span style={chip(colour)}>{status.replace("_", " ")}</span>;
}

function VerdictChip({ verdict }: { verdict: string }) {
  const colour =
    verdict === "malicious" ? "var(--status-danger)"
      : verdict === "suspicious" ? "var(--status-warning)"
      : verdict === "likely_benign" ? "var(--status-success)"
      : "var(--text-muted)";
  return <span style={chip(colour)}>{verdict.replace("_", " ")}</span>;
}

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div style={labelStyle}>{label}</div>
      <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 2,
                    fontFamily: mono ? "var(--font-mono)" : undefined }}>
        {value}
      </div>
    </div>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "12px 14px" }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text)", marginBottom: 8 }}>{title}</div>
      {children}
    </div>
  );
}

function ListRow({ label, values, mono }: { label: string; values: string[]; mono?: boolean }) {
  if (!values || values.length === 0) return null;
  return (
    <div style={{ marginTop: 6 }}>
      <div style={labelStyle}>{label} ({values.length})</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 3 }}>
        {values.slice(0, 20).map((v) => (
          <span key={v} style={{ ...chip("var(--border)"), color: "var(--text-secondary)",
                                 fontFamily: mono ? "var(--font-mono)" : undefined, maxWidth: "100%",
                                 overflow: "hidden", textOverflow: "ellipsis" }}>
            {v}
          </span>
        ))}
        {values.length > 20 && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>+{values.length - 20} more</span>
        )}
      </div>
    </div>
  );
}

function Banner({ tone, children }: { tone: "warning" | "danger"; children: React.ReactNode }) {
  const colour = tone === "danger" ? "var(--status-danger)" : "var(--status-warning)";
  return (
    <div role={tone === "danger" ? "alert" : undefined}
         style={{ fontSize: 12, color: colour, border: `1px solid ${colour}`,
                  borderRadius: "var(--radius)", padding: "8px 10px", lineHeight: 1.5 }}>
      {children}
    </div>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <p style={{ fontSize: 12.5, color: "var(--text-dim)", margin: 0, lineHeight: 1.5 }}>{children}</p>;
}

const labelStyle: React.CSSProperties = {
  fontSize: 10.5,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  color: "var(--text-muted)",
};

function chip(colour: string): React.CSSProperties {
  return {
    display: "inline-block",
    padding: "2px 8px",
    borderRadius: 999,
    border: `1px solid ${colour}`,
    color: colour,
    fontSize: 11,
    fontWeight: 600,
    whiteSpace: "nowrap",
  };
}

function primaryButton(busy: boolean): React.CSSProperties {
  return {
    padding: "8px 14px",
    borderRadius: "var(--radius)",
    border: "1px solid var(--shell-accent)",
    background: busy ? "var(--bg-elevated)" : "var(--shell-accent)",
    color: busy ? "var(--text-muted)" : "#fff",
    fontSize: 12,
    fontWeight: 600,
    cursor: busy ? "not-allowed" : "pointer",
    justifySelf: "start",
  };
}

function smallButton(): React.CSSProperties {
  return {
    padding: "8px 12px",
    borderRadius: "var(--radius)",
    border: "1px solid var(--border)",
    background: "transparent",
    color: "var(--text-secondary)",
    fontSize: 12,
    fontWeight: 600,
    cursor: "pointer",
  };
}

function formatWhen(value?: string | null): string {
  if (!value) return "—";
  const when = new Date(value);
  return Number.isNaN(when.getTime()) ? "—" : when.toLocaleString();
}

function messageOf(error: unknown, fallback: string): string {
  const raw = error instanceof Error ? error.message : "";
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed?.detail === "string") return parsed.detail;
  } catch {
    /* not JSON */
  }
  return raw && raw.length < 300 ? raw : fallback;
}
