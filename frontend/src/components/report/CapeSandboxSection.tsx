"use client";

/**
 * CAPEv2 detonation for this investigation.
 *
 * The browser only ever talks to the Threat Analyzer backend: it holds no CAPE
 * URL and no CAPE token, and nothing rendered here carries either.
 *
 * Two halves, because they answer different questions and an analyst needs to
 * tell them apart:
 *
 * 1. **What CAPE already knows** — the collector's result for this observable,
 *    stored with the investigation. For a hash that is CAPE's own prior
 *    analysis; for a domain it is whether any sample detonated *here* reached
 *    out to it. "Consulted and found nothing" is a real finding and is shown,
 *    because silence would read as "not checked".
 * 2. **Detonation** — the asynchronous submit/poll workflow, which only exists
 *    once somebody has asked for one.
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
import type { CollectedEvidence } from "@/lib/types";

const POLL_MS = 6000;
// Roughly a minute of waiting for the worker to create an auto-queued
// analysis, then the panel settles on the manual offer.
const AUTO_START_POLLS = 10;

export default function CapeSandboxSection({
  investigationId,
  observableType,
  capeEvidence,
}: {
  investigationId?: string;
  observableType?: string | null;
  capeEvidence?: CollectedEvidence["cape"];
}) {
  const [analysis, setAnalysis] = useState<api.SandboxAnalysisResult | api.SandboxAnalysis | null>(null);
  const [result, setResult] = useState<api.SandboxReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [waited, setWaited] = useState(0);
  const timer = useRef<number | null>(null);

  // CAPE runs a file and fetches a URL, so both are submittable — they just
  // mean different things, and the confirmation says which.
  const kind = String(observableType || "").toLowerCase();
  const isUrlTarget = ["domain", "url"].includes(kind);
  const eligible = ["hash", "file", "domain", "url"].includes(kind);

  const load = useCallback(async () => {
    if (!investigationId) {
      setLoading(false);
      return null;
    }
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
  //
  // The exception is an eligible sample with no analysis yet: an uploaded file
  // has one queued by the worker moments after the page first loads, so a few
  // polls avoid showing "not been detonated" about a detonation already under
  // way. Bounded, or an observable CAPE will never analyse polls for ever.
  useEffect(() => {
    const status = analysis?.status;
    const moving = status && api.SANDBOX_ACTIVE_STATUSES.includes(status);
    const awaitingAutoStart = !analysis && eligible && waited < AUTO_START_POLLS;
    if (!moving && !awaitingAutoStart) return;

    timer.current = window.setTimeout(() => {
      if (!analysis) setWaited((n) => n + 1);
      load();
    }, POLL_MS);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [analysis, analysis?.status, eligible, waited, load]);

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

  const collectorReport = (capeEvidence?.report as api.SandboxReport | undefined) || null;

  return (
    <div style={{ display: "grid", gap: 14 }}>
      {error && <Banner tone="danger">{error}</Banner>}

      {/* Half one: what the collector found when this investigation ran. */}
      {capeEvidence && (
        <div style={{ display: "grid", gap: 10 }}>
          <SubHeading>What CAPE already knows</SubHeading>
          {collectorReport ? (
            <>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 20 }}>
                <Fact label="Verdict" value={<VerdictChip verdict={collectorReport.verdict || "unknown"} />} />
                <Fact
                  label="Malware score"
                  value={
                    collectorReport.malscore === null || collectorReport.malscore === undefined
                      ? <span style={{ color: "var(--text-muted)" }}>not scored</span>
                      : <strong style={{ color: "var(--text)" }}>{collectorReport.malscore.toFixed(1)} / 10</strong>
                  }
                />
                <Fact label="CAPE task" value={collectorReport.task_id ?? "—"} mono />
                {collectorReport.machine && <Fact label="Machine" value={collectorReport.machine} mono />}
              </div>
              <Result report={collectorReport} />
            </>
          ) : (
            <Muted>
              {capeEvidence.reason ||
                "The CAPE analyzer ran and returned no analysis for this observable."}
            </Muted>
          )}
        </div>
      )}

      {capeEvidence && <Divider />}

      {!analysis && (
        <div style={{ display: "grid", gap: 10 }}>
          <SubHeading>Detonation</SubHeading>
          <Muted>
            {!eligible
              ? "CAPE analyses files and URLs. There is nothing to submit for this observable."
              : waited < AUTO_START_POLLS && !isUrlTarget
              ? "Starting a sandbox analysis…"
              : isUrlTarget
              ? "This has not been detonated in the CAPE sandbox. CAPE can fetch it and run whatever it returns."
              : "This sample has not been detonated in the CAPE sandbox."}
          </Muted>
          {eligible && !confirming && (isUrlTarget || waited >= AUTO_START_POLLS) && (
            <button type="button" onClick={() => setConfirming(true)} disabled={busy} style={primaryButton(busy)}>
              {isUrlTarget ? "Detonate URL in sandbox" : "Submit to sandbox"}
            </button>
          )}
          {eligible && confirming && (
            <div style={{ display: "grid", gap: 8, border: "1px solid var(--status-warning)",
                          borderRadius: "var(--radius)", padding: "12px 14px" }}>
              <strong style={{ fontSize: 13, color: "var(--text)" }}>
                {isUrlTarget ? "Detonate this URL?" : "Detonate this sample?"}
              </strong>
              <p style={{ fontSize: 12, color: "var(--text-dim)", margin: 0, lineHeight: 1.5 }}>
                {isUrlTarget ? (
                  <>
                    CAPE will <strong>fetch this URL</strong> from an isolated Windows analysis machine
                    with internet access and execute whatever it returns. The site will see a real
                    visit from the sandbox. Analysis takes a few minutes and the result is evidence
                    for review, not an automatic verdict.
                  </>
                ) : (
                  <>
                    The file will be <strong>executed</strong> on an isolated Windows analysis machine with
                    internet access enabled, so it may contact its real infrastructure. Analysis takes a
                    few minutes and the result is evidence for review, not an automatic verdict.
                  </>
                )}
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
          <SubHeading>Detonation</SubHeading>
          <Header analysis={analysis} result={result} />

          {result && result.executed === false && (
            // Above the limitations, and in the danger tone: a score of zero
            // from a sample that never started is the absence of an analysis,
            // and reads as a clean result unless something says otherwise.
            <Banner tone="danger">
              <strong>The sample did not execute.</strong> This analysis is not
              evidence about the file — the score reflects an analysis that never
              ran, not a clean one. Re-run it, or check the guest image has a
              handler for this file type.
            </Banner>
          )}

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
      {analysis.target_kind === "url" && analysis.target_url && (
        <Fact label="URL analysed" value={analysis.target_url} mono />
      )}
      {analysis.reused_existing && <Fact label="Source" value="Existing CAPE analysis" />}
      {result?.machine && <Fact label="Machine" value={result.machine} mono />}
      {result?.package && <Fact label="Package" value={result.package} mono />}
      {result?.route && <Fact label="Network route" value={result.route} />}
      <Fact label="Submitted" value={formatWhen(analysis.submitted_at || analysis.created_at)} />
      {analysis.completed_at && <Fact label="Completed" value={formatWhen(analysis.completed_at)} />}
      {analysis.requested_by && <Fact label="Requested by" value={analysis.requested_by} />}
    </div>
  );
}

function Result({ report }: { report: api.SandboxReport }) {
  // Stored evidence can predate a schema change; a missing branch here would
  // throw and take the entire Technical Evidence tab with it.
  const network = report.network || ({} as api.SandboxReport["network"]);
  const behaviour = report.behaviour || ({} as api.SandboxReport["behaviour"]);
  const detections = report.detections || [];
  const signatures = report.signatures || [];
  const dropped = report.dropped_files || [];
  const configs = report.extracted_configs || [];
  const errors = report.errors || [];

  return (
    <div style={{ display: "grid", gap: 14 }}>
      {/* Survives a failed detonation: CAPE hashes and scans the file even when
          the guest never opens it, which is exactly when this is all there is. */}
      {(report.sha256 || report.ssdeep || report.tlsh || report.file_type) && (
        <Block title="File identity">
          <div style={{ display: "grid", gap: 4 }}>
            <IdRow label="Type" value={report.file_type} />
            <IdRow label="Size" value={report.file_size ? `${report.file_size.toLocaleString()} bytes` : null} />
            <IdRow label="SHA-256" value={report.sha256} mono />
            <IdRow label="MD5" value={report.md5} mono />
            <IdRow label="ssdeep" value={report.ssdeep} mono />
            <IdRow label="TLSH" value={report.tlsh} mono />
            <IdRow label="CRC32" value={report.crc32} mono />
            <IdRow label="ClamAV" value={report.clamav} />
          </div>
        </Block>
      )}

      {(report.yara_matches?.length ?? 0) > 0 && (
        <Block title={`YARA matches (${report.yara_matches!.length})`}>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
            {report.yara_matches!.map((y) => (
              <li key={y.name} style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text)", fontFamily: "var(--font-mono)" }}>{y.name}</strong>
                {y.description ? ` — ${y.description}` : ""}
                {y.author && <span style={{ color: "var(--text-muted)" }}> · {y.author}</span>}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {detections.length > 0 && (
        <Block title="Detections">
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {detections.map((d) => (
              <span key={d} style={chip("var(--status-danger)")}>{d}</span>
            ))}
          </div>
        </Block>
      )}

      {signatures.length > 0 && (
        <Block title={`Behavioural signatures (${signatures.length})`}>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
            {signatures.slice(0, 15).map((s) => (
              <li key={s.name} style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text)" }}>{s.name}</strong>
                {s.description ? ` — ${s.description}` : ""}
                {s.ttps.length > 0 && (
                  <span style={{ color: "var(--text-muted)" }}> [{s.ttps.join(", ")}]</span>
                )}
                {/* What it actually matched. Without this a signature reads as
                    a category rather than a finding. */}
                {(s.details?.length ?? 0) > 0 && (
                  <ul style={{ margin: "3px 0 0", paddingLeft: 16 }}>
                    {s.details!.slice(0, 6).map((d, j) => (
                      <li key={j} style={{ fontSize: 11.5, color: "var(--text-muted)",
                                           fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                        {d}
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {((network.domains?.length || 0) > 0 || (network.destinations?.length || 0) > 0) && (
        <Block title="Network">
          <ListRow label="Contacted domains" values={network.domains} />
          <ListRow label="DNS queries" values={network.dns_queries} />
          <ListRow label="Destinations" values={network.destinations} />
          <ListRow label="TLS SNI" values={network.tls_sni} />
          {(network.http_requests?.length || 0) > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={labelStyle}>HTTP requests</div>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                {(network.http_requests || []).slice(0, 25).map((r, i) => (
                  <li key={i} style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                    {r.method} {r.host}{r.uri}{r.status ? ` → ${r.status}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Block>
      )}

      {(behaviour.process_count || 0) > 0 && (
        <Block title={`Behaviour (${behaviour.process_count} processes)`}>
          {/* The tree itself, which was collected and normalized but never
              drawn — the Behaviour block showed only the flat lists. */}
          {(behaviour.process_tree?.length ?? 0) > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={labelStyle}>Process tree</div>
              <div style={{ marginTop: 4 }}>
                <ProcessNodes nodes={behaviour.process_tree as ProcessNode[]} depth={0} />
              </div>
            </div>
          )}
          <ListRow label="Commands" values={behaviour.commands} mono />
          <ListRow label="Mutexes" values={behaviour.mutexes} mono />
          <ListRow label="Files written" values={behaviour.files_written} mono />
          <ListRow label="Registry" values={behaviour.registry_keys} mono />
        </Block>
      )}

      {dropped.length > 0 && (
        <Block title={`Dropped and extracted files (${dropped.length})`}>
          <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 3 }}>
            {dropped.slice(0, 15).map((f, i) => (
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

      {configs.length > 0 && (
        <Block title="Extracted configuration">
          <pre style={{ margin: 0, fontSize: 11.5, fontFamily: "var(--font-mono)", color: "var(--text-secondary)",
                        whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 260, overflow: "auto" }}>
            {JSON.stringify(configs, null, 2)}
          </pre>
        </Block>
      )}

      {errors.length > 0 && (
        <Block title="What CAPE reported going wrong">
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {errors.map((e, i) => (
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
      // Not muted grey: unknown here usually means the sample never ran, and a
      // faint pill reads as "nothing to see".
      : "var(--status-warning)";
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

interface ProcessNode {
  name: string;
  pid?: number | null;
  command_line?: string;
  children?: ProcessNode[];
}

function ProcessNodes({ nodes, depth }: { nodes: ProcessNode[]; depth: number }) {
  // Indented rather than a drawn graph: the shape is what matters — what
  // spawned what — and six levels of nesting still fits a report column.
  if (!nodes?.length || depth > 6) return null;
  return (
    <div style={{ display: "grid", gap: 2, paddingLeft: depth ? 14 : 0,
                  borderLeft: depth ? "1px solid var(--border)" : undefined }}>
      {nodes.map((node, i) => (
        <div key={`${node.pid ?? "?"}-${i}`}>
          <div style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
            <span style={{ color: "var(--text)" }}>{node.name || "unknown"}</span>
            {node.pid !== null && node.pid !== undefined && (
              <span style={{ color: "var(--text-muted)" }}> (pid {node.pid})</span>
            )}
          </div>
          {node.command_line && (
            <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
                          wordBreak: "break-all", paddingLeft: 8 }}>
              {node.command_line}
            </div>
          )}
          <ProcessNodes nodes={node.children || []} depth={depth + 1} />
        </div>
      ))}
    </div>
  );
}

function IdRow({ label, value, mono }: { label: string; value?: string | number | null; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div style={{ display: "flex", gap: 10, fontSize: 12 }}>
      <span style={{ color: "var(--text-muted)", minWidth: 74 }}>{label}</span>
      <span style={{ color: "var(--text-secondary)", wordBreak: "break-all",
                     fontFamily: mono ? "var(--font-mono)" : undefined }}>
        {value}
      </span>
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

const LIST_PREVIEW = 20;

function ListRow({ label, values, mono }: { label: string; values?: string[]; mono?: boolean }) {
  // "+46 more" hid the ones an analyst was looking for, with no way to reach
  // them. The tail is one click away now, and stays collapsed by default so a
  // sample that contacted hundreds of hosts does not bury everything else.
  const [expanded, setExpanded] = useState(false);
  if (!values || values.length === 0) return null;
  const shown = expanded ? values : values.slice(0, LIST_PREVIEW);
  const hidden = values.length - shown.length;

  return (
    <div style={{ marginTop: 6 }}>
      <div style={labelStyle}>{label} ({values.length})</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 3, alignItems: "center" }}>
        {shown.map((v) => (
          <span key={v} style={{ ...chip("var(--border)"), color: "var(--text-secondary)",
                                 fontFamily: mono ? "var(--font-mono)" : undefined, maxWidth: "100%",
                                 overflow: "hidden", textOverflow: "ellipsis" }}>
            {v}
          </span>
        ))}
        {(hidden > 0 || expanded) && (
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            style={{ background: "none", border: "none", padding: 0, cursor: "pointer",
                     fontSize: 11, color: "var(--accent)", textDecoration: "underline" }}
          >
            {expanded ? "show fewer" : `show all ${values.length}`}
          </button>
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

function SubHeading({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em",
                  textTransform: "uppercase", color: "var(--text-dim)" }}>
      {children}
    </div>
  );
}

function Divider() {
  return <div style={{ height: 1, background: "var(--border)" }} />;
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
