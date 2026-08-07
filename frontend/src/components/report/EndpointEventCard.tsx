"use client";

/**
 * One endpoint (Sysmon/EDR) event from an alert body.
 *
 * The process story is the evidence here, so the card leads with what ran, as
 * whom, from where and under which parent — then the behaviour signals that
 * produced the verdict, each with the reason it matters.
 */

import React, { useState } from "react";

import type { AlertEndpointEventReport } from "@/lib/types";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
};

const SEVERITY_COLORS: Record<string, string> = {
  high: "#f87171",
  medium: "#fbbf24",
  low: "#60a5fa",
  info: "#94a3b8",
};

export default function EndpointEventCard({
  report,
  defaultOpen = false,
}: {
  report: AlertEndpointEventReport;
  defaultOpen?: boolean;
}) {
  const [showRaw, setShowRaw] = useState(defaultOpen);
  const event = report.event || {};
  const classification = report.verdict?.classification || "inconclusive";
  const color = VERDICT_COLORS[String(classification).toLowerCase()] || "#94a3b8";

  return (
    <div
      style={{
        border: "1px solid var(--panel-divider-strong)",
        borderRadius: 14,
        background: "var(--bg-elevated)",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "12px 14px",
          borderLeft: `3px solid ${color}`,
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            fontSize: 9,
            fontWeight: 800,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            padding: "3px 8px",
            borderRadius: 6,
            background: "rgba(139,92,246,0.14)",
            color: "#a78bfa",
            fontFamily: "var(--font-sans)",
          }}
        >
          {(event.type || "endpoint event").replace(/_/g, " ")}
        </span>
        <span
          style={{
            flex: 1,
            minWidth: 220,
            fontFamily: "var(--font-mono)",
            fontSize: 12.5,
            color: "var(--text)",
            overflowWrap: "anywhere",
          }}
        >
          {basename(event.image) || event.header || "Endpoint event"}
        </span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.05em",
            textTransform: "uppercase",
            color,
            fontFamily: "var(--font-sans)",
          }}
        >
          {classification}
        </span>
        <span style={{ fontSize: 13, fontWeight: 700, fontFamily: "var(--font-mono)", color }}>
          {report.verdict?.risk_score ?? 0}
        </span>
        <button
          onClick={() => setShowRaw((prev) => !prev)}
          style={{
            padding: "5px 10px",
            borderRadius: 8,
            border: "1px solid var(--border)",
            background: "var(--bg-input)",
            color: "var(--text-secondary)",
            fontSize: 10,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            cursor: "pointer",
          }}
        >
          {showRaw ? "Hide fields" : "All fields"}
        </button>
      </div>

      <div style={{ padding: "0 14px 12px 17px", display: "grid", gap: 10 }}>
        <Facts
          rows={[
            ["Process", event.image, true],
            ["Command line", event.command_line, true],
            ["Parent", event.parent_image, true],
            ["User", event.host_user, false],
            ["Integrity", event.integrity_level, false],
            ["Working dir", event.current_directory, true],
            ["PID", event.process_id ? `${event.process_id}${event.parent_process_id ? ` (parent ${event.parent_process_id})` : ""}` : "", false],
            ["When (UTC)", event.utc_time, false],
            ["SHA256", event.hashes?.sha256, true],
            ["IMPHASH", event.hashes?.imphash, true],
          ]}
        />

        {report.findings?.length ? (
          <div style={{ display: "grid", gap: 6 }}>
            {report.findings.map((finding, i) => (
              <div
                key={`${finding.summary}:${i}`}
                style={{
                  border: "1px solid var(--border)",
                  borderLeft: `3px solid ${SEVERITY_COLORS[finding.severity] || "#94a3b8"}`,
                  borderRadius: 8,
                  padding: "7px 10px",
                  background: "var(--bg-input)",
                }}
              >
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span
                    style={{
                      fontSize: 9,
                      fontWeight: 800,
                      letterSpacing: "0.05em",
                      textTransform: "uppercase",
                      color: SEVERITY_COLORS[finding.severity] || "#94a3b8",
                      fontFamily: "var(--font-sans)",
                    }}
                  >
                    {finding.severity}
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text)", fontFamily: "var(--font-sans)" }}>
                    {finding.summary}
                  </span>
                </div>
                {finding.data?.explanation && (
                  <div style={{ fontSize: 11.5, color: "var(--text-secondary)", marginTop: 3, lineHeight: 1.55, fontFamily: "var(--font-sans)" }}>
                    {String(finding.data.explanation)}
                  </div>
                )}
                {finding.data?.matched && (
                  <code style={{ display: "block", marginTop: 4, fontSize: 10.5, color: "var(--text-muted)", fontFamily: "var(--font-mono)", overflowWrap: "anywhere" }}>
                    matched: {String(finding.data.matched)}
                  </code>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: 11.5, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
            No behaviour signal matched this event — the process metadata is recorded for context.
          </div>
        )}

        {showRaw && (
          <pre
            style={{
              margin: 0,
              padding: "10px 12px",
              borderRadius: 8,
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              maxHeight: 320,
              overflow: "auto",
              fontSize: 11,
              lineHeight: 1.6,
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {JSON.stringify(event.fields || {}, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

function Facts({ rows }: { rows: [string, string | undefined, boolean][] }) {
  const visible = rows.filter(([, value]) => !!value);
  if (!visible.length) return null;
  return (
    <div style={{ display: "grid", gap: 3 }}>
      {visible.map(([label, value, mono]) => (
        <div key={label} style={{ display: "flex", gap: 10, fontSize: 11.5, lineHeight: 1.6 }}>
          <span style={{ color: "var(--text-muted)", minWidth: 96, flexShrink: 0, fontFamily: "var(--font-sans)" }}>
            {label}
          </span>
          <span
            style={{
              color: "var(--text-secondary)",
              fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
              overflowWrap: "anywhere",
            }}
          >
            {value}
          </span>
        </div>
      ))}
    </div>
  );
}

function basename(path?: string): string {
  if (!path) return "";
  return path.split(/[\\/]/).pop() || path;
}
