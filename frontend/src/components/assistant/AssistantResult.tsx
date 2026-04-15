"use client";

import React from "react";
import * as api from "@/lib/api";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid from "@/components/ui/MetadataGrid";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";
import type { AssistantSessionDetail } from "@/lib/types";

const CATEGORY_LABELS: Record<string, string> = {
  EMAIL: "Emails",
  IP: "IP Addresses",
  HOST: "Hostnames",
  SID: "SIDs",
  ACCOUNT: "Accounts",
};

function buildSanitizationDetails(session: AssistantSessionDetail): Record<string, string[]> {
  const merged: Record<string, string> = {};
  for (const entry of session.entries ?? []) {
    Object.assign(merged, entry.token_map_json ?? {});
  }

  const grouped: Record<string, string[]> = {};
  for (const [token, original] of Object.entries(merged)) {
    const match = token.match(/^\[([A-Z]+)_\d+\]$/);
    if (!match) continue;
    const prefix = match[1];
    if (!grouped[prefix]) grouped[prefix] = [];
    if (!grouped[prefix].includes(original)) grouped[prefix].push(original);
  }
  return grouped;
}

export default function AssistantResult({
  session,
}: {
  session: AssistantSessionDetail | null;
}) {
  if (!session) {
    return (
      <EmptyState
        title="No assistant session selected"
        description="Choose a session from the list or create a new one to review sanitization and the generated report."
      />
    );
  }

  const sanitizationDetails = buildSanitizationDetails(session);
  const hasDetails = Object.keys(sanitizationDetails).length > 0;
  const sanitizedValueCount = Object.values(sanitizationDetails).reduce((sum, values) => sum + values.length, 0);
  const statusTone = sessionTone(session.status, session.error);
  const exportUrl = api.getAssistantExportUrl(session.id);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <ConsoleModule
        eyebrow="Assistant Session"
        title={session.title || "Untitled session"}
        description="A sanitized analyst workspace that keeps redacted values visible without exposing the original evidence."
        tone={statusTone}
        compact
        actions={
          <StatusPill tone={statusTone} outline>
            {session.status}
          </StatusPill>
        }
        footer={
          <MetadataGrid
            compact
            columns={2}
            items={[
              { label: "Mode", value: modeLabel(session.mode), tone: "info" },
              { label: "Source Type", value: session.source_type || "-", tone: "neutral" },
              { label: "Linked Investigation", value: session.linked_investigation_id || "-", tone: "neutral", mono: true },
              { label: "Updated", value: formatTimestamp(session.updated_at || session.completed_at || session.created_at), tone: "neutral" },
            ]}
          />
        }
      >
        <div style={{ display: "grid", gap: 14 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
            <SignalCard
              label="Entries"
              value={session.entries?.length ?? 0}
              caption="Raw input blocks captured in the session."
              tone="info"
              compact
            />
            <SignalCard
              label="Sanitized Values"
              value={sanitizedValueCount}
              caption="Total redacted tokens preserved in the map."
              tone="success"
              compact
            />
            <SignalCard
              label="Redaction Groups"
              value={Object.keys(sanitizationDetails).length || 0}
              caption="Email, IP, hostname, account, and SID clusters."
              tone="neutral"
              compact
            />
          </div>

          {session.error ? (
            <div style={errorBannerStyle}>
              <StatusPill tone="danger" outline>
                Error
              </StatusPill>
              <div style={{ fontSize: 13, lineHeight: 1.7 }}>{session.error}</div>
            </div>
          ) : null}
        </div>
      </ConsoleModule>

      <ConsoleModule
        eyebrow="Sanitization Summary"
        title="What was redacted"
        description="The assistant keeps the original values grouped by token family so analysts can understand what was removed."
        tone="info"
        compact
      >
        {hasDetails ? (
          <div style={{ display: "grid", gap: 12 }}>
            {Object.entries(sanitizationDetails).map(([prefix, values]) => (
              <MetadataGrid
                key={prefix}
                compact
                columns={1}
                items={[
                  {
                    label: `${CATEGORY_LABELS[prefix] ?? prefix} (${values.length})`,
                    value: <WrappedPills values={values} />,
                  },
                ]}
              />
            ))}
          </div>
        ) : (
          <div style={emptySanitizationStyle}>
            <pre style={preStyle}>{JSON.stringify(session.sanitization_summary_json || {}, null, 2)}</pre>
          </div>
        )}
      </ConsoleModule>

      <ConsoleModule
        eyebrow="Generated Report"
        title="Assistant output"
        description="Export the markdown report or review the generated content directly in the workspace."
        tone="neutral"
        compact
        actions={
          <a href={exportUrl} style={exportLinkStyle}>
            Export
          </a>
        }
      >
        <div style={reportSurfaceStyle}>
          <pre style={preStyle}>{session.report_markdown || "Run the assistant to generate a report."}</pre>
        </div>
      </ConsoleModule>
    </div>
  );
}

function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <ConsoleModule eyebrow="Assistant Output" title={title} description={description} tone="neutral" compact>
      <div style={{ color: "var(--text-dim)", fontSize: 13, lineHeight: 1.7 }}>
        Session output will appear here after you create or select a session.
      </div>
    </ConsoleModule>
  );
}

function WrappedPills({ values }: { values: string[] }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {values.map((value) => (
        <StatusPill key={value} tone="info" outline size="sm" mono>
          {value}
        </StatusPill>
      ))}
    </div>
  );
}

function sessionTone(status: AssistantSessionDetail["status"], error?: string | null) {
  if (error) return "danger";
  if (status === "completed") return "success";
  if (status === "processing") return "warning";
  if (status === "failed") return "danger";
  return "info";
}

function modeLabel(mode: string) {
  return mode
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatTimestamp(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

const errorBannerStyle: React.CSSProperties = {
  display: "flex",
  gap: 10,
  alignItems: "flex-start",
  padding: 14,
  borderRadius: 16,
  border: "1px solid rgba(251, 113, 133, 0.28)",
  background: "rgba(251, 113, 133, 0.08)",
  color: "var(--text-strong)",
};

const preStyle: React.CSSProperties = {
  margin: 0,
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  fontFamily: "var(--font-mono)",
  fontSize: 12.5,
  lineHeight: 1.75,
  color: "var(--text-strong)",
};

const reportSurfaceStyle: React.CSSProperties = {
  padding: 16,
  borderRadius: 16,
  border: "1px solid rgba(120, 145, 178, 0.14)",
  background: "linear-gradient(180deg, rgba(8, 13, 24, 0.72), rgba(6, 10, 18, 0.92))",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
  maxHeight: 560,
  overflow: "auto",
};

const emptySanitizationStyle: React.CSSProperties = {
  padding: 16,
  borderRadius: 16,
  border: "1px dashed rgba(120, 145, 178, 0.18)",
  background: "rgba(9, 14, 24, 0.56)",
};

const exportLinkStyle: React.CSSProperties = {
  color: "var(--accent)",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  textDecoration: "none",
};
