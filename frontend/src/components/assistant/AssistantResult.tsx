"use client";

import * as api from "@/lib/api";
import type { AssistantSessionDetail } from "@/lib/types";

export default function AssistantResult({
  session,
}: {
  session: AssistantSessionDetail | null;
}) {
  if (!session) {
    return <EmptyState text="Select or create an assistant session." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={panelStyle}>
        <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>
          Sanitization Summary
        </div>
        <pre style={preStyle}>
          {JSON.stringify(session.sanitization_summary_json || {}, null, 2)}
        </pre>
      </div>
      <div style={panelStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>Generated Report</div>
          <a href={api.getAssistantExportUrl(session.id)} style={{ color: "var(--accent)", fontSize: 12 }}>
            Export
          </a>
        </div>
        <pre style={preStyle}>{session.report_markdown || "Run the assistant to generate a report."}</pre>
      </div>
      {session.error ? (
        <div style={{ ...panelStyle, borderColor: "rgba(248,113,113,0.4)", color: "var(--red)" }}>
          {session.error}
        </div>
      ) : null}
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div style={{ ...panelStyle, color: "var(--text-dim)" }}>{text}</div>;
}

const panelStyle: React.CSSProperties = {
  border: "1px solid var(--border)",
  borderRadius: 12,
  background: "var(--panel)",
  padding: 14,
};

const preStyle: React.CSSProperties = {
  margin: 0,
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  fontFamily: "var(--font-mono)",
  fontSize: 12,
  color: "var(--text)",
};
