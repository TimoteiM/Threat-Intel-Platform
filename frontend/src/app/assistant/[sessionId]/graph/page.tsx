"use client";

import React from "react";
import Link from "next/link";
import * as api from "@/lib/api";
import AssistantIncidentGraph from "@/components/assistant/AssistantIncidentGraph";
import ConsoleModule from "@/components/ui/ConsoleModule";
import StatusPill from "@/components/ui/StatusPill";
import type { AssistantSessionDetail } from "@/lib/types";

export default function AssistantSessionGraphPage({ params }: { params: { sessionId: string } }) {
  const [session, setSession] = React.useState<AssistantSessionDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");

    api.getAssistantSession(params.sessionId)
      .then((data) => {
        if (alive) setSession(data);
      })
      .catch((err) => {
        if (alive) setError(err instanceof Error ? err.message : "Unable to load assistant session.");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });

    return () => {
      alive = false;
    };
  }, [params.sessionId]);

  const graph = session?.result_json?.incident_graph;
  const backHref = `/assistant?session=${encodeURIComponent(params.sessionId)}`;
  const exportUrl = api.getAssistantExportUrl(params.sessionId);

  return (
    <main style={pageStyle}>
      <div style={topBarStyle}>
        <div style={{ minWidth: 0 }}>
          <div style={eyebrowStyle}>Assistant graph workspace</div>
          <h1 style={titleStyle}>{session?.title || "Log interpretation graph"}</h1>
          <div style={metaStyle}>
            <StatusPill tone={riskTone(graph?.summary?.risk)} outline>{graph?.summary?.risk || "Risk pending"}</StatusPill>
            <StatusPill tone="info" outline>{typeLabel(graph?.summary?.investigationType || "graph")}</StatusPill>
            {session?.status ? <StatusPill tone="neutral" outline>{session.status}</StatusPill> : null}
          </div>
        </div>
        <div style={actionRowStyle}>
          <Link href={backHref} style={secondaryLinkStyle}>Back to assistant</Link>
          <a href={exportUrl} style={primaryLinkStyle}>Export</a>
        </div>
      </div>

      {loading ? (
        <ConsoleModule eyebrow="Loading" title="Preparing graph" description="Fetching the deterministic graph for this assistant session." tone="info" compact>
          <div style={messageStyle}>Loading graph workspace...</div>
        </ConsoleModule>
      ) : error ? (
        <ConsoleModule eyebrow="Graph unavailable" title="Could not load session" description={error} tone="danger" compact>
          <Link href={backHref} style={secondaryLinkStyle}>Return to assistant</Link>
        </ConsoleModule>
      ) : graph?.nodes?.length ? (
        <AssistantIncidentGraph graph={graph} fullPage />
      ) : (
        <ConsoleModule
          eyebrow="Graph unavailable"
          title="No graph nodes generated"
          description="This assistant session does not currently contain graph nodes. Re-run the session to rebuild graph data from normalized evidence."
          tone="warning"
          compact
        >
          <Link href={backHref} style={secondaryLinkStyle}>Return to assistant</Link>
        </ConsoleModule>
      )}
    </main>
  );
}

function riskTone(value: any): "neutral" | "info" | "success" | "warning" | "danger" {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "danger";
  if (normalized === "medium") return "warning";
  if (normalized === "low") return "success";
  return "info";
}

function typeLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

const pageStyle: React.CSSProperties = {
  minHeight: "100vh",
  padding: "18px clamp(16px, 2vw, 30px) 28px",
  background: "linear-gradient(180deg, rgba(15,23,42,0.96), rgba(2,6,23,0.98))",
};

const topBarStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 18,
  marginBottom: 14,
};

const eyebrowStyle: React.CSSProperties = {
  color: "var(--text-muted)",
  fontSize: 11,
  fontWeight: 900,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
};

const titleStyle: React.CSSProperties = {
  margin: "5px 0 8px",
  color: "var(--text-strong)",
  fontSize: "clamp(24px, 3vw, 36px)",
  lineHeight: 1.08,
};

const metaStyle: React.CSSProperties = { display: "flex", gap: 8, flexWrap: "wrap" };
const actionRowStyle: React.CSSProperties = { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" };

const secondaryLinkStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: 36,
  padding: "0 13px",
  borderRadius: 8,
  border: "1px solid var(--border-dim)",
  background: "rgba(15,23,42,0.56)",
  color: "var(--text-primary)",
  textDecoration: "none",
  fontSize: 12,
  fontWeight: 800,
};

const primaryLinkStyle: React.CSSProperties = {
  ...secondaryLinkStyle,
  border: "1px solid rgba(103,232,249,0.32)",
  background: "rgba(103,232,249,0.12)",
  color: "#cffafe",
};

const messageStyle: React.CSSProperties = {
  color: "var(--text-secondary)",
  fontSize: 13,
  lineHeight: 1.6,
};
