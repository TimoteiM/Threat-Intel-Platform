"use client";

import React from "react";
import Link from "next/link";
import * as api from "@/lib/api";
import ConsoleModule from "@/components/ui/ConsoleModule";
import StatusPill from "@/components/ui/StatusPill";
import type { AssistantSessionDetail } from "@/lib/types";


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

  const exportUrl = api.getAssistantExportUrl(session.id);

  // Strip the backend-appended "Resolved Identifiers" section from the markdown
  // before rendering — we display it ourselves below as structured UI.
  const resolvedSection = parseResolvedIdentifiers(session.report_markdown ?? "");
  const reportBody = stripResolvedSection(session.report_markdown ?? "");
  const incidentGraph = session.result_json?.incident_graph;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {incidentGraph?.nodes?.length ? (
        <ConsoleModule
          eyebrow="SOC investigation graph"
          title="Log interpretation graph"
          description="Open the deterministic evidence graph in a dedicated workspace with more room to inspect, pan, zoom, and move nodes."
          tone={riskTone(incidentGraph?.summary?.risk)}
          compact
          actions={
            <Link href={`/assistant/${session.id}/graph`} style={graphLinkStyle}>
              Open graph
            </Link>
          }
        >
          <div style={graphLaunchStyle}>
            <GraphStat label="Type" value={typeLabel(incidentGraph?.summary?.investigationType || "generic_multi_cluster_investigation")} />
            <GraphStat label="Nodes" value={incidentGraph.nodes.length} />
            <GraphStat label="Edges" value={Array.isArray(incidentGraph.edges) ? incidentGraph.edges.length : 0} />
            <GraphStat label="Risk" value={incidentGraph?.summary?.risk || "Medium"} />
          </div>
        </ConsoleModule>
      ) : incidentGraph ? (
        <ConsoleModule
          eyebrow="SOC investigation graph"
          title="Graph unavailable"
          description="The session has a graph payload, but no graph nodes were generated. Reopen or rerun the session to rebuild deterministic graph data from the logs."
          tone="warning"
          compact
        >
          <div style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.6 }}>
            Graph data checks will appear once the backend extracts source IPs, targeted accounts, and event relationships from the submitted logs.
          </div>
        </ConsoleModule>
      ) : null}

      <ConsoleModule
        eyebrow="Analyst output"
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
          <pre style={preStyle}>{reportBody || "Run the assistant to generate a report."}</pre>
        </div>
      </ConsoleModule>

      {resolvedSection.length > 0 && (
        <ConsoleModule
          eyebrow="Resolved Identifiers"
          title="Redacted values"
          description="Sensitive values were redacted before AI analysis. Each token maps to its original observed value."
          tone="warning"
          compact
        >
          <div style={{ display: "grid", gap: 8 }}>
            {resolvedSection.map(({ token, category, value }) => (
              <div key={token} style={resolvedRowStyle}>
                <StatusPill tone="warning" outline size="sm" mono>{token}</StatusPill>
                <span style={resolvedCategoryStyle}>{category}</span>
                <StatusPill tone="info" outline size="sm" mono>{value}</StatusPill>
              </div>
            ))}
          </div>
        </ConsoleModule>
      )}

    </div>
  );
}

interface ResolvedRow { token: string; category: string; value: string }

function parseResolvedIdentifiers(markdown: string): ResolvedRow[] {
  const rows: ResolvedRow[] = [];
  const sectionMatch = markdown.match(/---\s*\n+##\s*Resolved Identifiers[\s\S]*?\n+((?:\|.*\|\n?)+)/);
  if (!sectionMatch) return rows;
  for (const line of sectionMatch[1].split("\n")) {
    const cells = line.split("|").map((c) => c.trim().replace(/^`|`$/g, ""));
    if (cells.length >= 4 && cells[1] && !cells[1].startsWith("-")) {
      rows.push({ token: cells[1], category: cells[2], value: cells[3] });
    }
  }
  return rows;
}

function stripResolvedSection(markdown: string): string {
  return markdown.replace(/\n*---\s*\n+##\s*Resolved Identifiers[\s\S]*$/, "").trim();
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

function GraphStat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={graphStatStyle}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
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

const graphLaunchStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
  gap: 10,
};

const graphStatStyle: React.CSSProperties = {
  display: "grid",
  gap: 5,
  minHeight: 78,
  padding: 12,
  borderRadius: 8,
  border: "1px solid var(--border-dim)",
  background: "rgba(2,6,23,0.34)",
  color: "var(--text-secondary)",
};

const graphLinkStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: 34,
  padding: "0 13px",
  borderRadius: 8,
  border: "1px solid rgba(103,232,249,0.32)",
  background: "rgba(103,232,249,0.12)",
  color: "#cffafe",
  fontSize: 12,
  fontWeight: 800,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  textDecoration: "none",
};

const resolvedRowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "4px 0",
};

const resolvedCategoryStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-dim)",
  fontWeight: 600,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  minWidth: 110,
};


const exportLinkStyle: React.CSSProperties = {
  color: "var(--accent)",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  textDecoration: "none",
};
