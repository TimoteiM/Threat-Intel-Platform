"use client";

import React from "react";
import EvidenceTable from "@/components/evidence/EvidenceTable";

type Props = {
  hybridAnalysis: any;
};

type Intelligence = {
  summary?: Record<string, any>;
  process_tree_summary?: Record<string, any>;
  contacted_hosts?: any[];
  contacted_ips?: any[];
  dropped_files?: any[];
  suspicious_commands?: any[];
  screenshot_thumbnails?: any[];
  extracted_iocs?: any[];
};

function arr(value: any): any[] {
  return Array.isArray(value) ? value : [];
}

function text(value: any): string {
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function uniqueRows(rows: any[], keyFn: (row: any) => string): any[] {
  const out: any[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const key = keyFn(row).toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

function collectIntelligence(hybridAnalysis: any): Intelligence[] {
  return arr(hybridAnalysis?.items)
    .map((item: any) => item?.sandbox_intelligence || {})
    .filter((intel: Intelligence) => {
      const summary = intel?.summary || {};
      return Boolean(
        summary?.process_count ||
          summary?.contacted_host_count ||
          summary?.contacted_ip_count ||
          summary?.dropped_file_count ||
          summary?.suspicious_command_count ||
          summary?.extracted_ioc_count ||
          arr(intel?.screenshot_thumbnails).length
      );
    });
}

export default function AnyRunSandboxIntelligence({ hybridAnalysis }: Props) {
  const intelligence = React.useMemo(() => collectIntelligence(hybridAnalysis), [hybridAnalysis]);
  if (!intelligence.length) return null;

  const hosts = uniqueRows(intelligence.flatMap((i) => arr(i.contacted_hosts)), (row) => text(row?.host));
  const ips = uniqueRows(
    intelligence.flatMap((i) => arr(i.contacted_ips)),
    (row) => `${text(row?.ip)}:${text(row?.port)}:${text(row?.protocol)}`
  );
  const files = uniqueRows(
    intelligence.flatMap((i) => arr(i.dropped_files)),
    (row) => `${text(row?.path || row?.name)}:${text(row?.sha256 || row?.sha1 || row?.md5)}`
  );
  const commands = uniqueRows(
    intelligence.flatMap((i) => arr(i.suspicious_commands)),
    (row) => `${text(row?.process)}:${text(row?.command_line)}`
  );
  const iocs = uniqueRows(
    intelligence.flatMap((i) => arr(i.extracted_iocs)),
    (row) => `${text(row?.type)}:${text(row?.value)}`
  );
  const screenshots = uniqueRows(
    intelligence.flatMap((i) => arr(i.screenshot_thumbnails)),
    (row) => text(row?.url)
  );
  const primaryTree = intelligence.find((i) => i?.process_tree_summary)?.process_tree_summary || {};
  const summary = intelligence.reduce(
    (acc, intel) => {
      const s = intel.summary || {};
      acc.processes += Number(s.process_count || 0);
      acc.hosts += Number(s.contacted_host_count || 0);
      acc.ips += Number(s.contacted_ip_count || 0);
      acc.files += Number(s.dropped_file_count || 0);
      acc.commands += Number(s.suspicious_command_count || 0);
      acc.iocs += Number(s.extracted_ioc_count || 0);
      return acc;
    },
    { processes: 0, hosts: 0, ips: 0, files: 0, commands: 0, iocs: 0 }
  );

  return (
    <div style={{ marginBottom: 18 }}>
      <div style={statGrid}>
        <KeyStat label="Processes" value={summary.processes} />
        <KeyStat label="Hosts" value={hosts.length || summary.hosts} />
        <KeyStat label="IPs" value={ips.length || summary.ips} />
        <KeyStat label="Files" value={files.length || summary.files} />
        <KeyStat label="Commands" value={commands.length || summary.commands} tone={commands.length ? "warn" : "neutral"} />
        <KeyStat label="IOCs" value={iocs.length || summary.iocs} tone={iocs.length ? "hot" : "neutral"} />
      </div>

      {primaryTree?.narrative && (
        <div style={noteStyle}>{String(primaryTree.narrative)}</div>
      )}

      <EvidenceTable
        title="Process Tree Summary"
        data={[
          ...arr(primaryTree?.root_processes).slice(0, 6).map((row: any) => ({
            type: "Root",
            process: text(row?.name),
            pid: text(row?.pid),
            score: text(row?.threat_score),
            activity: `${Number(row?.network_events || 0)} net / ${Number(row?.file_events || 0)} file`,
            command: text(row?.command_line),
          })),
          ...arr(primaryTree?.high_risk_processes).slice(0, 8).map((row: any) => ({
            type: "High signal",
            process: text(row?.name),
            pid: text(row?.pid),
            score: text(row?.threat_score),
            activity: `${Number(row?.network_events || 0)} net / ${Number(row?.file_events || 0)} file`,
            command: text(row?.command_line),
          })),
        ]}
        columns={[
          { key: "type", label: "Type" },
          { key: "process", label: "Process", wrap: true },
          { key: "pid", label: "PID" },
          { key: "score", label: "Score" },
          { key: "activity", label: "Activity" },
          { key: "command", label: "Command", wrap: true },
        ]}
        showHeader
      />

      <EvidenceTable
        title="Contacted Hosts"
        data={hosts.slice(0, 20).map((row) => ({
          host: text(row?.host),
          source: text(row?.source),
          process: text(row?.process),
          threat: text(row?.threat_level),
          name: text(row?.threat_name),
        }))}
        columns={[
          { key: "host", label: "Host", wrap: true },
          { key: "source", label: "Source" },
          { key: "process", label: "Process", wrap: true },
          { key: "threat", label: "Threat" },
          { key: "name", label: "Name", wrap: true },
        ]}
        showHeader
      />

      <EvidenceTable
        title="Contacted IPs"
        data={ips.slice(0, 20).map((row) => ({
          ip: text(row?.ip),
          port: text(row?.port),
          protocol: text(row?.protocol),
          process: text(row?.process),
          threat: text(row?.threat_level),
        }))}
        columns={[
          { key: "ip", label: "IP" },
          { key: "port", label: "Port" },
          { key: "protocol", label: "Proto" },
          { key: "process", label: "Process", wrap: true },
          { key: "threat", label: "Threat" },
        ]}
        showHeader
      />

      <EvidenceTable
        title="Dropped / Created Files"
        data={files.slice(0, 20).map((row) => ({
          file: text(row?.path || row?.name),
          process: text(row?.process),
          action: text(row?.action || row?.source),
          hash: text(row?.sha256 || row?.sha1 || row?.md5),
        }))}
        columns={[
          { key: "file", label: "File", wrap: true },
          { key: "process", label: "Process", wrap: true },
          { key: "action", label: "Action" },
          { key: "hash", label: "Hash", wrap: true },
        ]}
        showHeader
      />

      <EvidenceTable
        title="Suspicious Commands"
        data={commands.slice(0, 20).map((row) => ({
          process: text(row?.process),
          pid: text(row?.pid),
          reason: text(row?.reason),
          command: text(row?.command_line),
        }))}
        columns={[
          { key: "process", label: "Process", wrap: true },
          { key: "pid", label: "PID" },
          { key: "reason", label: "Reason", wrap: true },
          { key: "command", label: "Command", wrap: true },
        ]}
        showHeader
      />

      {screenshots.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={tableTitleStyle}>Screenshot Thumbnails</div>
          <div style={thumbGridStyle}>
            {screenshots.slice(0, 8).map((shot, idx) => (
              <a key={`${shot?.url}-${idx}`} href={String(shot?.url || "#")} target="_blank" rel="noreferrer" style={thumbLinkStyle}>
                <img src={String(shot?.url || "")} alt={text(shot?.label)} style={thumbImageStyle} />
                <span style={thumbLabelStyle}>{text(shot?.label)}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      <EvidenceTable
        title="Extracted IOCs"
        data={iocs.slice(0, 40).map((row) => ({
          type: text(row?.type).toUpperCase(),
          value: text(row?.value),
          context: text(row?.context),
          confidence: text(row?.confidence),
        }))}
        columns={[
          { key: "type", label: "Type" },
          { key: "value", label: "Value", wrap: true },
          { key: "context", label: "Context", wrap: true },
          { key: "confidence", label: "Confidence" },
        ]}
        showHeader
      />
    </div>
  );
}

function KeyStat({ label, value, tone = "neutral" }: { label: string; value: number; tone?: "neutral" | "warn" | "hot" }) {
  const color = tone === "hot" ? "var(--red)" : tone === "warn" ? "var(--yellow)" : "var(--accent)";
  return (
    <div style={statStyle}>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>{label}</div>
      <div style={{ fontSize: 20, color, fontWeight: 700, lineHeight: 1.1 }}>{Number(value || 0)}</div>
    </div>
  );
}

const statGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(112px, 1fr))",
  gap: 8,
  marginBottom: 12,
};

const statStyle: React.CSSProperties = {
  minHeight: 64,
  padding: "10px 12px",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.42)",
};

const noteStyle: React.CSSProperties = {
  marginBottom: 14,
  padding: "10px 12px",
  fontSize: 12,
  color: "var(--text-secondary)",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "var(--bg-input)",
};

const tableTitleStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  color: "var(--text-dim)",
  letterSpacing: "0.01em",
  marginBottom: 6,
  padding: "6px 0",
  borderBottom: "1px solid var(--border-dim)",
  fontFamily: "var(--font-sans)",
};

const thumbGridStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
  gap: 10,
};

const thumbLinkStyle: React.CSSProperties = {
  display: "block",
  overflow: "hidden",
  border: "1px solid var(--border-dim)",
  borderRadius: "var(--radius-sm)",
  background: "rgba(15,23,42,0.42)",
  textDecoration: "none",
};

const thumbImageStyle: React.CSSProperties = {
  width: "100%",
  aspectRatio: "16 / 9",
  objectFit: "cover",
  display: "block",
  background: "var(--bg-root)",
};

const thumbLabelStyle: React.CSSProperties = {
  display: "block",
  padding: "7px 8px",
  fontSize: 11,
  color: "var(--text-secondary)",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};
