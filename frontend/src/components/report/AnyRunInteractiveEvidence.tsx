"use client";

import React from "react";
import { createPortal } from "react-dom";
import dagre from "dagre";
import EvidenceTable from "@/components/evidence/EvidenceTable";
import ReactFlow, {
  Controls,
  Handle,
  MarkerType,
  Node,
  Edge,
  Position,
  ReactFlowProvider,
} from "reactflow";
import "reactflow/dist/style.css";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

type Props = {
  hybridAnalysis: any;
  investigationId?: string;
  onRefresh?: () => void;
};

type GridCol = {
  key: string;
  label: string;
  minWidth?: number;
  maxWidth?: number;
};

function arr(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

function anyrunLabelText(value: any): string {
  if (typeof value === "string") return value.trim();
  if (value && typeof value === "object") {
    for (const key of ["threatName", "name", "tag", "title", "label", "value"]) {
      const text = String(value?.[key] ?? "").trim();
      if (text) return text;
    }
    return "";
  }
  return String(value ?? "").trim();
}

function normalizedAnyrunLabels(values: any): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of arr(values)) {
    const text = anyrunLabelText(value);
    if (!text) continue;
    const lowered = text.toLowerCase();
    if (seen.has(lowered)) continue;
    seen.add(lowered);
    out.push(text);
  }
  return out;
}

function isFlagged(item: any): boolean {
  const level = Number(item?.threatLevel ?? 0);
  const malconf = Boolean(item?.isMalconf);
  const threatNames = arr(item?.threatName);
  return level >= 1 || malconf || threatNames.length > 0;
}

function severityFromValue(value: any, key: string): "malicious" | "suspicious" | "legit" | "neutral" {
  const text = String(value ?? "").toLowerCase();
  const k = String(key || "").toLowerCase();
  if (
    text.includes("malicious") ||
    text.includes("phishing") ||
    text.includes("critical") ||
    (k.includes("threat") && /\b([2-9]|[1-9]\d+)\b/.test(text))
  ) {
    return "malicious";
  }
  if (
    text.includes("suspicious") ||
    text.includes("warning") ||
    text.includes("medium") ||
    text.includes("inconclusive") ||
    (k.includes("threat") && /\b1\b/.test(text))
  ) {
    return "suspicious";
  }
  if (
    text.includes("whitelisted") ||
    text.includes("legitimate") ||
    text.includes("trusted") ||
    text.includes("clean") ||
    text.includes("benign")
  ) {
    return "legit";
  }
  return "neutral";
}

type ProcessEventRow = {
  source_group: string;
  title: string;
  technique_id: string;
  severity: "danger" | "warning" | "other";
  timeshift: string;
  details: Record<string, any>;
};

type EventCategoryKey =
  | "modified_files"
  | "registry_changes"
  | "synchronization"
  | "http_requests"
  | "connections"
  | "network_threats"
  | "modules"
  | "debug";

const EVENT_CATEGORY_META: Array<{
  key: EventCategoryKey;
  label: string;
  description: string;
}> = [
  { key: "modified_files", label: "Modified files", description: "File-system changes made by the process" },
  { key: "registry_changes", label: "Registry changes", description: "Registry writes or modifications" },
  { key: "synchronization", label: "Synchronization", description: "Mutexes, events, and sync primitives" },
  { key: "http_requests", label: "HTTP requests", description: "Web requests issued by the process" },
  { key: "connections", label: "Connections", description: "Socket and network connection activity" },
  { key: "network_threats", label: "Network threats", description: "Threat detections tied to network events" },
  { key: "modules", label: "Modules", description: "Loaded modules and libraries" },
  { key: "debug", label: "Debug", description: "Debug and inspection events" },
];

function _toSeverity(ev: any): "danger" | "warning" | "other" {
  const n = Number(ev?.threatLevel ?? ev?.severity ?? ev?.priority ?? -1);
  const text = String(ev?.severity || ev?.level || ev?.threat || ev?.classification || "").toLowerCase();
  if (n >= 2 || text.includes("malicious") || text.includes("danger") || text.includes("critical")) return "danger";
  if (n === 1 || text.includes("suspicious") || text.includes("warning") || text.includes("medium")) return "warning";
  return "other";
}

function _extractTechniqueId(ev: any): string {
  const candidates = [
    ev?.technique_id,
    ev?.techniqueId,
    ev?.attack_id,
    ev?.mitre_id,
    ev?.mitre,
    ev?.ttc,
    ev?.tag,
    ev?.title,
    ev?.name,
    ev?.description,
    ev?.msg,
  ].filter(Boolean);
  for (const c of candidates) {
    const txt = String(c);
    const m = txt.match(/\bT\d{4}(?:\.\d{3})?\b/i);
    if (m) return m[0].toUpperCase();
  }
  return "UNMAPPED";
}

function _extractEventTitle(ev: any, fallbackGroup: string): string {
  const cand = ev?.title || ev?.name || ev?.description || ev?.msg || ev?.event || ev?.type || ev?.operation;
  if (cand) return String(cand);
  return fallbackGroup.replaceAll("_", " ");
}

function _extractTimeshift(ev: any): string {
  const v = ev?.timeshift ?? ev?.timeShift ?? ev?.offset_ms ?? ev?.time ?? ev?.timestamp ?? "";
  if (v == null || v === "") return "-";
  const s = String(v);
  if (/^\d+$/.test(s)) return `+${s} ms`;
  return s;
}

function _prettyEventKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^\w/, (m) => m.toUpperCase());
}

function _eventValueToText(value: any): string {
  if (value == null) return "-";
  if (typeof value === "string") return value || "-";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    const flat = value
      .slice(0, 6)
      .map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v)))
      .filter(Boolean);
    return flat.join(", ") || "-";
  }
  if (typeof value === "object") {
    try {
      const compact = JSON.stringify(value);
      return compact.length > 280 ? `${compact.slice(0, 280)}...` : compact;
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function _extractEventDetailRows(ev: Record<string, any>): Array<{ key: string; value: string }> {
  if (!ev || typeof ev !== "object") return [];
  const preferred = [
    "url",
    "domain",
    "hostname",
    "host",
    "destinationIP",
    "ip",
    "destinationPort",
    "port",
    "protocol",
    "method",
    "status",
    "headers",
    "rep",
    "asn",
    "cn",
    "pid",
    "processName",
    "query",
    "recordType",
    "threatName",
    "threatLevel",
    "description",
    "operation",
    "key",
    "registryKey",
    "path",
    "name",
    "valueName",
    "typeValue",
    "type",
    "valueType",
    "value",
    "timestamp",
    "date",
  ];

  const out: Array<{ key: string; value: string }> = [];
  const seen = new Set<string>();
  for (const key of preferred) {
    if (!(key in ev)) continue;
    const txt = _eventValueToText(ev[key]);
    if (!txt || txt === "-") continue;
    out.push({ key: _prettyEventKey(key), value: txt });
    seen.add(key);
  }

  for (const [rawKey, rawValue] of Object.entries(ev)) {
    if (seen.has(rawKey)) continue;
    const txt = _eventValueToText(rawValue);
    if (!txt || txt === "-") continue;
    out.push({ key: _prettyEventKey(rawKey), value: txt });
  }
  return out.slice(0, 12);
}

function flattenProcessEvents(proc: any): ProcessEventRow[] {
  const out: ProcessEventRow[] = [];
  const groups = Object.entries((proc?.events || {}) as Record<string, any>);
  for (const [groupKey, rows] of groups) {
    for (const item of arr(rows)) {
      const ev = typeof item === "object" && item ? item : { value: String(item) };
      out.push({
        source_group: groupKey,
        title: _extractEventTitle(ev, groupKey),
        technique_id: _extractTechniqueId(ev),
        severity: _toSeverity(ev),
        timeshift: _extractTimeshift(ev),
        details: ev,
      });
    }
  }
  return out;
}

function _eventCountForCategory(proc: any, category: EventCategoryKey): number {
  const explicit = Number(proc?.event_counts?.[category]);
  if (Number.isFinite(explicit)) return explicit;
  return arr(proc?.events?.[category]).length;
}

function _eventRowsForCategory(proc: any, category: EventCategoryKey): any[] {
  return arr(proc?.events?.[category]);
}

function _parseTimeshiftMs(value: any): number | null {
  if (value == null || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = String(value).trim();
  if (!text) return null;
  const plain = text.match(/^-?\d+(?:\.\d+)?$/);
  if (plain) return Number(plain[0]);
  const ms = text.match(/([+-]?\d+(?:\.\d+)?)\s*ms\b/i);
  if (ms) return Number(ms[1]);
  const sec = text.match(/([+-]?\d+(?:\.\d+)?)\s*s\b/i);
  if (sec) return Number(sec[1]) * 1000;
  return null;
}

function _hasGroupedProcessData(proc: any): boolean {
  return flattenProcessEvents(proc).length > 0;
}

function _hasDeepProcessData(proc: any): boolean {
  return flattenProcessEvents(proc).some((event) => _extractEventDetailRows(event.details || {}).length > 0);
}

function _processRefs(proc: any): string[] {
  return [proc?.uuid, proc?.guid, proc?.pid].filter(Boolean).map((x: any) => String(x));
}

function _num(v: any): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function _uniq<T>(vals: T[]): T[] {
  return Array.from(new Set(vals));
}

function _isLookupMode(value: any): boolean {
  return String(value || "").toLowerCase().includes("lookup");
}

function _asDisplayScore(value: any): string {
  return value == null || value === "" ? "-" : String(value);
}

function _findMaliciousLookupContext(context: any): any | null {
  const items = arr(context?.items);
  const current = context?.item || context;
  const candidates = items.length ? items : [current];
  for (const item of candidates) {
    const raw = item?.raw_summary || {};
    const source = String(raw?.source || "").toLowerCase();
    const verdict = String(item?.verdict || raw?.verdict || "").toLowerCase();
    const mode = raw?.mode || item?.mode;
    if (source === "anyrun" && _isLookupMode(mode) && verdict === "malicious") {
      return item;
    }
    const domainIntel = item?.domain_intelligence;
    if (domainIntel?.checked && String(domainIntel?.verdict || "").toLowerCase() === "malicious") {
      return domainIntel;
    }
  }
  return null;
}

function _lookupContextLabel(item: any): string {
  const raw = item?.raw_summary || {};
  const mode = String(raw?.mode || item?.mode || "lookup").toUpperCase();
  const score = _asDisplayScore(item?.threat_score ?? raw?.threat_score);
  const id = String(item?.analysis_id || raw?.analysis_id || "").trim();
  return `${mode} verdict: MALICIOUS${score !== "-" ? `, score ${score}` : ""}${id ? `, analysis ${id}` : ""}`;
}

function _procSignature(p: any): string {
  const name = String(p?.fileName || p?.image || p?.processName || p?.name || "").toLowerCase();
  const cmd = String(p?.commandLine || p?.cmd || "").toLowerCase();
  return `${name}::${cmd}`;
}

function _extractMitreTagsFromProc(p: any): string[] {
  const tags: string[] = [];
  const pools = [
    p?.mitre,
    p?.mitre_tags,
    p?.attack,
    p?.attack_tags,
    p?.threatName,
  ];
  for (const pool of pools) {
    for (const v of arr(pool)) {
      const txt = String(v || "");
      const m = txt.match(/\bT\d{4}(?:\.\d{3})?\b/gi);
      if (m) tags.push(...m.map((x) => x.toUpperCase()));
    }
  }
  return _uniq(tags);
}

function _processRelevanceScore(p: any): number {
  const name = String(p?.fileName || p?.image || p?.processName || p?.name || "").toLowerCase();
  const threatScore = _num(p?.threat_score ?? p?.threatScore ?? p?.score);
  const threatLevel = _num(p?.threat_level ?? p?.threatLevel);
  const networkCount = _num(p?.network_count);
  const threatEventCount = _num(p?.network_threat_count ?? p?.event_counts?.network_threats);
  const fileCount = _num(p?.file_activity_count);
  const mitreCount = _num(p?.mitre_count);
  const suspicious = Boolean(p?.suspicious_flag) || threatLevel >= 1 || threatScore >= 35 || threatEventCount > 0;

  let score = 0;
  if (threatLevel >= 2 || threatScore >= 70) score += 10;
  else if (suspicious) score += 6;
  if (networkCount > 0) score += 2;
  if (threatEventCount > 0) score += 4;
  if (fileCount > 0) score += 2;
  if (mitreCount > 0) score += 3;
  if (String(p?.commandLine || p?.cmd || "").trim()) score += 1;

  // De-prioritize very common low-signal system/browser process names.
  if (
    name === "svchost.exe" ||
    name === "conhost.exe" ||
    name === "csrss.exe" ||
    name === "fontdrvhost.exe" ||
    name === "dwm.exe" ||
    name === "smss.exe" ||
    name === "wininit.exe" ||
    name === "lsass.exe" ||
    name === "services.exe" ||
    name === "explorer.exe" ||
    name === "msedge.exe"
  ) {
    score -= 2;
  }
  return score;
}

function _isLowSignalSystemProcess(p: any): boolean {
  const name = String(p?.fileName || p?.image || p?.processName || p?.name || "").toLowerCase();
  return (
    name === "svchost.exe" ||
    name === "conhost.exe" ||
    name === "csrss.exe" ||
    name === "fontdrvhost.exe" ||
    name === "dwm.exe" ||
    name === "smss.exe" ||
    name === "wininit.exe" ||
    name === "lsass.exe" ||
    name === "services.exe" ||
    name === "explorer.exe" ||
    name === "msedge.exe"
  );
}

const NOISE_PROCESS_NAMES = new Set([
  "svchost.exe",
  "runtimebroker.exe",
  "lsass.exe",
]);

const GRAPH_NODE_WIDTH = 196;
const GRAPH_NODE_HEIGHT = 52;

// ── Custom ReactFlow node components ─────────────────────────────────────────

function ProcessIconSvg({ color, isEntry }: { color: string; isEntry: boolean }) {
  if (isEntry) {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" fill={color}>
        <polygon points="3,2 14,8 3,14" />
      </svg>
    );
  }
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <rect x="1.5" y="1.5" width="15" height="15" rx="2.5" stroke={color} strokeWidth="1.4" />
      <rect x="1.5" y="1.5" width="15" height="4.5" rx="2.5" fill={color} fillOpacity="0.35" />
      <circle cx="4.5" cy="3.75" r="1" fill={color} fillOpacity="0.7" />
      <circle cx="7.5" cy="3.75" r="1" fill={color} fillOpacity="0.7" />
      <text x="9" y="14.5" textAnchor="middle" fill={color} fontSize="6.5" fontWeight="bold" fontFamily="monospace">?</text>
    </svg>
  );
}

const ProcessGraphNode = React.memo(function ProcessGraphNode({ data }: { data: any }) {
  const proc = data?.process || {};
  const rawLabel = String(data?.label || proc?.fileName || proc?.processName || proc?.name || "process");
  const label = _filenameFromPath(rawLabel);
  const isEntry = Boolean(data?.isEntry);
  const threatLevel = Number(proc?.threat_level ?? proc?.threatLevel ?? 0);
  const threatScore = Number(proc?.threat_score ?? proc?.threatScore ?? 0);
  const malicious = threatLevel >= 2 || threatScore >= 70;
  const suspicious = Boolean(data?.suspicious) || Boolean(proc?.suspicious_flag) || threatLevel >= 1 || threatScore >= 35;
  const selected = Boolean(data?.__selected);

  const threatNames = normalizedAnyrunLabels(
    Array.isArray(proc?.threat_name) ? proc.threat_name : Array.isArray(proc?.threatName) ? proc.threatName : []
  );

  let statusText = "no specs";
  let statusColor = "#5fa8c5";
  if (malicious) {
    statusText = threatNames[0] || "malicious";
    statusColor = "#ef4444";
  } else if (suspicious) {
    statusText = threatNames[0] || "suspicious";
    statusColor = "#f59e0b";
  } else if (isEntry) {
    statusText = "analysis start";
    statusColor = "#22d3ee";
  }

  const iconColor = malicious ? "#ef4444" : isEntry ? "#22d3ee" : suspicious ? "#f59e0b" : "#4ea8cc";
  const iconBg = malicious
    ? "rgba(127,29,29,0.65)"
    : isEntry
    ? "rgba(8,72,102,0.75)"
    : suspicious
    ? "rgba(120,80,10,0.55)"
    : "rgba(13,55,84,0.75)";
  const borderColor = selected
    ? "#22d3ee"
    : malicious
    ? "rgba(239,68,68,0.7)"
    : isEntry
    ? "rgba(34,211,238,0.5)"
    : suspicious
    ? "rgba(245,158,11,0.55)"
    : "rgba(56,140,190,0.25)";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 10px 6px 7px",
        width: GRAPH_NODE_WIDTH,
        height: GRAPH_NODE_HEIGHT,
        background: isEntry ? "rgba(8,45,68,0.88)" : "rgba(10,28,46,0.92)",
        border: `1px solid ${borderColor}`,
        borderRadius: 7,
        boxSizing: "border-box",
        boxShadow: selected
          ? "0 0 0 2px rgba(34,211,238,0.22)"
          : malicious
          ? "0 0 8px rgba(239,68,68,0.18)"
          : "none",
        cursor: "pointer",
        userSelect: "none",
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: iconColor, width: 7, height: 7, border: "none", opacity: 0.7 }}
      />

      {/* icon */}
      <div
        style={{
          width: 32,
          height: 32,
          flexShrink: 0,
          borderRadius: 5,
          background: iconBg,
          border: `1px solid ${iconColor}30`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <ProcessIconSvg color={iconColor} isEntry={isEntry} />
      </div>

      {/* text */}
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          style={{
            fontSize: 12,
            fontWeight: 700,
            color: "#dff0fb",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            lineHeight: 1.25,
            letterSpacing: "0.01em",
          }}
        >
          {label}
        </div>
        <div
          style={{
            fontSize: 10,
            color: statusColor,
            opacity: 0.88,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            lineHeight: 1.3,
            marginTop: 2,
          }}
        >
          {statusText}
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        style={{ background: iconColor, width: 7, height: 7, border: "none", opacity: 0.7 }}
      />
    </div>
  );
});

const GRAPH_NODE_TYPES = { process: ProcessGraphNode, analysis: ProcessGraphNode, default: ProcessGraphNode };

function _hasDirectThreatSignal(p: any): boolean {
  return (
    _num(p?.network_threat_count ?? p?.event_counts?.network_threats) > 0 ||
    _num(p?.threat_level ?? p?.threatLevel ?? p?.scores?.verdict?.threatLevel) > 0 ||
    _num(p?.threat_score ?? p?.threatScore ?? p?.score) > 0 ||
    Boolean(p?.isMalconf) ||
    Boolean(p?.suspicious_flag) ||
    arr(p?.threatName).length > 0 ||
    arr(p?.mitre_tags ?? p?.mitreTags).length > 0
  );
}

function _effectiveProcessScore(p: any): number {
  const backendScore = _num(p?.relevance_score ?? p?.relevanceScore);
  if (backendScore > 0) return backendScore;
  return _processRelevanceScore(p);
}

function _intrinsicProcessScore(p: any): number {
  const backendScore = _num(p?.intrinsic_relevance_score ?? p?.intrinsicRelevanceScore);
  if (backendScore > 0) return backendScore;
  return _processRelevanceScore(p);
}

function _isExecutionContextProcess(p: any): boolean {
  const hasThreat = _num(p?.threat_score ?? p?.threatScore ?? p?.score) > 0 || _num(p?.threat_level ?? p?.threatLevel) > 0;
  const hasActivity =
    _num(p?.network_count) > 0 ||
    _num(p?.file_activity_count) > 0 ||
    _num(p?.mitre_count) > 0 ||
    arr(p?.mitre_tags).length > 0;
  return _isLowSignalSystemProcess(p) && !hasThreat && !hasActivity && _intrinsicProcessScore(p) < 3 && _effectiveProcessScore(p) < 6;
}

function _filenameFromPath(path: string): string {
  if (!path) return path;
  const sep = path.includes("\\") ? "\\" : "/";
  return path.split(sep).pop() || path;
}

function buildBackendProcessTreeGraph(raw: any): { nodes: any[]; edges: any[]; details: Record<string, any> } | null {
  const nodes = arr(raw?.behavior_graph?.nodes);
  const edges = arr(raw?.behavior_graph?.edges);
  if (!nodes.length) return null;

  // Normalize: extract filename from full-path labels and enrich process objects
  // so that _isLowSignalSystemProcess / _isExecutionContextProcess work correctly.
  const normalizedNodes = nodes.map((node: any, idx: number) => {
    const rawLabel = String(node?.label || node?.id || `node-${idx}`);
    const filename = _filenameFromPath(rawLabel);
    const proc = node?.process || {};
    const enrichedProc = {
      ...proc,
      fileName: proc?.fileName || filename,
      processName: proc?.processName || proc?.fileName || filename,
      name: proc?.name || proc?.fileName || filename,
    };
    return {
      id: String(node?.id || `backend-node-${idx}`),
      kind: String(node?.kind || "process"),
      label: filename,
      process: enrichedProc,
      position: node?.position,
      isEntry: Boolean(node?.isEntry),
      suspicious: Boolean(node?.suspicious),
    };
  });

  const nodeById = new Map<string, any>(normalizedNodes.map((n: any) => [String(n.id), n]));
  const allEdges = edges.filter((edge: any) => {
    const source = String(edge?.source || "");
    const target = String(edge?.target || "");
    return source && target && nodeById.has(source) && nodeById.has(target);
  });

  // Build adjacency maps for reconnection
  const parentOf = new Map<string, string>(); // childId -> parentId
  const childrenOf = new Map<string, string[]>();
  for (const n of normalizedNodes) childrenOf.set(String(n.id), []);
  for (const e of allEdges) {
    const src = String(e.source || e.from || "");
    const tgt = String(e.target || e.to || "");
    if (src && tgt) {
      parentOf.set(tgt, src);
      childrenOf.get(src)?.push(tgt);
    }
  }

  // ── Step 1: Find anchor nodes (threat-bearing + analysis/entry kinds) ────────
  // Descendants of anchors are ALWAYS kept regardless of their own threat level,
  // because they represent the actual process behavior we care about.
  // Only nodes that are ANCESTORS (above the anchor) are candidates for noise removal.
  const anchorIds = new Set<string>();
  for (const n of normalizedNodes) {
    const kind = String(n.kind || "process");
    if (kind !== "process") {
      anchorIds.add(String(n.id)); // analysis / entry nodes always anchor
      continue;
    }
    const proc = n.process || {};
    if (_hasDirectThreatSignal(proc) || n.suspicious || n.isEntry) {
      anchorIds.add(String(n.id));
    }
  }

  // ── Step 2: Collect all descendants of anchors (always kept) ─────────────────
  const protectedIds = new Set<string>(Array.from(anchorIds));
  const descStack = Array.from(anchorIds);
  while (descStack.length > 0) {
    const cur = descStack.pop()!;
    for (const child of childrenOf.get(cur) || []) {
      if (!protectedIds.has(child)) {
        protectedIds.add(child);
        descStack.push(child);
      }
    }
  }

  // ── Step 3: Mark noise only among non-protected (i.e. pure-ancestor) nodes ───
  const noiseIds = new Set<string>();
  for (const n of normalizedNodes) {
    if (protectedIds.has(String(n.id))) continue; // never filter descendants of anchors
    if (String(n.kind || "process") !== "process") continue;
    const proc = n.process || {};
    const nameLower = String(proc.name || proc.fileName || "").toLowerCase().trim();
    const isSystemRoot =
      nameLower === "[system process]" ||
      nameLower === "system process" ||
      (nameLower === "system" && !_hasDirectThreatSignal(proc));
    if (isSystemRoot || _isExecutionContextProcess(proc)) {
      noiseIds.add(String(n.id));
    }
  }

  // ── Step 4: Reconnect edges around removed noise ancestors ───────────────────
  function nonNoiseAncestor(id: string, depth = 0): string | null {
    if (depth > 20) return null;
    const parent = parentOf.get(id);
    if (!parent) return null;
    return noiseIds.has(parent) ? nonNoiseAncestor(parent, depth + 1) : parent;
  }

  const edgeSet = new Set<string>();
  const reconnectedEdges: any[] = [];
  for (const e of allEdges) {
    const src = String(e.source || e.from || "");
    const tgt = String(e.target || e.to || "");
    if (noiseIds.has(src) || noiseIds.has(tgt)) continue;
    const key = `${src}->${tgt}`;
    if (!edgeSet.has(key)) { edgeSet.add(key); reconnectedEdges.push(e); }
  }
  for (const noiseId of Array.from(noiseIds)) {
    const ancestor = nonNoiseAncestor(noiseId);
    if (!ancestor) continue;
    for (const child of childrenOf.get(noiseId) || []) {
      if (noiseIds.has(child)) continue;
      const key = `${ancestor}->${child}`;
      if (!edgeSet.has(key)) {
        edgeSet.add(key);
        reconnectedEdges.push({ source: ancestor, target: child, id: key, suspicious: false });
      }
    }
  }

  const filteredNodes = normalizedNodes.filter((n: any) => !noiseIds.has(String(n.id)));
  if (!filteredNodes.length) return null;

  const filteredIds = new Set(filteredNodes.map((n: any) => String(n.id)));
  const finalEdges = reconnectedEdges.filter((e: any) =>
    filteredIds.has(String(e.source || e.from || "")) && filteredIds.has(String(e.target || e.to || ""))
  );

  const details: Record<string, any> = {};
  filteredNodes.forEach((node: any) => {
    if (String(node?.kind || "process") !== "process") return;
    details[String(node.id)] = node?.process || {};
  });
  return layoutProcessGraph(filteredNodes, finalEdges, details);
}

function hasRicherProcessEvidence(raw: any): boolean {
  const processDetails = arr(raw?.behavior_details?.process_details);
  return processDetails.some((proc: any) => {
    const counts = proc?.event_counts || {};
    return (
      _num(counts?.network_threats) > 0 ||
      _num(counts?.http_requests) > 0 ||
      _num(counts?.connections) > 0 ||
      _num(counts?.dns_requests) > 0 ||
      _num(proc?.threat_level ?? proc?.threatLevel) > 0 ||
      _num(proc?.threat_score ?? proc?.threatScore ?? proc?.score) > 0
    );
  });
}

function isDegenerateBackendGraph(graph: { nodes: any[]; edges: any[]; details: Record<string, any> } | null, raw: any): boolean {
  if (!graph) return false;
  const processNodes = graph.nodes.filter((node: any) => String(node?.kind || "process") === "process");
  if (!processNodes.length) return hasRicherProcessEvidence(raw);
  if (processNodes.length === 1) {
    const only = processNodes[0];
    const label = String(only?.label || "").trim().toLowerCase();
    if (label === "[system process]" || label === "system" || label === "system process") {
      return hasRicherProcessEvidence(raw);
    }
  }
  const rawThreatAnchors = arr(raw?.behavior_details?.process_details).filter((proc: any) => {
    if (_isLowSignalSystemProcess(proc)) return false;
    return _hasDirectThreatSignal(proc);
  });
  if (!rawThreatAnchors.length) return false;
  const backendThreatAnchors = processNodes.filter((node: any) => {
    const proc = node?.process || graph?.details?.[String(node?.id || "")] || {};
    if (_isLowSignalSystemProcess(proc)) return false;
    return _hasDirectThreatSignal(proc);
  });
  if (!backendThreatAnchors.length) return true;
  return false;
}

function buildProcessTreeGraph(raw: any): { nodes: any[]; edges: any[]; details: Record<string, any> } {
  const processDetails = arr(raw?.behavior_details?.process_details);
  if (!processDetails.length) {
    const backendGraph = buildBackendProcessTreeGraph(raw);
    if (backendGraph && !isDegenerateBackendGraph(backendGraph, raw)) return backendGraph;
  }

  let processes = processDetails.length ? processDetails : arr(raw?.behavior_details?.processes);
  if (!processes.length) return { nodes: [], edges: [], details: {} };
  const detailByRef: Record<string, any> = {};
  for (const d of processDetails) {
    const refs = [d?.uuid, d?.guid, d?.pid, d?.name].filter(Boolean).map((x: any) => String(x));
    for (const r of refs) detailByRef[r] = d;
  }

  type PNode = { id: string; label: string; parentId: string | null; process: any };
  const nodesById = new Map<string, PNode>();
  const byPid = new Map<string, string>(); // PID -> canonical id
  const byUuid = new Map<string, string>();

  const richnessScore = (p: any): number => {
    const keys = [
      "commandLine", "cmd", "user", "username", "ppid", "parentPid",
      "start", "startedAt", "time", "fileName", "image", "processName", "name",
    ];
    let score = 0;
    for (const k of keys) if (p?.[k]) score += 1;
    return score;
  };

  const mergedById = new Map<string, any>();
  const uuidToId = new Map<string, string>();
  const guidToId = new Map<string, string>();

  // Normalize snapshots: prefer PID as stable identity, fallback UUID/GUID.
  processes.forEach((p: any, i: number) => {
    const uuid = String(p?.uuid || "").trim();
    const guid = String(p?.guid || "").trim();
    const pid = String(p?.pid || "").trim();

    let id = "";
    if (pid && byPid.has(pid)) id = byPid.get(pid)!;
    else if (uuid && uuidToId.has(uuid)) id = uuidToId.get(uuid)!;
    else if (guid && guidToId.has(guid)) id = guidToId.get(guid)!;
    else if (pid) id = `pid:${pid}`;
    else if (uuid) id = `uuid:${uuid}`;
    else if (guid) id = `guid:${guid}`;
    else id = `idx:${i}`;

    const prev = mergedById.get(id);
    if (!prev) {
      mergedById.set(id, { ...p });
    } else {
      // Keep richer snapshot values while preserving already-present useful fields.
      const next = { ...prev };
      const useIncoming = richnessScore(p) >= richnessScore(prev);
      for (const [k, v] of Object.entries(p || {})) {
        if (v == null || v === "") continue;
        if (next[k] == null || next[k] === "" || useIncoming) next[k] = v;
      }
      mergedById.set(id, next);
    }

    if (pid) byPid.set(pid, id);
    if (uuid) uuidToId.set(uuid, id);
    if (guid) guidToId.set(guid, id);
  });

  mergedById.forEach((p, id) => {
    const uuid = String(p?.uuid || "").trim();
    const guid = String(p?.guid || "").trim();
    const pid = String(p?.pid || "").trim();
    const matchedDetail = detailByRef[uuid] || detailByRef[guid] || detailByRef[pid] || detailByRef[String(p?.fileName || p?.image || p?.processName || p?.name || "")];
    const eventCounts = (matchedDetail?.event_counts || {}) as Record<string, number>;
    const networkThreatCount = _num(eventCounts.network_threats);
    const connCount = _num(eventCounts.connections) + _num(eventCounts.http_requests) + _num(eventCounts.dns_requests) + networkThreatCount;
    const fileCount = _num(eventCounts.modified_files) + _num(eventCounts.registry_changes);
    const mitreTags = _extractMitreTagsFromProc(matchedDetail || p);
    const threatScore = _num(matchedDetail?.threat_score ?? p?.threatScore ?? p?.score);
    const threatLevel = _num(matchedDetail?.threat_level ?? p?.threatLevel ?? p?.scores?.verdict?.threatLevel);
    const sha256 = String(
      matchedDetail?.sha256
      || p?.sha256
      || p?.cert?.sha256
      || p?.cert?.contentHash
      || ""
    );
    const label = String(p?.fileName || p?.image || p?.processName || p?.name || id);
    nodesById.set(id, {
      id,
      label,
      parentId: null,
      process: {
        ...p,
        ...(matchedDetail || {}),
        threat_score: threatScore,
        threat_level: threatLevel,
        mitre_tags: mitreTags,
        mitre_count: mitreTags.length,
        network_count: connCount,
        network_threat_count: networkThreatCount,
        file_activity_count: fileCount,
        suspicious_flag: threatLevel >= 1 || threatScore >= 35 || networkThreatCount > 0,
        sha256,
        duplicate_count: 1,
      },
    });
    if (pid) byPid.set(pid, id);
    if (uuid) byUuid.set(uuid, id);
    if (guid) byUuid.set(guid, id);
  });

  mergedById.forEach((p: any, id: string) => {
    if (!nodesById.has(id)) return;

    const parentUuid = String(p?.parent || p?.parentUuid || p?.parentGuid || "").trim();
    const ppid = String(p?.ppid || p?.parentPid || "").trim();
    const parentId = (parentUuid && byUuid.get(parentUuid)) || (ppid && byPid.get(ppid)) || null;
    if (parentId && parentId !== id) {
      const n = nodesById.get(id)!;
      n.parentId = parentId;
      nodesById.set(id, n);
    }
  });

  const children = new Map<string, string[]>();
  const indegree = new Map<string, number>();
  nodesById.forEach((n, id) => {
    indegree.set(id, 0);
    children.set(id, []);
  });
  nodesById.forEach((n, id) => {
    if (!n.parentId || !nodesById.has(n.parentId)) return;
    children.get(n.parentId)!.push(id);
    indegree.set(id, (indegree.get(id) || 0) + 1);
  });

  let roots = Array.from(nodesById.keys()).filter((id) => (indegree.get(id) || 0) === 0);
  const depth = new Map<string, number>();
  const visit = (id: string, d: number) => {
    const prev = depth.get(id);
    if (prev != null && prev <= d) return;
    depth.set(id, d);
    for (const c of children.get(id) || []) visit(c, d + 1);
  };
  roots.forEach((r) => visit(r, 0));

  // Collapse identical leaf siblings (same process signature under same parent).
  const removed = new Set<string>();
  const alias = new Map<string, string>();
  nodesById.forEach((n, id) => {
    if (removed.has(id)) return;
    const siblings = (children.get(n.parentId || "__root__") || []).filter((cid) => !removed.has(cid));
    const leafSiblings = siblings.filter((sid) => (children.get(sid) || []).length === 0);
    const bySig = new Map<string, string[]>();
    for (const sid of leafSiblings) {
      const sig = _procSignature(nodesById.get(sid)?.process || {});
      if (!bySig.has(sig)) bySig.set(sig, []);
      bySig.get(sig)!.push(sid);
    }
    bySig.forEach((ids) => {
      if (ids.length <= 1) return;
      const rep = ids[0];
      const repNode = nodesById.get(rep);
      if (!repNode) return;
      for (let i = 1; i < ids.length; i++) {
        const rid = ids[i];
        const rn = nodesById.get(rid);
        if (!rn) continue;
        repNode.process.duplicate_count = _num(repNode.process.duplicate_count) + 1;
        repNode.process.network_count = _num(repNode.process.network_count) + _num(rn.process.network_count);
        repNode.process.file_activity_count = _num(repNode.process.file_activity_count) + _num(rn.process.file_activity_count);
        repNode.process.mitre_tags = _uniq([...(arr(repNode.process.mitre_tags)), ...(arr(rn.process.mitre_tags))]);
        repNode.process.mitre_count = arr(repNode.process.mitre_tags).length;
        repNode.process.threat_score = Math.max(_num(repNode.process.threat_score), _num(rn.process.threat_score));
        repNode.process.threat_level = Math.max(_num(repNode.process.threat_level), _num(rn.process.threat_level));
        repNode.process.suspicious_flag = Boolean(repNode.process.suspicious_flag || rn.process.suspicious_flag);
        removed.add(rid);
        alias.set(rid, rep);
      }
      nodesById.set(rep, repNode);
    });
  });

  // Additional collapse: for repetitive low-signal leaf siblings with same executable name
  // under the same parent, keep one representative and aggregate duplicate count.
  nodesById.forEach((n) => {
    const parentKey = n.parentId || "__root__";
    const siblings = (children.get(parentKey) || []).filter((cid) => !removed.has(cid));
    const leafSiblings = siblings.filter((sid) => (children.get(sid) || []).length === 0);
    const byName = new Map<string, string[]>();
    for (const sid of leafSiblings) {
      const sn = nodesById.get(sid);
      const label = String(sn?.label || "").trim().toLowerCase();
      if (!label) continue;
      if (!byName.has(label)) byName.set(label, []);
      byName.get(label)!.push(sid);
    }
    byName.forEach((ids) => {
      if (ids.length <= 3) return;
      const scored = ids
        .map((id) => ({ id, score: _processRelevanceScore(nodesById.get(id)?.process || {}) }))
        .sort((a, b) => b.score - a.score);
      const rep = scored[0]?.id;
      if (!rep) return;
      const repNode = nodesById.get(rep);
      if (!repNode) return;
      for (let i = 1; i < scored.length; i++) {
        const rid = scored[i].id;
        const rn = nodesById.get(rid);
        if (!rn) continue;
        // keep clearly relevant nodes visible
        if (_processRelevanceScore(rn.process || {}) >= 6) continue;
        repNode.process.duplicate_count = _num(repNode.process.duplicate_count) + 1;
        repNode.process.network_count = _num(repNode.process.network_count) + _num(rn.process.network_count);
        repNode.process.file_activity_count = _num(repNode.process.file_activity_count) + _num(rn.process.file_activity_count);
        repNode.process.mitre_tags = _uniq([...(arr(repNode.process.mitre_tags)), ...(arr(rn.process.mitre_tags))]);
        repNode.process.mitre_count = arr(repNode.process.mitre_tags).length;
        repNode.process.threat_score = Math.max(_num(repNode.process.threat_score), _num(rn.process.threat_score));
        repNode.process.threat_level = Math.max(_num(repNode.process.threat_level), _num(rn.process.threat_level));
        repNode.process.suspicious_flag = Boolean(repNode.process.suspicious_flag || rn.process.suspicious_flag);
        removed.add(rid);
        alias.set(rid, rep);
      }
      nodesById.set(rep, repNode);
    });
  });

  // ── Relevance pruning ──────────────────────────────────────────────────────
  // Step 1: Find threat anchors — high-signal processes we MUST show.
  //         Allow noise-list names if they have a direct threat signal (e.g. malicious svchost).
  const threatAnchorIds = new Set<string>();
  nodesById.forEach((n, id) => {
    if (removed.has(id)) return;
    const proc = n.process || {};
    const score = _processRelevanceScore(proc);
    const name = String(n?.label || proc?.name || "").trim().toLowerCase();
    const isNoiseByName = NOISE_PROCESS_NAMES.has(name);
    if (score >= 6 && (!isNoiseByName || _hasDirectThreatSignal(proc))) {
      threatAnchorIds.add(id);
    }
  });

  // Step 2: Collect ALL descendants of threat anchors (always keep, even if low-signal).
  //         This ensures child msedge.exe, identity_helper.exe etc. are shown.
  const kept = new Set<string>(Array.from(threatAnchorIds));
  const descQueue = Array.from(threatAnchorIds);
  while (descQueue.length > 0) {
    const cur = descQueue.pop()!;
    for (const child of children.get(cur) || []) {
      if (!removed.has(child) && !kept.has(child)) {
        kept.add(child);
        descQueue.push(child);
      }
    }
  }

  // Step 3: Walk ancestors of threat anchors, stopping at execution-context noise.
  //         This prevents [System Process], System, csrss, wininit, services etc.
  //         from being pulled in just because they are in the ancestry chain.
  const addAncestors = (id: string) => {
    let cur = nodesById.get(id)?.parentId || null;
    let guard = 0;
    while (cur && guard < 200) {
      if (removed.has(cur)) break;
      const curNode = nodesById.get(cur);
      if (!curNode) break;
      if (_isExecutionContextProcess(curNode.process || {})) break; // stop at noise boundary
      kept.add(cur);
      cur = curNode.parentId || null;
      guard += 1;
    }
  };
  Array.from(threatAnchorIds).forEach(addAncestors);

  // Step 4: Safety fallback — if nothing was kept (no threat signals in the whole trace),
  //         show all non-execution-context nodes so the graph isn't empty.
  if (kept.size === 0) {
    nodesById.forEach((n, id) => {
      if (!removed.has(id) && !_isExecutionContextProcess(n.process || {})) kept.add(id);
    });
  }
  const rfNodes: any[] = [];
  const rfEdges: any[] = [];
  const chainIds = new Set<string>();
  Array.from(kept).forEach((id) => {
    let cur: string | null = id;
    let guard = 0;
    while (cur && guard < 200) {
      chainIds.add(cur);
      cur = String(nodesById.get(cur)?.parentId || "") || null;
      guard += 1;
    }
  });

  const keptIds = Array.from(kept).filter((id) => !removed.has(id) && nodesById.has(id));
  const keptIndegree = new Map<string, number>();
  keptIds.forEach((id) => keptIndegree.set(id, 0));
  nodesById.forEach((n, id) => {
    if (!n.parentId || !nodesById.has(n.parentId)) return;
    const sid = alias.get(id) || id;
    const tid = alias.get(n.parentId) || n.parentId;
    if (!kept.has(sid) || !kept.has(tid) || sid === tid) return;
    keptIndegree.set(sid, (keptIndegree.get(sid) || 0) + 1);
  });

  const rootIds = keptIds.filter((id) => (keptIndegree.get(id) || 0) === 0);

  keptIds.forEach((id) => {
    const n = nodesById.get(id)!;
    const dup = _num(n?.process?.duplicate_count);
    const threatScore = _num(n?.process?.threat_score ?? n?.process?.threatScore ?? n?.process?.score);
    const threatLevel = _num(n?.process?.threat_level ?? n?.process?.threatLevel);
    const suspicious =
      Boolean(n?.process?.suspicious_flag) ||
      threatLevel >= 1 ||
      threatScore >= 35 ||
      _num(n?.process?.network_threat_count ?? n?.process?.event_counts?.network_threats) > 0;
    rfNodes.push({
      id,
      kind: "process",
      label: dup > 1 ? `${n.label} (${dup})` : n.label,
      process: n.process,
      isEntry: rootIds.includes(id),
      suspicious,
      partOfChain: chainIds.has(id),
    });
  });

  const renderedNow = new Set(rfNodes.map((n: any) => String(n.id)));
  nodesById.forEach((n, id) => {
    if (!n.parentId || !nodesById.has(n.parentId)) return;
    const sid = alias.get(id) || id;
    const tid = alias.get(n.parentId) || n.parentId;
    if (!renderedNow.has(sid) || !renderedNow.has(tid) || sid === tid) return;
    const sourceNode = nodesById.get(tid);
    const targetNode = nodesById.get(sid);
    const suspiciousEdge =
      chainIds.has(sid) ||
      chainIds.has(tid) ||
      Boolean(sourceNode?.process?.suspicious_flag) ||
      Boolean(targetNode?.process?.suspicious_flag);
    rfEdges.push({
      id: `${tid}->${sid}`,
      source: tid,
      target: sid,
      label: "",
      suspicious: suspiciousEdge,
    });
  });
  const details: Record<string, any> = {};
  rfNodes.forEach((n) => {
    details[String(n.id)] = n.process || {};
  });
  return layoutProcessGraph(rfNodes, rfEdges, details);
}

function layoutProcessGraph(nodes: any[], edges: any[], details: Record<string, any>) {
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({
    rankdir: "LR",
    ranksep: 120,
    nodesep: 40,
    marginx: 24,
    marginy: 24,
  });
  graph.setDefaultEdgeLabel(() => ({}));

  nodes.forEach((node: any) => {
    graph.setNode(String(node.id), { width: GRAPH_NODE_WIDTH, height: GRAPH_NODE_HEIGHT });
  });
  edges.forEach((edge: any) => {
    if (!edge?.source || !edge?.target) return;
    graph.setEdge(String(edge.source), String(edge.target));
  });
  dagre.layout(graph);

  const laidOutNodes = nodes.map((node: any) => {
    const layout = graph.node(String(node.id));
    return {
      ...node,
      position: {
        x: (layout?.x ?? 0) - GRAPH_NODE_WIDTH / 2,
        y: (layout?.y ?? 0) - GRAPH_NODE_HEIGHT / 2,
      },
    };
  });
  return { nodes: laidOutNodes, edges, details };
}

export function AnyRunGraph({ raw, height = 520, analysisContext }: { raw?: any; height?: number; analysisContext?: any }) {
  const processTree = React.useMemo(() => buildProcessTreeGraph(raw || {}), [raw]);
  const rawNodes = arr(processTree?.nodes);
  const rawEdges = arr(processTree?.edges);
  const detailByNode = processTree?.details || {};
  const [selectedNode, setSelectedNode] = React.useState<string | null>(null);
  const [selectedProcessManual, setSelectedProcessManual] = React.useState<any | null>(null);
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [processViewMode, setProcessViewMode] = React.useState<"view" | "group" | "deep">("view");
  const [activeEventCategory, setActiveEventCategory] = React.useState<EventCategoryKey>("modified_files");
  const threatRows = arr(raw?.behavior_details?.network_threats);
  const processDetails = arr(raw?.behavior_details?.process_details);
  const maliciousLookupContext = React.useMemo(
    () => _findMaliciousLookupContext(analysisContext),
    [analysisContext]
  );
  const graphProcessRefs = React.useMemo(() => {
    const refs = new Set<string>();
    for (const n of rawNodes) {
      const p = n?.process || {};
      for (const ref of _processRefs(p)) {
        refs.add(ref);
      }
    }
    return refs;
  }, [rawNodes]);
  const graphProcessByRef = React.useMemo(() => {
    const byRef: Record<string, any> = {};
    for (const n of rawNodes) {
      const p = n?.process || {};
      for (const ref of _processRefs(p)) {
        if (!byRef[ref]) byRef[ref] = p;
      }
    }
    return byRef;
  }, [rawNodes]);
  const processIndexByRef = React.useMemo(() => {
    const m: Record<string, any> = {};
    for (const p of processDetails) {
      // Use stable identifiers only; name-based keys cause collisions (e.g., many svchost.exe).
      const refs = _processRefs(p);
      for (const r of refs) m[r] = p;
    }
    return m;
  }, [processDetails]);
  const processListItems = React.useMemo(() => {
    const graphProcessNodes = rawNodes.filter((n: any) => String(n?.kind || "process") === "process");
    const src = processDetails.length ? processDetails : graphProcessNodes.map((n: any) => n?.process || {});
    const byKey = new Map<string, any>();
    for (const p of src) {
      const refs = _processRefs(p);
      const graphEnrichment = refs.map((ref) => graphProcessByRef[ref]).find(Boolean) || {};
      const enriched = { ...p, ...graphEnrichment };
      const pid = String(p?.pid ?? "").trim();
      const uuid = String(p?.uuid ?? p?.guid ?? "").trim();
      const name = String(enriched?.name || enriched?.fileName || enriched?.image || enriched?.processName || "process").trim();
      const cmd = String(enriched?.command_line || enriched?.commandLine || enriched?.cmd || "").trim();
      // Collapse exact duplicates (same identity + same command line).
      const key = [uuid || "-", pid || "-", name.toLowerCase(), cmd.toLowerCase()].join("|");
      if (!byKey.has(key)) {
        byKey.set(key, { ...enriched, __dup_count: 1, __key: key });
      } else {
        const prev = byKey.get(key);
        byKey.set(key, { ...prev, __dup_count: Number(prev?.__dup_count || 1) + 1 });
      }
    }
    return Array.from(byKey.values());
  }, [processDetails, rawNodes, graphProcessByRef]);
  const relevantProcessListItems = React.useMemo(() => {
    return processListItems.filter((p: any) => {
      const refs = [p?.uuid, p?.guid, p?.pid].filter(Boolean).map((x: any) => String(x));
      const inRenderedGraph = refs.some((r) => graphProcessRefs.has(r));
      return inRenderedGraph;
    });
  }, [processListItems, graphProcessRefs]);
  const groupProcessListItems = React.useMemo(
    () => relevantProcessListItems.filter((p: any) => _hasGroupedProcessData(p)),
    [relevantProcessListItems]
  );
  const deepProcessListItems = React.useMemo(
    () => relevantProcessListItems.filter((p: any) => _hasDeepProcessData(p)),
    [relevantProcessListItems]
  );
  const activeProcessList = React.useMemo(() => {
    if (processViewMode === "group") return groupProcessListItems;
    if (processViewMode === "deep") return deepProcessListItems;
    return relevantProcessListItems;
  }, [processViewMode, relevantProcessListItems, groupProcessListItems, deepProcessListItems]);
  const nodeIdByRef = React.useMemo(() => {
    const m: Record<string, string> = {};
    for (const n of rawNodes) {
      const id = String(n?.id || "");
      const p = n?.process || {};
      // Avoid name-based mapping; it incorrectly maps many same-name processes to one node.
      const refs = [p?.uuid, p?.guid, p?.pid].filter(Boolean).map((x: any) => String(x));
      for (const r of refs) {
        if (!m[r]) m[r] = id;
      }
    }
    return m;
  }, [rawNodes]);
  const threatByProcess = React.useMemo(() => {
    const m: Record<string, { count: number; maxLevel: number }> = {};
    for (const t of threatRows) {
      const refs = [t?.process, t?.processUuid, t?.uuid, t?.pid].filter(Boolean).map((x: any) => String(x));
      const lvl = Number(t?.threatLevel ?? t?.severity ?? t?.priority ?? 0);
      for (const r of refs) {
        const prev = m[r] || { count: 0, maxLevel: 0 };
        m[r] = { count: prev.count + 1, maxLevel: Math.max(prev.maxLevel, lvl) };
      }
    }
    return m;
  }, [threatRows]);

  const nodesBase = React.useMemo<Node[]>(
    () =>
      rawNodes.map((n: any, idx: number) => {
        const label = String(n?.label || n?.id || `node-${idx}`);
        const p = n?.process || {};
        const refs = [
          String(p?.uuid || ""),
          String(p?.guid || ""),
          String(p?.pid || ""),
          String(n?.id || ""),
        ].filter(Boolean);
        let threatCount = 0;
        let threatLevel = Number(p?.threat_level || 0);
        for (const r of refs) {
          const st = threatByProcess[r];
          if (st) {
            threatCount += st.count;
            threatLevel = Math.max(threatLevel, st.maxLevel);
          }
        }
        const threatScore = Number(p?.threat_score || 0);
        const suspicious = Boolean(n?.suspicious) || Boolean(p?.suspicious_flag) || threatLevel >= 1 || threatScore >= 35;
        const isEntry = Boolean(n?.isEntry);
        const kind = String(n?.kind || "process");
        return {
          id: String(n?.id || `n-${idx}`),
          type: kind === "analysis" ? "analysis" : "process",
          position: n?.position || { x: 0, y: idx * 90 },
          data: {
            label,
            process: { ...p, threat_level: threatLevel, threat_score: threatScore },
            kind,
            isEntry,
            suspicious,
          },
          style: { padding: 0, background: "transparent", border: "none" },
        };
      }),
    [rawNodes, threatByProcess]
  );

  const nodes = React.useMemo(
    () =>
      nodesBase.map((n) => ({
        ...n,
        data: { ...(n as any).data, __selected: selectedNode === n.id },
      })),
    [nodesBase, selectedNode]
  );

  const edges = React.useMemo<Edge[]>(
    () =>
      rawEdges
        .map((e: any, idx: number) => ({
          id: String(e?.id || `e-${idx}`),
          source: String(e?.source || ""),
          target: String(e?.target || ""),
          label: "",
          style: {
            stroke: e?.suspicious ? "rgba(239,68,68,0.75)" : "rgba(56,180,240,0.45)",
            strokeWidth: e?.suspicious ? 1.8 : 1.2,
          },
          labelStyle: { fill: "#94a3b8", fontSize: 10 },
          type: "bezier",
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: 12,
            height: 12,
            color: e?.suspicious ? "rgba(239,68,68,0.85)" : "rgba(56,180,240,0.6)",
          },
        }))
        .filter((e: any) => e.source && e.target),
    [rawEdges]
  );

  if (!rawNodes.length) return <EmptyNote>No AnyRun process tree available.</EmptyNote>;

  const selectedFromNode = selectedNode ? (detailByNode[selectedNode] || {}) : null;
  const selected = (selectedFromNode && Object.keys(selectedFromNode).length > 0)
    ? selectedFromNode
    : (selectedProcessManual || null);
  const selectedProcessDetail = React.useMemo(() => {
    if (!selected) return selectedProcessManual || null;
    const refs = [selected?.uuid, selected?.guid, selected?.pid]
      .filter(Boolean)
      .map((x: any) => String(x));
    for (const r of refs) {
      if (processIndexByRef[r]) return processIndexByRef[r];
    }
    return selectedProcessManual || null;
  }, [selected, processIndexByRef, selectedProcessManual]);
  const selectedRefs = selected
    ? [
        String(selected?.uuid || ""),
        String(selected?.guid || ""),
        String(selected?.pid || ""),
      ].filter(Boolean)
    : [];
  const selectedThreatCount = selectedRefs.reduce((acc, r) => acc + Number(threatByProcess[r]?.count || 0), 0);
  const selectedThreatLevel = selectedRefs.reduce((acc, r) => Math.max(acc, Number(threatByProcess[r]?.maxLevel || 0)), 0);
  const selectedProcessThreatLevel = Math.max(
    selectedThreatLevel,
    _num(selectedProcessDetail?.threat_level ?? selected?.threat_level ?? selected?.threatLevel)
  );
  const selectedProcessScore = selectedProcessDetail?.threat_score ?? selected?.threat_score ?? 0;
  const selectedEventCounts = React.useMemo(() => {
    const counts: Record<EventCategoryKey, number> = {
      modified_files: 0,
      registry_changes: 0,
      synchronization: 0,
      http_requests: 0,
      connections: 0,
      network_threats: 0,
      modules: 0,
      debug: 0,
    };
    for (const item of EVENT_CATEGORY_META) {
      counts[item.key] = _eventCountForCategory(selectedProcessDetail || {}, item.key);
    }
    return counts;
  }, [selectedProcessDetail]);
  const selectedEventCategoryRows = React.useMemo(
    () => _eventRowsForCategory(selectedProcessDetail || {}, activeEventCategory),
    [selectedProcessDetail, activeEventCategory]
  );
  const selectedEvents = React.useMemo(() => {
    const all = flattenProcessEvents(selectedProcessDetail || {});
    return all.filter((event) => String(event.source_group || "") === activeEventCategory);
  }, [selectedProcessDetail, activeEventCategory]);
  const selectedEventTimeline = React.useMemo(() => {
    const points = selectedEvents
      .map((event, index) => ({
        index,
        severity: event.severity,
        ms: _parseTimeshiftMs(event.timeshift),
      }))
      .filter((entry) => entry.ms != null) as Array<{ index: number; severity: ProcessEventRow["severity"]; ms: number }>;
    if (!points.length) return [];
    const maxMs = Math.max(...points.map((point) => point.ms), 1);
    return points.map((point) => ({
      ...point,
      left: Math.max(0, Math.min(100, (point.ms / maxMs) * 100)),
    }));
  }, [selectedEvents]);
  const activeEventMeta = React.useMemo(
    () => EVENT_CATEGORY_META.find((item) => item.key === activeEventCategory) || EVENT_CATEGORY_META[0],
    [activeEventCategory]
  );
  const groupedBySeverityAndTechnique = React.useMemo(() => {
    const map: Record<string, Record<string, ProcessEventRow[]>> = { danger: {}, warning: {}, other: {} };
    for (const e of selectedEvents) {
      if (!map[e.severity][e.technique_id]) map[e.severity][e.technique_id] = [];
      map[e.severity][e.technique_id].push(e);
    }
    return map;
  }, [selectedEvents]);
  React.useEffect(() => {
    if (!showAdvanced) return;
    const firstWithEvents = EVENT_CATEGORY_META.find((item) => selectedEventCounts[item.key] > 0)?.key;
    if (!selectedProcessDetail) {
      setActiveEventCategory("modified_files");
      return;
    }
    if (selectedEventCounts[activeEventCategory] > 0) return;
    setActiveEventCategory(firstWithEvents || EVENT_CATEGORY_META[0].key);
  }, [activeEventCategory, selectedEventCounts, selectedProcessDetail, showAdvanced]);
  React.useEffect(() => {
    if (!showAdvanced) return;
    if (activeProcessList.length === 0) {
      setSelectedNode(null);
      setSelectedProcessManual(null);
      return;
    }
    if ((!selected && !selectedProcessManual) || (processViewMode !== "view" && !selectedProcessManual)) {
      const first = activeProcessList[0];
      const refs = [first?.uuid, first?.guid, first?.pid].filter(Boolean).map((x: any) => String(x));
      let nodeId = "";
      for (const r of refs) {
        if (nodeIdByRef[r]) {
          nodeId = nodeIdByRef[r];
          break;
        }
      }
      setSelectedNode(nodeId || null);
      setSelectedProcessManual(first || null);
      return;
    }
    const selectedRefs = [selected?.uuid, selected?.guid, selected?.pid, selectedProcessManual?.uuid, selectedProcessManual?.guid, selectedProcessManual?.pid]
      .filter(Boolean)
      .map((x: any) => String(x));
    const selectedNames = [selected?.fileName, selected?.image, selected?.processName, selected?.name, selectedProcessManual?.name]
      .filter(Boolean)
      .map((x: any) => String(x));
    const stillPresent = activeProcessList.some((p: any) => {
      const refs = [p?.uuid, p?.guid, p?.pid].filter(Boolean).map((x: any) => String(x));
      if (refs.some((ref) => selectedRefs.includes(ref))) return true;
      const names = [p?.fileName, p?.image, p?.processName, p?.name].filter(Boolean).map((x: any) => String(x));
      return names.some((name) => selectedNames.includes(name));
    });
    if (!stillPresent) {
      const first = activeProcessList[0];
      const refs = [first?.uuid, first?.guid, first?.pid].filter(Boolean).map((x: any) => String(x));
      let nodeId = "";
      for (const r of refs) {
        if (nodeIdByRef[r]) {
          nodeId = nodeIdByRef[r];
          break;
        }
      }
      setSelectedNode(nodeId || null);
      setSelectedProcessManual(first || null);
    }
  }, [activeProcessList, nodeIdByRef, processViewMode, selected, selectedProcessManual, showAdvanced]);
  React.useEffect(() => {
    if (!showAdvanced || typeof document === "undefined") return;
    const body = document.body;
    const html = document.documentElement;
    const previousBodyOverflow = body.style.overflow;
    const previousHtmlOverflow = html.style.overflow;
    const previousBodyOverscroll = body.style.overscrollBehavior;
    const previousHtmlOverscroll = html.style.overscrollBehavior;

    body.style.overflow = "hidden";
    html.style.overflow = "hidden";
    body.style.overscrollBehavior = "none";
    html.style.overscrollBehavior = "none";

    return () => {
      body.style.overflow = previousBodyOverflow;
      html.style.overflow = previousHtmlOverflow;
      body.style.overscrollBehavior = previousBodyOverscroll;
      html.style.overscrollBehavior = previousHtmlOverscroll;
    };
  }, [showAdvanced]);

  return (
    <div style={{ marginBottom: 10, position: "relative" }}>
      {maliciousLookupContext && (
        <div
          style={{
            marginBottom: 10,
            padding: "9px 12px",
            border: "1px solid rgba(239,68,68,0.35)",
            background: "rgba(239,68,68,0.08)",
            borderRadius: 6,
            color: "var(--text-secondary)",
            fontSize: 12,
            lineHeight: 1.5,
          }}
        >
          <strong style={{ color: "var(--red, #ef4444)" }}>AnyRun intelligence verdict:</strong>{" "}
          {_lookupContextLabel(maliciousLookupContext)}. Process scores below are sandbox process telemetry only, so a clean
          or zero process score means AnyRun did not assign malicious behavior to that specific process in this run.
        </div>
      )}
      <div style={{ height, border: "1px solid #132e45", borderRadius: 6, overflow: "hidden", background: "#09202f" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={GRAPH_NODE_TYPES}
          onNodeClick={(_, n) => {
            setSelectedNode(String(n.id));
            setSelectedProcessManual((n as any)?.data?.kind === "process" ? ((n as any)?.data?.process || null) : null);
          }}
          onPaneClick={() => {
            setSelectedNode(null);
            setSelectedProcessManual(null);
          }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          zoomOnScroll
          panOnScroll={false}
          panOnDrag
          fitView
          minZoom={0.2}
          maxZoom={2.5}
          proOptions={{ hideAttribution: true }}
        >
          <Controls showInteractive={false} />
        </ReactFlow>
        {selected && (
          <div
            style={{
              position: "absolute",
              right: 14,
              bottom: 14,
              width: 360,
              border: "1px solid #1b4d6b",
              background: "rgba(4,39,61,0.97)",
              borderRadius: 6,
              boxShadow: "0 12px 30px rgba(0,0,0,0.35)",
              zIndex: 12,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                borderBottom: "1px solid rgba(59,130,246,0.25)",
                padding: "8px 10px",
                fontSize: 12,
              }}
            >
              <div style={{ color: "var(--accent)", fontWeight: 700 }}>
                Process details
                <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>
                  ID {selected?.pid || selected?.uuid || "-"}
                </span>
                {selectedThreatCount > 0 && (
                  <span style={{ color: selectedProcessThreatLevel >= 2 ? "var(--red)" : "var(--yellow)", marginLeft: 8 }}>
                    {selectedProcessThreatLevel >= 2 ? "Malicious" : "Suspicious"}
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={() => {
                  setSelectedNode(null);
                  setSelectedProcessManual(null);
                }}
                style={{
                  border: "none",
                  background: "transparent",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  fontSize: 16,
                }}
              >
                ×
              </button>
            </div>
            <div style={{ padding: 10, fontSize: 12, color: "var(--text-secondary)" }}>
              <div style={{ marginBottom: 6 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)", lineHeight: 1.35, wordBreak: "break-all", overflowWrap: "break-word" }}>
                  {_filenameFromPath(selected?.fileName || selected?.image || selected?.processName || selected?.name || "-")}
                </div>
                {(() => {
                  const full = selected?.fileName || selected?.image || selected?.processName || selected?.name || "";
                  const base = _filenameFromPath(full);
                  return full && full !== base ? (
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, wordBreak: "break-all", lineHeight: 1.4 }}>
                      {full}
                    </div>
                  ) : null;
                })()}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>PID:</strong> {selected?.pid ?? "-"} | <strong>PPID:</strong> {selected?.ppid ?? selected?.parentPid ?? "-"}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>User:</strong> {selected?.user || selected?.username || "-"}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>Start:</strong> {selected?.start || selected?.startedAt || selected?.time || "-"}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>Indicators:</strong> {selectedThreatCount}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>Process score:</strong> {String(selectedProcessScore ?? "-")}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>Network activity:</strong> {String(selected?.network_count ?? selectedProcessDetail?.network_count ?? "0")}
                {" | "}
                <strong>File activity:</strong> {String(selected?.file_activity_count ?? selectedProcessDetail?.file_activity_count ?? "0")}
              </div>
              <div style={{ marginBottom: 6 }}>
                <strong>MITRE tags:</strong> {arr(selected?.mitre_tags || selectedProcessDetail?.mitre_tags).slice(0, 6).join(", ") || "-"}
              </div>
              <div style={{ marginBottom: 6, wordBreak: "break-all" }}>
                <strong>SHA256:</strong> {selected?.sha256 || selectedProcessDetail?.sha256 || "-"}
              </div>
              <div>
                <div style={{ marginBottom: 4, color: "var(--accent)" }}><strong>Command line</strong></div>
                <div
                  style={{
                    background: "rgba(14,116,144,0.2)",
                    border: "1px solid rgba(14,116,144,0.35)",
                    borderRadius: 4,
                    padding: 8,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    fontFamily: "var(--font-mono)",
                    fontSize: 11,
                  }}
                >
                  {selected?.commandLine || selected?.cmd || "-"}
                </div>
              </div>
              <div style={{ marginTop: 10 }}>
                <button
                  type="button"
                  onClick={() => setShowAdvanced(true)}
                  style={{
                    padding: "6px 10px",
                    border: "1px solid rgba(56,189,248,0.45)",
                    borderRadius: 6,
                    background: "rgba(8,47,73,0.7)",
                    color: "var(--accent)",
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  More info
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
      {showAdvanced && typeof document !== "undefined" && createPortal((
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(2,6,23,0.82)",
            zIndex: 2147483647,
            display: "flex",
            justifyContent: "center",
            alignItems: "stretch",
            padding: "calc(var(--app-header-height, 72px) + 12px) 2vw 2vh",
            boxSizing: "border-box",
            overscrollBehavior: "contain",
          }}
        >
          <div
            style={{
              width: "96vw",
              height: "calc(100vh - var(--app-header-height, 72px) - 24px)",
              border: "1px solid #1b4d6b",
              borderRadius: 8,
              background: "#06314a",
              display: "grid",
              gridTemplateColumns: "280px 1fr",
              overflow: "hidden",
            }}
          >
            <div style={{ borderRight: "1px solid #1b4d6b", background: "#072f46", display: "flex", flexDirection: "column", minHeight: 0 }}>
              <div style={{ padding: "10px 12px", borderBottom: "1px solid #1b4d6b", fontWeight: 700, color: "var(--accent)" }}>
                {processViewMode === "view" ? "Process Chain" : processViewMode === "group" ? "Processes With Group Details" : "Processes With Deep Details"} ({activeProcessList.length})
              </div>
              <div style={{ overflowY: "auto", padding: 8 }}>
                {activeProcessList.length === 0 ? (
                  <EmptyNote>
                    {processViewMode === "group"
                      ? "No processes have group details."
                      : processViewMode === "deep"
                        ? "No processes have deep details."
                        : "No relevant processes available."}
                  </EmptyNote>
                ) : activeProcessList.map((p: any, idx: number) => {
                  const key = String(p?.uuid || p?.guid || p?.pid || p?.name || idx);
                  const title = String(p?.name || p?.fileName || p?.image || p?.processName || p?.label || "process");
                  const pid = p?.pid != null ? String(p.pid) : "-";
                  const isContext = _isExecutionContextProcess(p);
                  const active = Boolean(selected && [selected?.uuid, selected?.guid, selected?.pid, selected?.name, selected?.fileName, selected?.image].filter(Boolean).map(String).includes(key));
                  return (
                    <button
                      key={`plist-${key}-${idx}`}
                      type="button"
                      onClick={() => {
                        const refs = [p?.uuid, p?.guid, p?.pid, p?.fileName, p?.image, p?.processName, p?.name]
                          .filter(Boolean)
                          .map((x: any) => String(x));
                        let nodeId = "";
                        for (const r of refs) {
                          if (nodeIdByRef[r]) {
                            nodeId = nodeIdByRef[r];
                            break;
                          }
                        }
                        if (nodeId) setSelectedNode(nodeId);
                        else setSelectedNode(null);
                        setSelectedProcessManual(p || null);
                      }}
                      style={{
                        width: "100%",
                        textAlign: "left",
                        padding: "8px 9px",
                        border: active ? "1px solid rgba(56,189,248,0.7)" : "1px solid var(--border-dim)",
                        background: active ? "rgba(14,116,144,0.22)" : "rgba(2,23,39,0.5)",
                        borderRadius: 6,
                        color: "var(--text-primary)",
                        cursor: "pointer",
                        marginBottom: 6,
                        fontSize: 12,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                        <div style={{ fontWeight: 700 }}>{title}</div>
                        {isContext && (
                          <div
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              letterSpacing: 0.3,
                              textTransform: "uppercase",
                              color: "#93c5fd",
                              background: "rgba(59,130,246,0.14)",
                              border: "1px solid rgba(96,165,250,0.32)",
                              borderRadius: 999,
                              padding: "2px 6px",
                              whiteSpace: "nowrap",
                            }}
                          >
                            Context
                          </div>
                        )}
                      </div>
                      <div style={{ color: "var(--text-muted)", marginTop: 2 }}>
                        PID: {pid}{Number(p?.__dup_count || 1) > 1 ? `  |  x${p.__dup_count}` : ""}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
            <div style={{ minHeight: 0, overflow: "auto", display: "flex", flexDirection: "column" }}>
              {true ? (
                <>
                  <div
                    style={{
                      padding: "10px 14px",
                      borderBottom: "1px solid #1b4d6b",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 12,
                      position: "sticky",
                      top: 0,
                      zIndex: 2,
                      background: "#06314a",
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: "var(--text-primary)", fontSize: 14, fontWeight: 700, marginBottom: 2 }}>
                        Advanced details of process
                      </div>
                      <div style={{ color: "var(--text-primary)", fontSize: 15, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        <span style={{ color: "#dbeafe" }}>[{selected?.pid || selectedProcessDetail?.pid || "-"}]</span>{" "}
                        <span>{selected?.fileName || selected?.image || selected?.processName || selected?.name || selectedProcessDetail?.name || "-"}</span>{" "}
                        <span style={{ color: "var(--accent)", fontWeight: 500 }}>
                          {selectedProcessDetail?.image || selected?.image || ""}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                      {(["view", "group", "deep"] as const).map((mode) => (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => setProcessViewMode(mode)}
                          style={{
                            padding: "6px 10px",
                            border: "1px solid rgba(96,165,250,0.28)",
                            borderRadius: 6,
                            background: processViewMode === mode ? "rgba(59,130,246,0.18)" : "rgba(2,23,39,0.5)",
                            color: processViewMode === mode ? "#dbeafe" : "var(--text-muted)",
                            cursor: "pointer",
                            fontWeight: 700,
                            textTransform: "capitalize",
                          }}
                        >
                          {mode}
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => setShowAdvanced(false)}
                        style={{
                          marginLeft: 6,
                          border: "none",
                          background: "transparent",
                          color: "var(--text-muted)",
                          cursor: "pointer",
                          fontSize: 20,
                        }}
                      >
                        x
                      </button>
                    </div>
                  </div>
                  <div
                    style={{
                      padding: 12,
                      display: "grid",
                      gridTemplateColumns: "430px minmax(0, 1fr)",
                      gap: 12,
                      minHeight: 0,
                      flex: 1,
                      overflow: "hidden",
                    }}
                  >
                    <div style={{ minHeight: 0, display: "flex", flexDirection: "column", gap: 12, overflowY: "auto", paddingRight: 4 }}>
                      <AnalystCard title="Threat Verdict">
                        <div style={{ display: "grid", gridTemplateColumns: "118px 1fr", gap: 14, alignItems: "center" }}>
                          <div
                            style={{
                              width: 118,
                              height: 118,
                              borderRadius: "50%",
                              border: "4px solid rgba(59,130,246,0.35)",
                              display: "flex",
                              flexDirection: "column",
                              alignItems: "center",
                              justifyContent: "center",
                              color: "var(--text-primary)",
                              background: "radial-gradient(circle at 35% 30%, rgba(59,130,246,0.18), rgba(6,49,74,0.9) 70%)",
                            }}
                          >
                            <div style={{ fontSize: 34, fontWeight: 800, lineHeight: 1 }}>
                              {selectedProcessScore}
                            </div>
                            <div style={{ fontSize: 11, color: "#93c5fd", marginTop: 6 }}>OUT OF 100</div>
                          </div>
                          <div>
                            <div
                              style={{
                                fontSize: 19,
                                fontWeight: 800,
                                color:
                                  selectedProcessThreatLevel >= 2
                                    ? "#fca5a5"
                                    : selectedProcessThreatLevel >= 1
                                      ? "#fde68a"
                                      : "#67e8f9",
                                marginBottom: 8,
                              }}
                            >
                              {selectedProcessThreatLevel >= 2 ? "High risk" : selectedProcessThreatLevel >= 1 ? "Suspicious" : "No process verdict"}
                            </div>
                            <div style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.5 }}>
                              This score is scoped to the selected process and comes from live sandbox telemetry. Lookup or community intelligence verdicts are shown separately because they are indicator-level, not process-level.
                            </div>
                            {maliciousLookupContext && selectedProcessThreatLevel < 1 && _num(selectedProcessScore) === 0 && (
                              <div style={{ marginTop: 8, color: "#fca5a5", fontSize: 12, lineHeight: 1.4 }}>
                                Indicator-level AnyRun intelligence is malicious, but this process has no assigned sandbox threat score.
                              </div>
                            )}
                            <div style={{ marginTop: 10, color: "#93c5fd", fontSize: 12 }}>
                              Indicators: {selectedThreatCount}
                            </div>
                          </div>
                        </div>
                      </AnalystCard>

                      <AnalystCard title="Process information">
                        <AnalystPair label="Username" value={selectedProcessDetail?.username || selected?.user || selected?.username || "-"} />
                        <AnalystPair label="SID" value={selectedProcessDetail?.sid || "-"} />
                        <AnalystPair label="IL" value={selectedProcessDetail?.integrity_level || "-"} />
                        <AnalystPair label="Start" value={selectedProcessDetail?.start || selected?.start || selected?.startedAt || selected?.time || "-"} />
                        <AnalystPair label="PID" value={selectedProcessDetail?.pid || selected?.pid || "-"} />
                        <AnalystPair label="PPID" value={selectedProcessDetail?.ppid || selected?.ppid || selected?.parentPid || "-"} />
                      </AnalystCard>

                      <AnalystCard title="File information">
                        <AnalystPair label="Company" value={selectedProcessDetail?.company || "-"} />
                        <AnalystPair label="Description" value={selectedProcessDetail?.description || "-"} />
                        <AnalystPair label="Version" value={selectedProcessDetail?.version || "-"} />
                        <AnalystPair label="SHA256" value={selectedProcessDetail?.sha256 || selected?.sha256 || "-"} long />
                      </AnalystCard>

                      <AnalystCard title="Command line">
                        <div
                          style={{
                            color: "#93c5fd",
                            fontSize: 12,
                            lineHeight: 1.45,
                            wordBreak: "break-word",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {selectedProcessDetail?.command_line || selected?.commandLine || selected?.cmd || "-"}
                        </div>
                      </AnalystCard>

                      <AnalystCard title="Events">
                        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                          {EVENT_CATEGORY_META.map((item) => {
                            const active = activeEventCategory === item.key;
                            const count = selectedEventCounts[item.key];
                            return (
                              <button
                                key={item.key}
                                type="button"
                                onClick={() => setActiveEventCategory(item.key)}
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "1fr auto",
                                  alignItems: "center",
                                  gap: 12,
                                  padding: "8px 10px",
                                  border: "none",
                                  borderRadius: 6,
                                  background: active ? "rgba(59,130,246,0.2)" : "transparent",
                                  color: active ? "#dbeafe" : "var(--text-secondary)",
                                  cursor: "pointer",
                                  textAlign: "left",
                                }}
                                title={item.description}
                              >
                                <span style={{ fontWeight: active ? 700 : 500 }}>{item.label}</span>
                                <span style={{ color: active ? "#93c5fd" : "var(--text-muted)", fontWeight: 700 }}>{count}</span>
                              </button>
                            );
                          })}
                        </div>
                      </AnalystCard>
                    </div>

                    <div style={{ minHeight: 0, display: "flex", flexDirection: "column", gap: 12, overflowY: "auto", paddingRight: 4 }}>
                      <AnalystCard title="Timeline of the process" bodyStyle={{ padding: 0 }}>
                        <div style={{ padding: "12px 12px 6px 12px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", color: "#93c5fd", fontSize: 12, marginBottom: 8 }}>
                            <span>0 s</span>
                            <span>
                              {selectedEventTimeline.length
                                ? `${Math.max(...selectedEventTimeline.map((point) => point.ms)).toFixed(0)} ms`
                                : "No event timing"}
                            </span>
                          </div>
                          <div
                            style={{
                              position: "relative",
                              height: 10,
                              borderRadius: 999,
                              background: "rgba(96,165,250,0.18)",
                              overflow: "hidden",
                              marginBottom: 18,
                            }}
                          >
                            <div style={{ position: "absolute", inset: 0, background: "linear-gradient(90deg, rgba(96,165,250,0.88), rgba(103,232,249,0.72))" }} />
                            {selectedEventTimeline.map((point) => (
                              <div
                                key={`timeline-${point.index}`}
                                style={{
                                  position: "absolute",
                                  top: -7,
                                  left: `${point.left}%`,
                                  width: 2,
                                  height: 24,
                                  background:
                                    point.severity === "danger"
                                      ? "#f87171"
                                      : point.severity === "warning"
                                        ? "#facc15"
                                        : "#93c5fd",
                                }}
                              />
                            ))}
                          </div>
                          <div style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 10 }}>
                            Active category: <span style={{ color: "#dbeafe", fontWeight: 700 }}>{activeEventMeta.label}</span>
                          </div>
                        </div>
                        <div style={{ borderTop: "1px solid rgba(59,130,246,0.18)", padding: "10px 12px 12px 12px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 18, marginBottom: 10, color: "var(--text-muted)", fontSize: 12 }}>
                            <span><span style={{ color: "var(--red)" }}>●</span> Danger</span>
                            <span><span style={{ color: "var(--yellow)" }}>●</span> Warning</span>
                            <span><span style={{ color: "var(--accent)" }}>●</span> Other</span>
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            <AnalystStatChip label="Rows" value={selectedEventCategoryRows.length} />
                            <AnalystStatChip label="Flattened events" value={selectedEvents.length} />
                            <AnalystStatChip label="Process score" value={selectedProcessScore} />
                          </div>
                        </div>
                      </AnalystCard>

                      <AnalystCard
                        title={processViewMode === "view" ? `${activeEventMeta.label} overview` : processViewMode === "group" ? `${activeEventMeta.label} grouped events` : `${activeEventMeta.label} deep events`}
                      >
                        <div style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 12 }}>
                          {activeEventMeta.description}
                        </div>

                        {processViewMode === "view" && (
                          selectedEventCategoryRows.length === 0 ? (
                            <EmptyNote>No {activeEventMeta.label.toLowerCase()} recorded for this process.</EmptyNote>
                          ) : (
                            <div style={{ display: "grid", gap: 8 }}>
                              {selectedEventCategoryRows.slice(0, 12).map((row, index) => {
                                const event = selectedEvents[index];
                                const detailRows = _extractEventDetailRows((event?.details || row) as Record<string, any>);
                                return (
                                  <div
                                    key={`overview-row-${index}`}
                                    style={{
                                      border: "1px solid rgba(96,165,250,0.18)",
                                      borderRadius: 8,
                                      background: "rgba(7,47,70,0.72)",
                                      padding: "10px 12px",
                                    }}
                                  >
                                    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
                                      <div style={{ color: "var(--text-primary)", fontWeight: 700 }}>
                                        {event?.title || _extractEventTitle(row, activeEventCategory)}
                                      </div>
                                      <div style={{ color: "#93c5fd", fontSize: 12, whiteSpace: "nowrap" }}>
                                        {event?.timeshift || _extractTimeshift(row)}
                                      </div>
                                    </div>
                                    {detailRows.length === 0 ? (
                                      <div style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                                        No structured details available for this event.
                                      </div>
                                    ) : (
                                      detailRows.slice(0, 4).map((detail, detailIndex) => (
                                        <div
                                          key={`overview-detail-${index}-${detailIndex}`}
                                          style={{
                                            color: "var(--text-secondary)",
                                            fontSize: 12,
                                            marginBottom: detailIndex === 3 ? 0 : 6,
                                            lineHeight: 1.5,
                                            display: "grid",
                                            gap: 2,
                                            minWidth: 0,
                                          }}
                                        >
                                          <strong>{detail.key}:</strong>
                                          <div
                                            style={{
                                              maxWidth: "100%",
                                              overflowWrap: "anywhere",
                                              wordBreak: "break-word",
                                              whiteSpace: "pre-wrap",
                                            }}
                                          >
                                            {detail.value}
                                          </div>
                                        </div>
                                      ))
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          )
                        )}

                        {processViewMode === "group" && (
                          selectedEvents.length === 0 ? (
                            <EmptyNote>No group details available for {activeEventMeta.label.toLowerCase()}.</EmptyNote>
                          ) : (
                            <div>
                              {(["danger", "warning", "other"] as const).map((sev) => {
                                const byTech = groupedBySeverityAndTechnique[sev];
                                const techKeys = Object.keys(byTech || {});
                                if (!techKeys.length) return null;
                                const color = sev === "danger" ? "var(--red)" : sev === "warning" ? "var(--yellow)" : "var(--accent)";
                                return (
                                  <div key={`sev-${sev}`} style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                                    <div style={{ padding: "7px 10px", borderBottom: "1px solid var(--border-dim)", color, fontWeight: 700, background: "rgba(2,23,39,0.55)" }}>
                                      {sev.toUpperCase()} {techKeys.length}
                                    </div>
                                    <div>
                                      {techKeys.map((tech) => (
                                        <details key={`tech-${sev}-${tech}`} style={{ borderTop: "1px solid var(--border-dim)" }} open>
                                          <summary style={{ cursor: "pointer", listStyle: "none", padding: "8px 10px", color: "var(--text-secondary)" }}>
                                            <span style={{ color: "var(--accent)", fontWeight: 700 }}>
                                              {tech === "UNMAPPED" ? "Unmapped events" : tech}
                                            </span>{" "}
                                            ({byTech[tech].length})
                                          </summary>
                                          <div style={{ padding: "0 14px 10px 14px" }}>
                                            {byTech[tech].map((e, i) => (
                                              <div key={`ev-${sev}-${tech}-${i}`} style={{ marginBottom: 4, color: "var(--text-primary)", fontSize: 13 }}>
                                                └ {e.title}
                                              </div>
                                            ))}
                                          </div>
                                        </details>
                                      ))}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          )
                        )}

                        {processViewMode === "deep" && (
                          selectedEvents.length === 0 ? (
                            <EmptyNote>No deep event data available for {activeEventMeta.label.toLowerCase()}.</EmptyNote>
                          ) : (
                            selectedEvents.map((e, i) => {
                              const sevColor = e.severity === "danger" ? "var(--red)" : e.severity === "warning" ? "var(--yellow)" : "var(--accent)";
                              const d = e.details || {};
                              return (
                                <details key={`deep-${i}`} open style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                                  <summary style={{ cursor: "pointer", listStyle: "none", padding: "8px 10px", borderBottom: "1px solid var(--border-dim)", background: "rgba(2,23,39,0.55)" }}>
                                    <span style={{ color: "var(--text-primary)", fontWeight: 700 }}>{e.timeshift}</span>{" "}
                                    <span style={{ color: "var(--text-primary)", marginLeft: 10 }}>{e.title}</span>{" "}
                                    <span style={{ color: sevColor, marginLeft: 10, fontWeight: 700 }}>
                                      {e.technique_id === "UNMAPPED" ? "UNMAPPED" : e.technique_id}
                                    </span>
                                  </summary>
                                  <div style={{ padding: 10, background: "rgba(14,116,144,0.22)" }}>
                                    {(() => {
                                      const rows = _extractEventDetailRows(d);
                                      if (!rows.length) {
                                        return (
                                          <div style={{ marginBottom: 0, color: "var(--text-secondary)" }}>
                                            No structured details available for this event.
                                          </div>
                                        );
                                      }
                                      return rows.map((row, rowIdx) => (
                                        <div
                                          key={`deep-row-${i}-${rowIdx}`}
                                          style={{
                                            marginBottom: rowIdx === rows.length - 1 ? 0 : 6,
                                            color: "var(--text-secondary)",
                                            lineHeight: 1.5,
                                            display: "grid",
                                            gap: 2,
                                            minWidth: 0,
                                          }}
                                        >
                                          <strong>{row.key}:</strong>
                                          <div
                                            style={{
                                              maxWidth: "100%",
                                              overflowWrap: "anywhere",
                                              wordBreak: "break-word",
                                              whiteSpace: "pre-wrap",
                                            }}
                                          >
                                            {row.value}
                                          </div>
                                        </div>
                                      ));
                                    })()}
                                  </div>
                                </details>
                              );
                            })
                          )
                        )}
                      </AnalystCard>
                    </div>
                  </div>
                </>
              ) : (
                <>
              <div style={{ padding: "10px 12px", borderBottom: "1px solid #1b4d6b", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ color: "var(--text-primary)", fontSize: 16, fontWeight: 700 }}>
                  Advanced details of process{" "}
                  <span style={{ color: "var(--accent)" }}>
                    [{selected?.pid || selectedProcessDetail?.pid || "-"}]{" "}
                    {selected?.fileName || selected?.image || selected?.processName || selected?.name || selectedProcessDetail?.name || "-"}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <button
                    type="button"
                    onClick={() => setProcessViewMode("view")}
                    style={{
                      padding: "6px 10px",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      background: processViewMode === "view" ? "rgba(56,189,248,0.2)" : "rgba(2,23,39,0.5)",
                      color: processViewMode === "view" ? "var(--accent)" : "var(--text-muted)",
                      cursor: "pointer",
                    }}
                  >
                    View
                  </button>
                  <button
                    type="button"
                    onClick={() => setProcessViewMode("group")}
                    style={{
                      padding: "6px 10px",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      background: processViewMode === "group" ? "rgba(56,189,248,0.2)" : "rgba(2,23,39,0.5)",
                      color: processViewMode === "group" ? "var(--accent)" : "var(--text-muted)",
                      cursor: "pointer",
                    }}
                  >
                    Group
                  </button>
                  <button
                    type="button"
                    onClick={() => setProcessViewMode("deep")}
                    style={{
                      padding: "6px 10px",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      background: processViewMode === "deep" ? "rgba(56,189,248,0.2)" : "rgba(2,23,39,0.5)",
                      color: processViewMode === "deep" ? "var(--accent)" : "var(--text-muted)",
                      cursor: "pointer",
                    }}
                  >
                    Deep
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(false)}
                    style={{
                      marginLeft: 6,
                      border: "none",
                      background: "transparent",
                      color: "var(--text-muted)",
                      cursor: "pointer",
                      fontSize: 20,
                    }}
                  >
                    ×
                  </button>
                </div>
              </div>
              <div style={{ padding: 12 }}>
                {processViewMode === "view" && (
                  <EvidenceTable
                    title="Main Information"
                    data={[
                      { field: "Process Verdict", value: selectedProcessThreatLevel >= 2 ? "MALICIOUS" : selectedProcessThreatLevel >= 1 ? "SUSPICIOUS" : "NO PROCESS VERDICT" },
                      { field: "Process Score", value: selectedProcessScore ?? "-" },
                      { field: "Username", value: selectedProcessDetail?.username || selected?.user || selected?.username || "-" },
                      { field: "SID", value: selectedProcessDetail?.sid || "-" },
                      { field: "Integrity Level", value: selectedProcessDetail?.integrity_level || "-" },
                      { field: "Start", value: selectedProcessDetail?.start || selected?.start || selected?.startedAt || selected?.time || "-" },
                      { field: "Company", value: selectedProcessDetail?.company || "-" },
                      { field: "Description", value: selectedProcessDetail?.description || "-" },
                      { field: "Version", value: selectedProcessDetail?.version || "-" },
                      { field: "Command line", value: selectedProcessDetail?.command_line || selected?.commandLine || selected?.cmd || "-" },
                    ]}
                    columns={[{ key: "field" }, { key: "value", wrap: true }]}
                  />
                )}
                {processViewMode === "group" && (
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 10, color: "var(--text-muted)", fontSize: 12 }}>
                      <span><span style={{ color: "var(--red)" }}>●</span> Danger</span>
                      <span><span style={{ color: "var(--yellow)" }}>●</span> Warning</span>
                      <span><span style={{ color: "var(--accent)" }}>●</span> Other</span>
                    </div>
                    {(["danger", "warning", "other"] as const).map((sev) => {
                      const byTech = groupedBySeverityAndTechnique[sev];
                      const techKeys = Object.keys(byTech || {});
                      if (!techKeys.length) return null;
                      const color = sev === "danger" ? "var(--red)" : sev === "warning" ? "var(--yellow)" : "var(--accent)";
                      return (
                        <div key={`sev-${sev}`} style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                          <div style={{ padding: "7px 10px", borderBottom: "1px solid var(--border-dim)", color, fontWeight: 700, background: "rgba(2,23,39,0.55)" }}>
                            {sev.toUpperCase()} {techKeys.length}
                          </div>
                          <div>
                            {techKeys.map((tech) => (
                              <details key={`tech-${sev}-${tech}`} style={{ borderTop: "1px solid var(--border-dim)" }} open>
                                <summary style={{ cursor: "pointer", listStyle: "none", padding: "8px 10px", color: "var(--text-secondary)" }}>
                                  <span style={{ color: "var(--accent)", fontWeight: 700 }}>
                                    {tech === "UNMAPPED" ? "Unmapped events" : tech}
                                  </span>{" "}
                                  ({byTech[tech].length})
                                </summary>
                                <div style={{ padding: "0 14px 10px 14px" }}>
                                  {byTech[tech].map((e, i) => (
                                    <div key={`ev-${sev}-${tech}-${i}`} style={{ marginBottom: 4, color: "var(--text-primary)", fontSize: 13 }}>
                                      └ {e.title}
                                    </div>
                                  ))}
                                </div>
                              </details>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
                {processViewMode === "deep" && (
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 10, color: "var(--text-muted)", fontSize: 12 }}>
                      <span><span style={{ color: "var(--red)" }}>●</span> Danger</span>
                      <span><span style={{ color: "var(--yellow)" }}>●</span> Warning</span>
                      <span><span style={{ color: "var(--accent)" }}>●</span> Other</span>
                    </div>
                    {selectedEvents.length === 0 ? (
                      <EmptyNote>No deep event data available for this process.</EmptyNote>
                    ) : (
                      selectedEvents.map((e, i) => {
                        const sevColor = e.severity === "danger" ? "var(--red)" : e.severity === "warning" ? "var(--yellow)" : "var(--accent)";
                        const d = e.details || {};
                        return (
                          <details key={`deep-${i}`} open style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
                            <summary style={{ cursor: "pointer", listStyle: "none", padding: "8px 10px", borderBottom: "1px solid var(--border-dim)", background: "rgba(2,23,39,0.55)" }}>
                              <span style={{ color: "var(--text-primary)", fontWeight: 700 }}>{e.timeshift}</span>{" "}
                              <span style={{ color: "var(--text-primary)", marginLeft: 10 }}>{e.title}</span>{" "}
                              <span style={{ color: sevColor, marginLeft: 10, fontWeight: 700 }}>
                                {e.technique_id === "UNMAPPED" ? "UNMAPPED" : e.technique_id}
                              </span>
                            </summary>
                            <div style={{ padding: 10, background: "rgba(14,116,144,0.22)" }}>
                              {(() => {
                                const rows = _extractEventDetailRows(d);
                                if (!rows.length) {
                                  return (
                                    <div style={{ marginBottom: 0, color: "var(--text-secondary)" }}>
                                      No structured details available for this event.
                                    </div>
                                  );
                                }
                                return rows.map((row, rowIdx) => (
                                  <div
                                    key={`deep-row-${i}-${rowIdx}`}
                                    style={{
                                      marginBottom: rowIdx === rows.length - 1 ? 0 : 6,
                                      color: "var(--text-secondary)",
                                      lineHeight: 1.5,
                                      display: "grid",
                                      gap: 2,
                                      minWidth: 0,
                                    }}
                                  >
                                    <strong>{row.key}:</strong>
                                    <div
                                      style={{
                                        maxWidth: "100%",
                                        overflowWrap: "anywhere",
                                        wordBreak: "break-word",
                                        whiteSpace: "pre-wrap",
                                      }}
                                    >
                                      {row.value}
                                    </div>
                                  </div>
                                ));
                              })()}
                            </div>
                          </details>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
                </>
              )}
            </div>
          </div>
        </div>
      ), document.body)}
    </div>
  );
}

function DataGrid({
  title,
  rows,
  columns,
}: {
  title: string;
  rows: Record<string, any>[];
  columns: GridCol[];
}) {
  const colDefs = React.useMemo<ColumnDef<Record<string, any>>[]>(
    () =>
      columns.map((c) => ({
        accessorKey: c.key,
        header: c.label,
        cell: (ctx) => {
          const v = ctx.getValue() as any;
          const text = v == null || v === "" ? "-" : String(v);
          return (
            <div
              title={text}
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                maxWidth: c.maxWidth || 360,
                minWidth: c.minWidth || 80,
                whiteSpace: "nowrap",
                wordBreak: "normal",
              }}
            >
              {text}
            </div>
          );
        },
      })),
    [columns]
  );

  const table = useReactTable({
    data: rows,
    columns: colDefs,
    getCoreRowModel: getCoreRowModel(),
  });

  const minTableWidth = Math.max(
    1800,
    columns.reduce((acc, c) => acc + (c.minWidth || 170), 0)
  );

  const topScrollRef = React.useRef<HTMLDivElement | null>(null);
  const bottomScrollRef = React.useRef<HTMLDivElement | null>(null);
  const syncingRef = React.useRef<"top" | "bottom" | null>(null);

  const syncFromTop = React.useCallback(() => {
    if (!topScrollRef.current || !bottomScrollRef.current) return;
    if (syncingRef.current === "bottom") return;
    syncingRef.current = "top";
    bottomScrollRef.current.scrollLeft = topScrollRef.current.scrollLeft;
    requestAnimationFrame(() => {
      syncingRef.current = null;
    });
  }, []);

  const syncFromBottom = React.useCallback(() => {
    if (!topScrollRef.current || !bottomScrollRef.current) return;
    if (syncingRef.current === "top") return;
    syncingRef.current = "bottom";
    topScrollRef.current.scrollLeft = bottomScrollRef.current.scrollLeft;
    requestAnimationFrame(() => {
      syncingRef.current = null;
    });
  }, []);

  return (
    <div
      style={{
        marginBottom: 14,
        width: "100%",
        maxWidth: "100%",
        minWidth: 0,
      }}
    >
      <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6 }}>{title}</div>
      {!rows.length ? (
        <EmptyNote>No data.</EmptyNote>
      ) : (
        <>
          <div
            ref={topScrollRef}
            onScroll={syncFromTop}
            style={{
              overflowX: "auto",
              overflowY: "hidden",
              height: 12,
              border: "1px solid var(--border)",
              borderRadius: 8,
              marginBottom: 6,
            }}
          >
            <div style={{ width: minTableWidth, height: 1 }} />
          </div>
        <div
          ref={bottomScrollRef}
          onScroll={syncFromBottom}
          style={{ overflowX: "auto", border: "1px solid var(--border)", borderRadius: 8 }}
        >
          <table style={{ width: "100%", minWidth: minTableWidth, borderCollapse: "collapse", tableLayout: "auto" }}>
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id} style={{ background: "rgba(148,163,184,0.08)" }}>
                  {hg.headers.map((h) => (
                    <th
                      key={h.id}
                      style={{
                        textAlign: "left",
                        fontSize: 11,
                        color: "var(--text-muted)",
                        padding: "8px 10px",
                        borderBottom: "1px solid var(--border)",
                        position: "sticky",
                        top: 0,
                        background: "rgba(15,23,42,0.96)",
                      }}
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((r) => (
                <tr key={r.id}>
                  {r.getVisibleCells().map((c) => (
                    <td
                      key={c.id}
                      style={{
                        fontSize: 12,
                        color: (() => {
                          const sev = severityFromValue(c.getValue(), String(c.column.id));
                          if (sev === "malicious") return "var(--red)";
                          if (sev === "suspicious") return "var(--yellow)";
                          if (sev === "legit") return "var(--green)";
                          return "var(--text-primary)";
                        })(),
                        padding: "8px 10px",
                        borderBottom: "1px solid var(--border-dim)",
                        maxWidth: 520,
                        verticalAlign: "top",
                        background: (() => {
                          const sev = severityFromValue(c.getValue(), String(c.column.id));
                          if (sev === "malicious") return "rgba(239,68,68,0.10)";
                          if (sev === "suspicious") return "rgba(245,158,11,0.10)";
                          if (sev === "legit") return "rgba(52,211,153,0.10)";
                          return "transparent";
                        })(),
                      }}
                    >
                      {flexRender(c.column.columnDef.cell, c.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </>
      )}
    </div>
  );
}

export default function AnyRunInteractiveEvidence({ hybridAnalysis, investigationId, onRefresh }: Props) {
  const [rerunConfirm, setRerunConfirm] = React.useState(false);
  const [rerunning, setRerunning] = React.useState(false);
  const [rerunError, setRerunError] = React.useState<string | null>(null);
  const [rerunStarted, setRerunStarted] = React.useState(false);
  const [rerunElapsed, setRerunElapsed] = React.useState(0);
  const RERUN_TIMEOUT = 180; // seconds
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const tickRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = React.useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    if (tickRef.current) { clearInterval(tickRef.current); tickRef.current = null; }
  }, []);

  // Stop polling when evidence is no longer cached (re-run completed)
  React.useEffect(() => {
    if (!rerunStarted) return;
    const isCached = arr(hybridAnalysis?.items).some((i: any) => i?.cache_hit);
    if (!isCached) {
      stopPolling();
      setRerunStarted(false);
      setRerunElapsed(0);
    }
  }, [hybridAnalysis, rerunStarted, stopPolling]);

  // Cleanup on unmount
  React.useEffect(() => () => stopPolling(), [stopPolling]);

  const handleRerun = React.useCallback(async () => {
    if (!investigationId) return;
    setRerunning(true);
    setRerunError(null);
    try {
      const { rerunCollector } = await import("@/lib/api");
      await rerunCollector(investigationId, "hybrid_analysis");
      setRerunStarted(true);
      setRerunConfirm(false);
      setRerunElapsed(0);

      // 1-second tick for progress bar
      tickRef.current = setInterval(() => {
        setRerunElapsed((prev) => {
          if (prev >= RERUN_TIMEOUT) { stopPolling(); return prev; }
          return prev + 1;
        });
      }, 1_000);

      // Refresh evidence every 10 s
      pollRef.current = setInterval(() => {
        onRefresh?.();
      }, 10_000);
    } catch (e: any) {
      setRerunError(e?.message || "Re-run failed");
    } finally {
      setRerunning(false);
    }
  }, [investigationId, onRefresh, stopPolling]);

  const items = arr(hybridAnalysis?.items);
  if (!items.length) {
    return (
      <EmptyNote>
        {hybridAnalysis?.meta?.status === "failed"
          ? `Sandbox collector failed: ${hybridAnalysis?.meta?.error || "unknown error"}`
          : "Sandbox data not available (collector not run)"}
      </EmptyNote>
    );
  }

  return (
    <ReactFlowProvider>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10 }}>
        Source priority: Any.Run first, Hybrid fallback.
      </div>
      <EvidenceTable
        title="Sandbox Verdicts"
        data={items.map((item: any, idx: number) => ({
          index: idx + 1,
          source: String(item?.raw_summary?.source || "hybrid").toUpperCase(),
          type: item?.indicator_type || "unknown",
          mode: String(item?.raw_summary?.mode || "lookup").toUpperCase(),
          execution: item?.cache_hit ? "CACHED" : "LIVE",
          verdict: String(item?.verdict || "unknown").toUpperCase(),
          threat_score: item?.threat_score ?? "—",
          analysis_id: item?.analysis_id || "—",
          error: item?.error || "—",
        }))}
        columns={[
          { key: "index", label: "#" },
          { key: "source", label: "Source" },
          { key: "type", label: "Indicator Type" },
          { key: "mode", label: "Mode" },
          { key: "execution", label: "Execution" },
          { key: "verdict", label: "Verdict" },
          { key: "threat_score", label: "Threat Score" },
          { key: "analysis_id", label: "Analysis ID", wrap: true },
          { key: "error", label: "Status/Error", wrap: true },
        ]}
        showHeader
      />

      {/* Re-run button — shown when the result is cached and a fresh sandbox is possible */}
      {investigationId && items.some((i: any) => i?.cache_hit) && (
        <div style={{ marginBottom: 12 }}>
          {!rerunStarted ? (
            !rerunConfirm ? (
              <button
                onClick={() => { setRerunConfirm(true); setRerunError(null); }}
                style={{
                  fontSize: 11, padding: "4px 12px", borderRadius: 4, cursor: "pointer",
                  background: "var(--color-accent, #2563eb)", color: "#fff", border: "none",
                }}
              >
                Re-run live sandbox (bypass cache)
              </button>
            ) : (
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 8,
                background: "var(--bg-card, #1e293b)", border: "1px solid var(--border, #334155)",
                borderRadius: 6, padding: "6px 12px", fontSize: 11,
              }}>
                <span>Submit a fresh AnyRun sandbox task? This may take 2–3 minutes.</span>
                <button
                  onClick={handleRerun}
                  disabled={rerunning}
                  style={{
                    padding: "3px 10px", borderRadius: 4, cursor: rerunning ? "wait" : "pointer",
                    background: "#16a34a", color: "#fff", border: "none", fontSize: 11,
                  }}
                >
                  {rerunning ? "Submitting…" : "Confirm"}
                </button>
                <button
                  onClick={() => setRerunConfirm(false)}
                  disabled={rerunning}
                  style={{
                    padding: "3px 10px", borderRadius: 4, cursor: "pointer",
                    background: "transparent", color: "var(--text-muted)", border: "1px solid var(--border, #334155)", fontSize: 11,
                  }}
                >
                  Cancel
                </button>
                {rerunError && <span style={{ color: "#ef4444" }}>{rerunError}</span>}
              </div>
            )
          ) : (
            <div style={{ fontSize: 11 }}>
              <div style={{ marginBottom: 4, color: "var(--text-muted)" }}>
                {rerunElapsed >= RERUN_TIMEOUT
                  ? "Sandbox timed out — result may still arrive. Refresh manually."
                  : `Sandbox running… ${rerunElapsed}s / ${RERUN_TIMEOUT}s`}
              </div>
              <div style={{
                height: 4, borderRadius: 2, background: "var(--border, #334155)",
                width: 240, overflow: "hidden",
              }}>
                <div style={{
                  height: "100%", borderRadius: 2,
                  background: rerunElapsed >= RERUN_TIMEOUT ? "#ef4444" : "#2563eb",
                  width: `${Math.min(100, (rerunElapsed / RERUN_TIMEOUT) * 100)}%`,
                  transition: "width 1s linear",
                }} />
              </div>
            </div>
          )}
        </div>
      )}

      {items.map((item: any, idx: number) => {
        const raw = item?.raw_summary || {};
        const sourceLower = String(raw?.source || "").toLowerCase();
        const modeLower = String(raw?.mode || "").toLowerCase();
        const summary = raw?.summary || {};
        const details = arr(summary?.details);
        const io = item?.dynamic_io_summary || {};
        const domains = arr(io?.domains).filter(isFlagged);
        const hosts = arr(io?.hosts).filter(isFlagged);
        const anyrunIocs = arr(raw?.iocs);
        const anyrunAiSummary = String(raw?.anyrun_ai_summary || "").trim();
        const behaviorCounts = raw?.behavior_counts || {};
        const behaviorDetails = raw?.behavior_details || {};
        const hasSandboxTask = Boolean(item?.analysis_id || item?.analysis_link);
        const hasBehaviorDetails =
          arr(behaviorDetails?.dns_requests).length > 0 ||
          arr(behaviorDetails?.connections).length > 0 ||
          arr(behaviorDetails?.http_requests).length > 0 ||
          arr(behaviorDetails?.network_threats).length > 0 ||
          arr(behaviorDetails?.processes).length > 0 ||
          arr(behaviorDetails?.process_details).length > 0;
        const isLookupOnly = modeLower === "lookup" || modeLower === "lookup_deferred";
        const showSandboxSections = !isLookupOnly && (hasSandboxTask || hasBehaviorDetails);
        const anyrunLink = sourceLower === "anyrun"
          ? (
            (typeof item?.analysis_link === "string" && item.analysis_link.startsWith("http"))
              ? item.analysis_link
              : (item?.analysis_id ? `https://app.any.run/tasks/${item.analysis_id}` : null)
          )
          : null;
        const anyrunFallbackError = String(raw?.anyrun_error || "").trim();

        const dnsRows = arr(behaviorDetails?.dns_requests).map((d: any) => ({
          timeshift: d?.time || d?.timestamp || "-",
          rep: d?.reputation || d?.reputationNumber || "-",
          domain: d?.domainName || d?.domain || d?.hostname || "-",
          ips: arr(d?.ips).join(", ") || arr(d?.answers).join(", ") || d?.resolvedTo || "-",
          threat: d?.threatLevel ?? "-",
        }));
        const connRows = arr(behaviorDetails?.connections).map((c: any) => ({
          timeshift: c?.time || c?.timestamp || "-",
          protocol: c?.protocol || "-",
          rep: c?.reputation || "-",
          pid: c?.pid ?? "-",
          process_name: c?.processName ?? c?.process ?? "-",
          cn: c?.country || c?.geo?.country || "-",
          ip: c?.destinationIP || c?.ip || c?.host || "-",
          port: c?.destinationPort ?? c?.port ?? "-",
          domain: c?.domain || "-",
          asn: c?.asn || "-",
          traffic: c?.traffic || "-",
        }));
        const httpRows = arr(behaviorDetails?.http_requests).map((h: any) => ({
          timeshift: h?.time || h?.timestamp || "-",
          headers: `${h?.method || "-"}${h?.httpCode ? ` - ${h.httpCode}` : ""}`,
          rep: h?.reputation || "-",
          pid: h?.pid ?? "-",
          process_name: h?.processName ?? h?.process ?? "-",
          cn: h?.country || "-",
          url: h?.url || h?.requestUrl || "-",
          content: h?.content || h?.body?.response?.size || h?.mimeType || h?.contentType || "-",
        }));
        const threatRows = arr(behaviorDetails?.network_threats).map((t: any) => ({
          type: t?.class || t?.category || t?.type || "-",
          indicator: t?.indicator || t?.domain || t?.destinationIP || t?.url || "-",
          threat_level: t?.threatLevel ?? t?.priority ?? t?.severity ?? "-",
          threat_name: normalizedAnyrunLabels(t?.threatName).join(", ") || t?.name || "-",
          description: t?.description || t?.msg || "-",
        }));

        return (
          <div key={`anyrun-${idx}`} style={{ marginTop: 14 }}>
            {sourceLower !== "anyrun" && anyrunFallbackError && (
              <div
                style={{
                  marginBottom: 10,
                  padding: "8px 10px",
                  border: "1px solid rgba(245,158,11,0.45)",
                  background: "rgba(245,158,11,0.08)",
                  color: "var(--yellow)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              >
                Any.Run unavailable for this sample. Fallback source used: {String(raw?.source || "hybrid").toUpperCase()}.
                {" "}Reason: {anyrunFallbackError}
              </div>
            )}
            {(() => {
              const tiThreatNames = normalizedAnyrunLabels(raw?.threatName || item?.threat_names);
              const tiTags = normalizedAnyrunLabels(raw?.tags);
              const allLabels = _uniq([...tiThreatNames, ...tiTags]).filter(Boolean);
              const relatedTasksCount = Number(raw?.related_tasks_count || 0);
              const relatedIncidents: any[] = arr(raw?.relatedIncidents).slice(0, 5);
              if (!allLabels.length && !relatedTasksCount && !relatedIncidents.length) return null;
              return (
                <div style={{ marginBottom: 10, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                  {allLabels.map((label: string, i: number) => (
                    <span
                      key={i}
                      style={{
                        padding: "2px 8px",
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                        background: "rgba(239,68,68,0.12)",
                        color: "#ef4444",
                        border: "1px solid rgba(239,68,68,0.30)",
                        letterSpacing: "0.02em",
                      }}
                    >
                      {label}
                    </span>
                  ))}
                  {relatedTasksCount > 0 && (
                    <span style={{ fontSize: 11, color: "var(--text-secondary)", marginLeft: 4 }}>
                      {relatedTasksCount} community submission{relatedTasksCount !== 1 ? "s" : ""}
                    </span>
                  )}
                  {relatedIncidents.map((inc: any, i: number) => {
                    const title = String(inc?.title || inc?.name || "").trim();
                    return title ? (
                      <span
                        key={`inc-${i}`}
                        style={{
                          padding: "2px 8px",
                          borderRadius: 4,
                          fontSize: 11,
                          background: "rgba(245,158,11,0.10)",
                          color: "#f59e0b",
                          border: "1px solid rgba(245,158,11,0.25)",
                        }}
                      >
                        {title}
                      </span>
                    ) : null;
                  })}
                </div>
              );
            })()}
            <EvidenceTable
              title={`Any.Run Evidence #${idx + 1}`}
              data={[
                { field: "Detected Type", value: summary?.detectedType || item?.indicator_type || "-" },
                { field: "Threat Level", value: summary?.threatLevel ?? "-" },
                { field: "Last Seen", value: summary?.lastSeen || "-" },
                ...(showSandboxSections
                  ? [
                      { field: "HTTP Requests", value: behaviorCounts?.http_requests ?? httpRows.length ?? "?" },
                      { field: "Connections", value: behaviorCounts?.connections ?? connRows.length ?? "?" },
                      { field: "DNS Requests", value: behaviorCounts?.dns_requests ?? dnsRows.length ?? "?" },
                      { field: "Network Threats", value: behaviorCounts?.network_threats ?? threatRows.length ?? "?" },
                    ]
                  : []),
                { field: "Task URL", value: anyrunLink || "-" },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />

            {!showSandboxSections && (() => {
              const itemVerdict = String(item?.verdict || "").toLowerCase();
              const isMaliciousLookup = itemVerdict === "malicious";
              const isSandboxFailure = !item?.checked && modeLower === "sandbox";
              const sandboxError = String(item?.error || "").trim();
              const domainIntel = item?.domain_intelligence;
              const domainIntelVerdict = String(domainIntel?.verdict || "").toLowerCase();
              const domainIntelMalicious = domainIntel?.checked && domainIntelVerdict === "malicious";
              const domainIntelHostname = String(domainIntel?.hostname || "").trim();
              const borderColor = isMaliciousLookup || domainIntelMalicious
                ? "1px solid rgba(239,68,68,0.30)"
                : isSandboxFailure
                  ? "1px solid rgba(245,158,11,0.30)"
                  : "1px solid rgba(96,165,250,0.20)";
              const bgColor = isMaliciousLookup || domainIntelMalicious
                ? "rgba(239,68,68,0.07)"
                : isSandboxFailure
                  ? "rgba(245,158,11,0.07)"
                  : "rgba(96,165,250,0.07)";
              return (
                <div
                  style={{
                    marginBottom: 12,
                    padding: "10px 12px",
                    border: borderColor,
                    background: bgColor,
                    color: "var(--text-secondary)",
                    borderRadius: 8,
                    fontSize: 12,
                    lineHeight: 1.6,
                  }}
                >
                  {isMaliciousLookup ? (
                    <>
                      <strong style={{ color: "var(--red, #ef4444)" }}>MALICIOUS</strong> verdict confirmed by AnyRun
                      threat intelligence community. This indicator was previously analysed and classified as malicious
                      by community sandbox submissions. Live behavioral data (process tree, DNS, HTTP) is not available
                      in this lookup-only result — submit to sandbox for execution details.
                    </>
                  ) : isSandboxFailure ? (
                    <>
                      <strong style={{ color: "#f59e0b" }}>Sandbox attempt failed.</strong>{" "}
                      AnyRun submitted this indicator to the sandbox but did not receive a completed report.
                      {sandboxError && (
                        <span style={{ display: "block", marginTop: 4, fontStyle: "italic", opacity: 0.85 }}>
                          Reason: {sandboxError}
                        </span>
                      )}
                      {domainIntelMalicious && domainIntelHostname && (
                        <span style={{ display: "block", marginTop: 6, color: "#ef4444", fontWeight: 600 }}>
                          Domain intelligence for {domainIntelHostname} shows MALICIOUS — see the Domain Intelligence section below.
                        </span>
                      )}
                    </>
                  ) : domainIntelMalicious ? (
                    <>
                      URL lookup returned a <strong>CLEAN</strong> verdict from AnyRun intelligence. However,{" "}
                      <strong style={{ color: "#ef4444" }}>domain intelligence
                      {domainIntelHostname ? ` for ${domainIntelHostname}` : ""} shows MALICIOUS</strong> — see the
                      Domain Intelligence section below. Phishing pages that evade automated URL scanning are commonly
                      flagged at the domain level rather than the URL level.
                    </>
                  ) : (
                    <>
                      This result comes from Any.Run lookup intelligence only. The official SDK returns rich behavior
                      details only after a real sandbox task ID and completed report are available. This entry did not
                      produce a completed sandbox report, so process, DNS, connection, and HTTP behavior details are not
                      available here.
                    </>
                  )}
                  <div style={{
                    marginTop: 10,
                    paddingTop: 8,
                    borderTop: "1px solid rgba(245,158,11,0.20)",
                    color: "rgba(245,158,11,0.85)",
                    fontSize: 11,
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 6,
                  }}>
                    <span style={{ fontWeight: 700, flexShrink: 0 }}>⚠ Analyst note:</span>
                    <span>
                      Phishing pages that require user interaction (form submission, credential entry) may evade
                      automated sandbox detection and return a CLEAN or UNKNOWN verdict. A negative or inconclusive
                      result does <strong>not</strong> rule out phishing. Correlate with threat intelligence tags,
                      domain age, certificate details, and visual inspection before clearing.
                    </span>
                  </div>
                </div>
              );
            })()}

            {anyrunAiSummary && (
              <EvidenceTable
                title="Any.Run AI Summary"
                data={[{ summary: anyrunAiSummary }]}
                columns={[{ key: "summary", wrap: true }]}
              />
            )}

            {/* Domain-level TI intelligence (shown alongside URL result when available) */}
            {(() => {
              const di = item?.domain_intelligence;
              if (!di || !di.checked) return null;
              const diSummary = di?.raw_summary?.summary || {};
              const diVerdict = String(di?.verdict || "unknown").toUpperCase();
              const diLink = di?.analysis_id
                ? (typeof di?.analysis_link === "string" && di.analysis_link.startsWith("http")
                    ? di.analysis_link
                    : `https://app.any.run/tasks/${di.analysis_id}`)
                : null;
              const domainLabel = String(di?.hostname || "domain lookup");
              const verdictColor = diVerdict === "MALICIOUS" ? "var(--red, #ef4444)"
                : diVerdict === "SUSPICIOUS" ? "var(--yellow, #f59e0b)"
                : "var(--text-secondary)";
              return (
                <div style={{
                  marginBottom: 12,
                  padding: "10px 14px",
                  border: `1px solid ${diVerdict === "MALICIOUS" ? "rgba(239,68,68,0.35)" : "rgba(96,165,250,0.20)"}`,
                  background: diVerdict === "MALICIOUS" ? "rgba(239,68,68,0.06)" : "rgba(96,165,250,0.05)",
                  borderRadius: 8,
                  fontSize: 12,
                }}>
                  <div style={{ fontWeight: 600, color: "var(--accent)", marginBottom: 8, fontSize: 12 }}>
                    Domain Intelligence ({domainLabel})
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 16px", color: "var(--text-secondary)" }}>
                    <span style={{ fontWeight: 500 }}>Verdict</span>
                    <span style={{ color: verdictColor, fontWeight: 600 }}>{diVerdict}</span>
                    {di?.threat_score != null && <>
                      <span style={{ fontWeight: 500 }}>Threat Score</span>
                      <span>{di.threat_score}</span>
                    </>}
                    {diSummary?.lastSeen && <>
                      <span style={{ fontWeight: 500 }}>Last Seen</span>
                      <span>{diSummary.lastSeen}</span>
                    </>}
                    {diLink && <>
                      <span style={{ fontWeight: 500 }}>Task URL</span>
                      <a href={diLink} target="_blank" rel="noopener noreferrer"
                        style={{ color: "var(--accent)", wordBreak: "break-all" }}>{diLink}</a>
                    </>}
                  </div>
                  {di?.threat_names?.length > 0 && (
                    <div style={{ marginTop: 6, color: "var(--text-secondary)" }}>
                      <span style={{ fontWeight: 500 }}>Threat Names: </span>
                      {normalizedAnyrunLabels(di.threat_names).join(", ")}
                    </div>
                  )}
                  <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)", fontStyle: "italic" }}>
                    This domain-level intelligence was retrieved separately from the URL analysis above.
                  </div>
                </div>
              );
            })()}

            {showSandboxSections && (
              <div
                style={{
                  marginBottom: 12,
                  padding: "10px 12px",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  background: "var(--bg-elevated)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 10,
                }}
              >
                <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  Process Graph is available in a dedicated windowed tab for large visibility.
                </div>
                <button
                  type="button"
                  onClick={() => {
                    if (typeof window === "undefined") return;
                    const u = new URL(window.location.href);
                    u.pathname = `${u.pathname.replace(/\/$/, "")}/process-graph`;
                    u.search = "";
                    u.searchParams.set("graph_index", String(idx));
                    window.open(u.toString(), "_blank", "noopener,noreferrer");
                  }}
                  style={{
                    padding: "7px 12px",
                    border: "1px solid rgba(96,165,250,0.35)",
                    borderRadius: 6,
                    background: "rgba(96,165,250,0.12)",
                    color: "var(--accent)",
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  Open Process Graph
                </button>
              </div>
            )}

            {anyrunIocs.length > 0 && (
              <details style={{ marginBottom: 10 }}>
                <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                  IOCs ({anyrunIocs.length})
                </summary>
                <DataGrid
                  title="IOC Details"
                  rows={anyrunIocs.map((ioc: any) => ({
                    category: ioc?.category || "-",
                    type: ioc?.type || "-",
                    ioc: ioc?.ioc || ioc?.value || "-",
                    reputation: ioc?.reputation || "-",
                    source_event: ioc?.discoveringEntryId || "-",
                  }))}
                  columns={[
                    { key: "category", label: "Category", minWidth: 120 },
                    { key: "type", label: "Type", minWidth: 120 },
                    { key: "ioc", label: "IOC", minWidth: 240, maxWidth: 620 },
                    { key: "reputation", label: "Reputation", minWidth: 100 },
                    { key: "source_event", label: "Source Event", minWidth: 140, maxWidth: 260 },
                  ]}
                />
              </details>
            )}

            {showSandboxSections && (
              <>
                <details style={{ marginBottom: 10 }}>
                  <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                    DNS Request Details ({dnsRows.length})
                  </summary>
                  <DataGrid
                    title="DNS Requests"
                    rows={dnsRows}
                    columns={[
                      { key: "timeshift", label: "Timeshift", minWidth: 260 },
                      { key: "rep", label: "Rep", minWidth: 130 },
                      { key: "domain", label: "Domain", minWidth: 320, maxWidth: 560 },
                      { key: "ips", label: "IPs", minWidth: 320, maxWidth: 560 },
                      { key: "threat", label: "Threat", minWidth: 130 },
                    ]}
                  />
                </details>

                <details style={{ marginBottom: 10 }}>
                  <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                    Connection Details ({connRows.length})
                  </summary>
                  <DataGrid
                    title="Connections"
                    rows={connRows}
                    columns={[
                      { key: "timeshift", label: "Timeshift", minWidth: 260 },
                      { key: "protocol", label: "Protocol", minWidth: 130 },
                      { key: "rep", label: "Rep", minWidth: 130 },
                      { key: "pid", label: "PID", minWidth: 110 },
                      { key: "process_name", label: "Process Name", minWidth: 320, maxWidth: 520 },
                      { key: "cn", label: "CN", minWidth: 110 },
                      { key: "ip", label: "IP", minWidth: 240 },
                      { key: "port", label: "Port", minWidth: 110 },
                      { key: "domain", label: "Domain", minWidth: 260, maxWidth: 420 },
                      { key: "asn", label: "ASN", minWidth: 280, maxWidth: 420 },
                      { key: "traffic", label: "Traffic", minWidth: 180 },
                    ]}
                  />
                </details>

                <details style={{ marginBottom: 10 }}>
                  <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                    HTTP Request Details ({httpRows.length})
                  </summary>
                  <DataGrid
                    title="HTTP Requests"
                    rows={httpRows}
                    columns={[
                      { key: "timeshift", label: "Timeshift", minWidth: 260 },
                      { key: "headers", label: "Headers", minWidth: 180, maxWidth: 260 },
                      { key: "rep", label: "Rep", minWidth: 130 },
                      { key: "pid", label: "PID", minWidth: 110 },
                      { key: "process_name", label: "Process Name", minWidth: 280, maxWidth: 420 },
                      { key: "cn", label: "CN", minWidth: 110 },
                      { key: "url", label: "URL", minWidth: 520, maxWidth: 900 },
                      { key: "content", label: "Content", minWidth: 260, maxWidth: 420 },
                    ]}
                  />
                </details>

                {threatRows.length > 0 && (
                  <details style={{ marginBottom: 10 }}>
                    <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                      Network Threat Details ({threatRows.length})
                    </summary>
                    <DataGrid
                      title="Network Threats"
                      rows={threatRows}
                      columns={[
                        { key: "type", label: "Type", minWidth: 170 },
                        { key: "indicator", label: "Indicator", minWidth: 320, maxWidth: 560 },
                        { key: "threat_level", label: "Threat Level", minWidth: 170 },
                        { key: "threat_name", label: "Threat Name", minWidth: 280, maxWidth: 480 },
                        { key: "description", label: "Description", minWidth: 360, maxWidth: 700 },
                      ]}
                    />
                  </details>
                )}
              </>
            )}

            {showSandboxSections && (details.length > 0 || domains.length > 0 || hosts.length > 0) && (
              <EvidenceTable
                title="Any.Run Highlights"
                data={[
                  { field: "Flagged Summary Signals", value: details.length },
                  { field: "Flagged Domains", value: domains.length },
                  { field: "Flagged Hosts/IPs", value: hosts.length },
                ]}
                columns={[{ key: "field" }, { key: "value" }]}
              />
            )}

            {showSandboxSections && (
              <div style={{
                marginTop: 10,
                padding: "8px 10px",
                borderRadius: 6,
                border: "1px solid rgba(245,158,11,0.22)",
                background: "rgba(245,158,11,0.05)",
                color: "rgba(245,158,11,0.80)",
                fontSize: 11,
                display: "flex",
                alignItems: "flex-start",
                gap: 6,
              }}>
                <span style={{ fontWeight: 700, flexShrink: 0 }}>⚠ Analyst note:</span>
                <span>
                  Phishing pages requiring active user interaction (form fill, credential submission) may not trigger
                  malicious behaviour during automated sandbox detonation. A CLEAN or UNKNOWN sandbox verdict does{" "}
                  <strong>not</strong> rule out phishing — cross-reference threat intelligence tags, domain age, TLS
                  certificate, and visual page inspection before clearing.
                </span>
              </div>
            )}
          </div>
        );
      })}
    </ReactFlowProvider>
  );
}

function AnalystCard({
  title,
  children,
  bodyStyle,
}: {
  title: string;
  children: React.ReactNode;
  bodyStyle?: React.CSSProperties;
}) {
  return (
    <div
      style={{
        border: "1px solid rgba(27,77,107,0.95)",
        borderRadius: 8,
        overflow: "hidden",
        background: "linear-gradient(180deg, rgba(7,47,70,0.96), rgba(6,37,56,0.98))",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          padding: "10px 12px",
          borderBottom: "1px solid rgba(59,130,246,0.18)",
          color: "#c7f0ff",
          fontWeight: 700,
          fontSize: 14,
        }}
      >
        {title}
      </div>
      <div style={{ padding: 12, ...bodyStyle }}>{children}</div>
    </div>
  );
}

function AnalystPair({
  label,
  value,
  long = false,
}: {
  label: string;
  value: React.ReactNode;
  long?: boolean;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "96px 1fr",
        gap: 10,
        marginBottom: 8,
        alignItems: "start",
      }}
    >
      <div style={{ color: "#67e8f9", fontWeight: 700, fontSize: 12 }}>{label}:</div>
      <div
        style={{
          color: "var(--text-secondary)",
          fontSize: 12,
          lineHeight: 1.45,
          overflowWrap: "anywhere",
          wordBreak: long ? "break-all" : "break-word",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function AnalystStatChip({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div
      style={{
        border: "1px solid rgba(96,165,250,0.24)",
        background: "rgba(15,23,42,0.22)",
        borderRadius: 999,
        padding: "4px 10px",
        color: "var(--text-secondary)",
        fontSize: 12,
      }}
    >
      <span style={{ color: "#67e8f9", fontWeight: 700 }}>{label}:</span> {value}
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        padding: "12px 16px",
        fontSize: 12,
        color: "var(--text-dim)",
        background: "var(--bg-input)",
        borderRadius: "var(--radius-sm)",
        borderLeft: "3px solid var(--text-muted)",
        marginBottom: 8,
      }}
    >
      {children}
    </div>
  );
}
