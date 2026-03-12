"use client";

import React from "react";
import EvidenceTable from "@/components/evidence/EvidenceTable";
import ReactFlow, {
  Controls,
  MarkerType,
  Node,
  Edge,
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

function _num(v: any): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function _uniq<T>(vals: T[]): T[] {
  return Array.from(new Set(vals));
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
  const fileCount = _num(p?.file_activity_count);
  const mitreCount = _num(p?.mitre_count);
  const suspicious = Boolean(p?.suspicious_flag) || threatLevel >= 1 || threatScore >= 35;

  let score = 0;
  if (threatLevel >= 2 || threatScore >= 70) score += 10;
  else if (suspicious) score += 6;
  if (networkCount > 0) score += 2;
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

function buildProcessTreeGraph(raw: any): { nodes: any[]; edges: any[]; details: Record<string, any> } {
  let processes = arr(raw?.behavior_details?.processes);
  if (!processes.length) {
    processes = arr(raw?.behavior_details?.process_details);
  }
  if (!processes.length) return { nodes: [], edges: [], details: {} };
  const processDetails = arr(raw?.behavior_details?.process_details);
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
    const connCount = _num(eventCounts.connections) + _num(eventCounts.http_requests) + _num(eventCounts.dns_requests);
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
        file_activity_count: fileCount,
        suspicious_flag: threatLevel >= 1 || threatScore >= 35,
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
  const subtreeSize = (root: string): number => {
    let total = 0;
    const stack = [root];
    const seen = new Set<string>();
    while (stack.length) {
      const cur = stack.pop()!;
      if (seen.has(cur)) continue;
      seen.add(cur);
      total += 1;
      for (const c of children.get(cur) || []) stack.push(c);
    }
    return total;
  };
  // Focus on the primary execution tree (closest to AnyRun visual graph).
  if (roots.length > 1) {
    roots = roots
      .map((r) => ({ r, size: subtreeSize(r) }))
      .sort((a, b) => b.size - a.size)
      .slice(0, 1)
      .map((x) => x.r);
  }
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

  // Relevance pruning (AnyRun-like): keep suspicious/high-signal processes and their ancestry.
  const MAX_RENDER_NODES = 70;
  const kept = new Set<string>();
  for (const r of roots) kept.add(r);
  const candidates: Array<{ id: string; score: number }> = [];
  nodesById.forEach((n, id) => {
    if (removed.has(id)) return;
    const score = _processRelevanceScore(n.process || {});
    candidates.push({ id, score });
    if (score >= 6) kept.add(id);
  });
  const addAncestors = (id: string) => {
    let cur = nodesById.get(id)?.parentId || null;
    let guard = 0;
    while (cur && guard < 200) {
      kept.add(cur);
      cur = nodesById.get(cur)?.parentId || null;
      guard += 1;
    }
  };
  Array.from(kept).forEach(addAncestors);
  if (kept.size < MAX_RENDER_NODES) {
    const ranked = candidates
      .filter((c) => !kept.has(c.id))
      .sort((a, b) => b.score - a.score);
    for (const c of ranked) {
      kept.add(c.id);
      addAncestors(c.id);
      if (kept.size >= MAX_RENDER_NODES) break;
    }
  }

  const levels = new Map<number, string[]>();
  depth.forEach((d, id) => {
    if (removed.has(id)) return;
    if (!kept.has(id)) return;
    if (!levels.has(d)) levels.set(d, []);
    levels.get(d)!.push(id);
  });

  const rfNodes: any[] = [];
  const spacingX = 280;
  const spacingY = 110;
  Array.from(levels.entries())
    .sort((a, b) => a[0] - b[0])
    .forEach(([d, ids]) => {
      const sorted = [...ids].sort((a, b) => {
        const al = String(nodesById.get(a)?.label || "").toLowerCase();
        const bl = String(nodesById.get(b)?.label || "").toLowerCase();
        return al.localeCompare(bl);
      });
      const offsetY = -((sorted.length - 1) * spacingY) / 2;
      sorted.forEach((id, idx) => {
        const n = nodesById.get(id)!;
        const dup = _num(n?.process?.duplicate_count);
        rfNodes.push({
          id,
          kind: "process",
          label: dup > 1 ? `${n.label} x${dup}` : n.label,
          process: n.process,
          position: { x: d * spacingX, y: offsetY + idx * spacingY },
        });
      });
    });

  const rfEdges: any[] = [];
  const renderedIds = new Set(rfNodes.map((n: any) => String(n.id)));
  nodesById.forEach((n, id) => {
    if (!n.parentId || !nodesById.has(n.parentId)) return;
    const sid = alias.get(id) || id;
    const tid = alias.get(n.parentId) || n.parentId;
    if (!renderedIds.has(sid) || !renderedIds.has(tid) || sid === tid) return;
    rfEdges.push({
      id: `${tid}->${sid}`,
      source: tid,
      target: sid,
      label: "",
    });
  });
  const details: Record<string, any> = {};
  rfNodes.forEach((n) => {
    details[String(n.id)] = n.process || {};
  });
  return { nodes: rfNodes, edges: rfEdges, details };
}

export function AnyRunGraph({ raw, height = 520 }: { raw?: any; height?: number }) {
  const processTree = React.useMemo(() => buildProcessTreeGraph(raw || {}), [raw]);
  const rawNodes = arr(processTree?.nodes);
  const rawEdges = arr(processTree?.edges);
  const detailByNode = processTree?.details || {};
  const [selectedNode, setSelectedNode] = React.useState<string | null>(null);
  const [selectedProcessManual, setSelectedProcessManual] = React.useState<any | null>(null);
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [processViewMode, setProcessViewMode] = React.useState<"view" | "group" | "deep">("group");
  const threatRows = arr(raw?.behavior_details?.network_threats);
  const processDetails = arr(raw?.behavior_details?.process_details);
  const processIndexByRef = React.useMemo(() => {
    const m: Record<string, any> = {};
    for (const p of processDetails) {
      // Use stable identifiers only; name-based keys cause collisions (e.g., many svchost.exe).
      const refs = [p?.uuid, p?.guid, p?.pid].filter(Boolean).map((x: any) => String(x));
      for (const r of refs) m[r] = p;
    }
    return m;
  }, [processDetails]);
  const processListItems = React.useMemo(() => {
    const src = processDetails.length ? processDetails : rawNodes.map((n: any) => n?.process || {});
    const byKey = new Map<string, any>();
    for (const p of src) {
      const pid = String(p?.pid ?? "").trim();
      const uuid = String(p?.uuid ?? p?.guid ?? "").trim();
      const name = String(p?.name || p?.fileName || p?.image || p?.processName || "process").trim();
      const cmd = String(p?.command_line || p?.commandLine || p?.cmd || "").trim();
      // Collapse exact duplicates (same identity + same command line).
      const key = [uuid || "-", pid || "-", name.toLowerCase(), cmd.toLowerCase()].join("|");
      if (!byKey.has(key)) {
        byKey.set(key, { ...p, __dup_count: 1, __key: key });
      } else {
        const prev = byKey.get(key);
        byKey.set(key, { ...prev, __dup_count: Number(prev?.__dup_count || 1) + 1 });
      }
    }
    return Array.from(byKey.values());
  }, [processDetails, rawNodes]);
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
        const suspicious = Boolean(p?.suspicious_flag) || threatLevel >= 1 || threatScore >= 35;
        const malicious = threatLevel >= 2 || threatScore >= 70;
        const borderColor =
          malicious ? "#ef4444" : suspicious || threatCount > 0 ? "#f59e0b" : "rgba(125,211,252,0.7)";
        const leftBar =
          malicious ? "3px solid #ef4444" : suspicious || threatCount > 0 ? "3px solid #f59e0b" : "3px solid #60a5fa";
        return {
          id: String(n?.id || `n-${idx}`),
          position: n?.position || { x: ((idx % 8) * 280), y: Math.floor(idx / 8) * 110 },
          data: { label, process: p },
          style: {
            border: `1px solid ${borderColor}`,
            borderLeft: leftBar,
            background: "#0b3550",
            color: "var(--text-primary)",
            fontSize: 12,
            borderRadius: 8,
            padding: "8px 10px",
            width: 260,
          },
        };
      }),
    [rawNodes, threatByProcess]
  );

  const nodes = React.useMemo(
    () =>
      nodesBase.map((n) => ({
        ...n,
        style: {
          ...(n.style || {}),
          border: selectedNode === n.id ? "2px solid #22d3ee" : (n.style as any)?.border,
          boxShadow: selectedNode === n.id ? "0 0 0 2px rgba(34,211,238,0.18)" : "none",
        },
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
          style: { stroke: "rgba(56,189,248,0.6)", strokeWidth: 1.4 },
          labelStyle: { fill: "#94a3b8", fontSize: 10 },
          type: "smoothstep",
          markerEnd: { type: MarkerType.ArrowClosed, color: "rgba(56,189,248,0.9)" },
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
  const selectedEvents = React.useMemo(() => flattenProcessEvents(selectedProcessDetail || {}), [selectedProcessDetail]);
  const groupedBySeverityAndTechnique = React.useMemo(() => {
    const map: Record<string, Record<string, ProcessEventRow[]>> = { danger: {}, warning: {}, other: {} };
    for (const e of selectedEvents) {
      if (!map[e.severity][e.technique_id]) map[e.severity][e.technique_id] = [];
      map[e.severity][e.technique_id].push(e);
    }
    return map;
  }, [selectedEvents]);

  return (
    <div style={{ marginBottom: 10, position: "relative" }}>
      <div style={{ height, border: "1px solid #1b4d6b", borderRadius: 6, overflow: "hidden", background: "#07324a" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodeClick={(_, n) => {
            setSelectedNode(String(n.id));
            setSelectedProcessManual((n as any)?.data?.process || null);
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
                  <span style={{ color: selectedThreatLevel >= 2 ? "var(--red)" : "var(--yellow)", marginLeft: 8 }}>
                    {selectedThreatLevel >= 2 ? "Malicious" : "Suspicious"}
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
              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", marginBottom: 6 }}>
                {selected?.fileName || selected?.image || selected?.processName || selected?.name || "-"}
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
                <strong>Threat score:</strong> {String(selected?.threat_score ?? selectedProcessDetail?.threat_score ?? "-")}
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
      {showAdvanced && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(2,6,23,0.82)",
            zIndex: 110,
            display: "flex",
            justifyContent: "center",
            alignItems: "stretch",
            padding: "2vh 2vw",
          }}
        >
          <div
            style={{
              width: "96vw",
              height: "96vh",
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
                Processes ({processListItems.length})
              </div>
              <div style={{ overflowY: "auto", padding: 8 }}>
                {processListItems.map((p: any, idx: number) => {
                  const key = String(p?.uuid || p?.guid || p?.pid || p?.name || idx);
                  const title = String(p?.name || p?.fileName || p?.image || p?.processName || p?.label || "process");
                  const pid = p?.pid != null ? String(p.pid) : "-";
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
                      <div style={{ fontWeight: 700 }}>{title}</div>
                      <div style={{ color: "var(--text-muted)", marginTop: 2 }}>
                        PID: {pid}{Number(p?.__dup_count || 1) > 1 ? `  |  x${p.__dup_count}` : ""}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
            <div style={{ minHeight: 0, overflow: "auto" }}>
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
                      { field: "Threat Verdict", value: selectedThreatLevel >= 2 ? "MALICIOUS" : selectedThreatLevel >= 1 ? "SUSPICIOUS" : "NO VERDICT" },
                      { field: "Threat Score", value: selectedProcessDetail?.threat_score ?? "-" },
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
                                  <div key={`deep-row-${i}-${rowIdx}`} style={{ marginBottom: rowIdx === rows.length - 1 ? 0 : 4, color: "var(--text-secondary)" }}>
                                    <strong>{row.key}:</strong> {row.value}
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
            </div>
          </div>
        </div>
      )}
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

export default function AnyRunInteractiveEvidence({ hybridAnalysis }: Props) {
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

      {items.map((item: any, idx: number) => {
        const raw = item?.raw_summary || {};
        const sourceLower = String(raw?.source || "").toLowerCase();
        const summary = raw?.summary || {};
        const details = arr(summary?.details);
        const io = item?.dynamic_io_summary || {};
        const domains = arr(io?.domains).filter(isFlagged);
        const hosts = arr(io?.hosts).filter(isFlagged);
        const anyrunIocs = arr(raw?.iocs);
        const anyrunAiSummary = String(raw?.anyrun_ai_summary || "").trim();
        const behaviorCounts = raw?.behavior_counts || {};
        const behaviorDetails = raw?.behavior_details || {};
        const anyrunLink = sourceLower === "anyrun"
          ? (
            (typeof item?.analysis_link === "string" && item.analysis_link.startsWith("http"))
              ? item.analysis_link
              : (item?.analysis_id ? `https://app.any.run/tasks/${item.analysis_id}` : null)
          )
          : null;
        const anyrunFallbackError = String(raw?.anyrun_error || "").trim();

        const dnsRows = arr(behaviorDetails?.dns_requests).slice(0, 200).map((d: any) => ({
          timeshift: d?.time || d?.timestamp || "-",
          rep: d?.reputation || d?.reputationNumber || "-",
          domain: d?.domainName || d?.domain || d?.hostname || "-",
          ips: arr(d?.ips).join(", ") || arr(d?.answers).join(", ") || d?.resolvedTo || "-",
          threat: d?.threatLevel ?? "-",
        }));
        const connRows = arr(behaviorDetails?.connections).slice(0, 200).map((c: any) => ({
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
        const httpRows = arr(behaviorDetails?.http_requests).slice(0, 200).map((h: any) => ({
          timeshift: h?.time || h?.timestamp || "-",
          headers: `${h?.method || "-"}${h?.httpCode ? ` - ${h.httpCode}` : ""}`,
          rep: h?.reputation || "-",
          pid: h?.pid ?? "-",
          process_name: h?.processName ?? h?.process ?? "-",
          cn: h?.country || "-",
          url: h?.url || h?.requestUrl || "-",
          content: h?.content || h?.body?.response?.size || h?.mimeType || h?.contentType || "-",
        }));
        const threatRows = arr(behaviorDetails?.network_threats).slice(0, 200).map((t: any) => ({
          type: t?.class || t?.category || t?.type || "-",
          indicator: t?.indicator || t?.domain || t?.destinationIP || t?.url || "-",
          threat_level: t?.threatLevel ?? t?.priority ?? t?.severity ?? "-",
          threat_name: arr(t?.threatName).join(", ") || t?.name || "-",
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
            <EvidenceTable
              title={`Any.Run Evidence #${idx + 1}`}
              data={[
                { field: "Detected Type", value: summary?.detectedType || item?.indicator_type || "-" },
                { field: "Threat Level", value: summary?.threatLevel ?? "-" },
                { field: "Last Seen", value: summary?.lastSeen || "-" },
                { field: "HTTP Requests", value: behaviorCounts?.http_requests ?? dnsRows.length ?? "—" },
                { field: "Connections", value: behaviorCounts?.connections ?? connRows.length ?? "—" },
                { field: "DNS Requests", value: behaviorCounts?.dns_requests ?? dnsRows.length ?? "—" },
                { field: "Network Threats", value: behaviorCounts?.network_threats ?? threatRows.length ?? "—" },
                { field: "Task URL", value: anyrunLink || "-" },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />

            {anyrunAiSummary && (
              <EvidenceTable
                title="Any.Run AI Summary"
                data={[{ summary: anyrunAiSummary }]}
                columns={[{ key: "summary", wrap: true }]}
              />
            )}

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

            {anyrunIocs.length > 0 && (
              <details style={{ marginBottom: 10 }}>
                <summary style={{ cursor: "pointer", color: "var(--accent)", fontSize: 12 }}>
                  IOCs ({anyrunIocs.length})
                </summary>
                <DataGrid
                  title="IOC Details"
                  rows={anyrunIocs.slice(0, 500).map((ioc: any) => ({
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

            {(details.length > 0 || domains.length > 0 || hosts.length > 0) && (
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
          </div>
        );
      })}
    </ReactFlowProvider>
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
