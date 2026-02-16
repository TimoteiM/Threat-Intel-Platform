/**
 * Design tokens and display configuration.
 */

import { Classification, Confidence, SOCAction, CollectorStatus } from "./types";

// ─── Classification display ───

export const CLASSIFICATION_CONFIG: Record<Classification, {
  color: string;
  bg: string;
  label: string;
}> = {
  benign:       { color: "#10b981", bg: "rgba(16,185,129,0.08)",  label: "BENIGN" },
  suspicious:   { color: "#f59e0b", bg: "rgba(245,158,11,0.08)", label: "SUSPICIOUS" },
  malicious:    { color: "#ef4444", bg: "rgba(239,68,68,0.08)",  label: "MALICIOUS" },
  inconclusive: { color: "#64748b", bg: "rgba(100,116,139,0.08)", label: "INCONCLUSIVE" },
};

// ─── SOC Action display ───

export const ACTION_CONFIG: Record<SOCAction, {
  color: string;
  icon: string;
}> = {
  monitor:     { color: "#10b981", icon: "◉" },
  investigate: { color: "#f59e0b", icon: "⬡" },
  block:       { color: "#ef4444", icon: "⊘" },
  hunt:        { color: "#f97316", icon: "◎" },
};

// ─── Severity display ───

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#ef4444",
  medium:   "#f59e0b",
  low:      "#3b82f6",
  info:     "#64748b",
};

// ─── Collector status display ───

export const COLLECTOR_STATUS_CONFIG: Record<CollectorStatus, {
  symbol: string;
  color: string;
}> = {
  completed: { symbol: "✓", color: "#10b981" },
  running:   { symbol: "◌", color: "#3b82f6" },
  failed:    { symbol: "✗", color: "#ef4444" },
  pending:   { symbol: "○", color: "#475569" },
  skipped:   { symbol: "–", color: "#475569" },
};

// ─── IOC type display ───

export const IOC_TYPE_COLORS: Record<string, string> = {
  ip:     "#3b82f6",
  domain: "#8b5cf6",
  url:    "#f59e0b",
  hash:   "#64748b",
  email:  "#10b981",
};

// ─── Collector display names ───

export const COLLECTOR_NAMES: Record<string, string> = {
  dns:   "DNS",
  http:  "HTTP",
  tls:   "TLS",
  whois: "WHOIS",
  asn:   "ASN",
  intel: "INTEL",
  vt:    "VT",
};

// ─── Tabs ───

export const REPORT_TABS = [
  { id: "summary",    label: "EXECUTIVE SUMMARY" },
  { id: "evidence",   label: "TECHNICAL EVIDENCE" },
  { id: "findings",   label: "FINDINGS" },
  { id: "indicators", label: "INDICATORS & PIVOTS" },
  { id: "signals",    label: "SIGNALS & GAPS" },
] as const;

export type TabId = typeof REPORT_TABS[number]["id"];
