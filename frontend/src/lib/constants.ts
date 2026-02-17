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
  benign:       { color: "#34d399", bg: "rgba(52,211,153,0.10)",  label: "BENIGN" },
  suspicious:   { color: "#fbbf24", bg: "rgba(251,191,36,0.10)", label: "SUSPICIOUS" },
  malicious:    { color: "#f87171", bg: "rgba(248,113,113,0.10)",  label: "MALICIOUS" },
  inconclusive: { color: "#94a3b8", bg: "rgba(148,163,184,0.10)", label: "INCONCLUSIVE" },
};

// ─── SOC Action display ───

export const ACTION_CONFIG: Record<SOCAction, {
  color: string;
  icon: string;
}> = {
  monitor:     { color: "#34d399", icon: "◉" },
  investigate: { color: "#fbbf24", icon: "⬡" },
  block:       { color: "#f87171", icon: "⊘" },
  hunt:        { color: "#fb923c", icon: "◎" },
};

// ─── Severity display ───

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f87171",
  high:     "#f87171",
  medium:   "#fbbf24",
  low:      "#60a5fa",
  info:     "#94a3b8",
};

// ─── Collector status display ───

export const COLLECTOR_STATUS_CONFIG: Record<CollectorStatus, {
  symbol: string;
  color: string;
}> = {
  completed: { symbol: "✓", color: "#34d399" },
  running:   { symbol: "◌", color: "#60a5fa" },
  failed:    { symbol: "✗", color: "#f87171" },
  pending:   { symbol: "○", color: "#64748b" },
  skipped:   { symbol: "–", color: "#64748b" },
};

// ─── IOC type display ───

export const IOC_TYPE_COLORS: Record<string, string> = {
  ip:     "#60a5fa",
  domain: "#a78bfa",
  url:    "#fbbf24",
  hash:   "#94a3b8",
  email:  "#34d399",
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
  { id: "summary",    label: "Executive Summary" },
  { id: "evidence",   label: "Technical Evidence" },
  { id: "findings",   label: "Findings" },
  { id: "indicators", label: "Indicators & Pivots" },
  { id: "signals",    label: "Signals & Gaps" },
] as const;

export type TabId = typeof REPORT_TABS[number]["id"];
