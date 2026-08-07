/**
 * Design tokens and display configuration.
 */

import { Classification, SOCAction, CollectorStatus } from "./types";

export const APP_BRAND = "Threat Analyzer";
export const APP_SUBTITLE = "Threat Intelligence and Investigation Platform";
export const APP_SHELL_MAX_WIDTH = 1680;
export const APP_VERSION = "v2.0";

export type AppNavLink = {
  href: string;
  label: string;
};

export type AppFooterLink = AppNavLink & {
  external?: boolean;
};

export type AppFooterLinkGroup = {
  title: string;
  links: readonly AppFooterLink[];
};

export const APP_NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/investigations", label: "All Cases" },
  { href: "/batches", label: "Bulk Analysis" },
  { href: "/watchlist", label: "Watchlist" },
  { href: "/email-investigations", label: "Email" },
  { href: "/alert-investigations", label: "Alert Body" },
  { href: "/assistant", label: "AI Assistant" },
  { href: "/soc-indicators", label: "SOC Graph" },
  { href: "/clients", label: "Clients" },
  { href: "/alerts", label: "Alerts" },
  { href: "/ip-lookup", label: "IP Lookup" },
  { href: "/settings", label: "Settings" },
] as const;

export const APP_FOOTER_LINK_GROUPS = [
  {
    title: "Platform",
    links: [
      { href: "/", label: "New Investigation" },
      { href: "/investigations", label: "All Cases" },
      { href: "/batches", label: "Bulk Analysis" },
      { href: "/dashboard", label: "Dashboard" },
    ],
  },
  {
    title: "Tools",
    links: [
      { href: "/ip-lookup", label: "IP Lookup" },
      { href: "/watchlist", label: "Domain Watchlist" },
      { href: "/alerts", label: "Alerts" },
      { href: "/clients", label: "Client Management" },
    ],
  },
  {
    title: "Technology",
    links: [
      { href: "https://www.virustotal.com", label: "VirusTotal", external: true },
      { href: "https://www.abuseipdb.com", label: "AbuseIPDB", external: true },
      { href: "https://urlscan.io", label: "URLScan.io", external: true },
      { href: "https://attack.mitre.org", label: "MITRE ATT&CK", external: true },
    ],
  },
] satisfies readonly AppFooterLinkGroup[];

// Classification display

export const CLASSIFICATION_CONFIG: Record<Classification, {
  color: string;
  bg: string;
  label: string;
}> = {
  benign: { color: "#38d9a9", bg: "rgba(56,217,169,0.12)", label: "BENIGN" },
  suspicious: { color: "#fbbf24", bg: "rgba(251,191,36,0.12)", label: "SUSPICIOUS" },
  malicious: { color: "#fb7185", bg: "rgba(251,113,133,0.12)", label: "MALICIOUS" },
  inconclusive: { color: "#94a3b8", bg: "rgba(148,163,184,0.12)", label: "INCONCLUSIVE" },
};

// SOC Action display

export const ACTION_CONFIG: Record<SOCAction, {
  color: string;
  icon: string;
}> = {
  monitor: { color: "#38d9a9", icon: "◉" },
  investigate: { color: "#fbbf24", icon: "⬡" },
  block: { color: "#fb7185", icon: "⊘" },
  hunt: { color: "#fb923c", icon: "◎" },
};

// Severity display

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#fb7185",
  high: "#fb7185",
  medium: "#fbbf24",
  low: "#66a8ff",
  info: "#94a3b8",
};

// Collector status display

export const COLLECTOR_STATUS_CONFIG: Record<CollectorStatus, {
  symbol: string;
  color: string;
}> = {
  completed: { symbol: "✓", color: "#38d9a9" },
  running: { symbol: "◌", color: "#66a8ff" },
  failed: { symbol: "✕", color: "#fb7185" },
  pending: { symbol: "○", color: "#64748b" },
  skipped: { symbol: "–", color: "#64748b" },
};

// IOC type display

export const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#66a8ff",
  domain: "#a78bfa",
  url: "#fbbf24",
  hash: "#94a3b8",
  email: "#38d9a9",
};

// Collector display names

export const COLLECTOR_NAMES: Record<string, string> = {
  dns: "DNS",
  http: "HTTP",
  tls: "TLS",
  whois: "WHOIS",
  asn: "ASN",
  intel: "INTEL",
  vt: "VT",
  threat_feeds: "THREAT FEEDS",
  brave_osint: "BRAVE OSINT",
  hybrid_analysis: "ANYRUN ANALYSIS",
  urlscan: "URLSCAN",
  screenshot: "SCREENSHOT",
  js_analysis: "JS ANALYSIS",
  opencti: "OPENCTI",
};

// Tabs

export const REPORT_TABS = [
  { id: "summary", label: "Executive Summary" },
  { id: "evidence", label: "Technical Evidence" },
  { id: "findings", label: "Findings" },
  { id: "indicators", label: "Indicators & Pivots" },
  { id: "signals", label: "Signals & Gaps" },
] as const;

export type TabId = typeof REPORT_TABS[number]["id"];
