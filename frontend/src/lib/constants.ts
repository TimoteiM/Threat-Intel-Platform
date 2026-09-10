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
  /** Visual grouping only — clusters related nav items with a hairline
   *  divider between groups, instead of one flat row of thirteen links. */
  group?: "work" | "monitor" | "intake" | "reach" | "system";
};

export type AppFooterLink = AppNavLink & {
  external?: boolean;
};

export type AppFooterLinkGroup = {
  title: string;
  links: readonly AppFooterLink[];
};

export const APP_NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard", group: "work" },
  { href: "/investigations", label: "All Cases", group: "work" },
  { href: "/batches", label: "Bulk Analysis", group: "work" },
  { href: "/watchlist", label: "Watchlist", group: "monitor" },
  { href: "/exclusions", label: "Exclusion", group: "monitor" },
  { href: "/detections", label: "Detections", group: "monitor" },
  { href: "/alerts", label: "Alerts", group: "monitor" },
  { href: "/email-investigations", label: "Email", group: "intake" },
  { href: "/alert-investigations", label: "Alert Body", group: "intake" },
  { href: "/assistant", label: "AI Assistant", group: "reach" },
  { href: "/clients", label: "Clients", group: "reach" },
  { href: "/ip-lookup", label: "IP Lookup", group: "reach" },
  { href: "/settings", label: "Settings", group: "system" },
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
      { href: "/exclusions", label: "Exclusion List" },
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

// These mirror the palette defined in globals.css (--shell-success,
// --shell-warning, --shell-danger, --shell-accent, --shell-info). They stay
// as literal hex — not var() strings — because call sites across the app
// build translucent fills by appending a two-digit alpha suffix directly to
// this string (`${config.color}33`), which only produces valid CSS when the
// value is a bare hex colour.
export const CLASSIFICATION_CONFIG: Record<Classification, {
  color: string;
  bg: string;
  label: string;
}> = {
  benign: { color: "#2bd4a0", bg: "rgba(43,212,160,0.12)", label: "BENIGN" },
  suspicious: { color: "#f2a93c", bg: "rgba(242,169,60,0.12)", label: "SUSPICIOUS" },
  malicious: { color: "#fb7185", bg: "rgba(251,113,133,0.12)", label: "MALICIOUS" },
  inconclusive: { color: "#948fb0", bg: "rgba(148,143,176,0.12)", label: "INCONCLUSIVE" },
};

// SOC Action display

export const ACTION_CONFIG: Record<SOCAction, {
  color: string;
  icon: string;
}> = {
  monitor: { color: "#2bd4a0", icon: "◉" },
  investigate: { color: "#f2a93c", icon: "⬡" },
  block: { color: "#fb7185", icon: "⊘" },
  hunt: { color: "#fb923c", icon: "◎" },
};

// Severity display

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#fb7185",
  high: "#fb7185",
  medium: "#f2a93c",
  low: "#5b9dff",
  info: "#948fb0",
};

// Collector status display

export const COLLECTOR_STATUS_CONFIG: Record<CollectorStatus, {
  symbol: string;
  color: string;
}> = {
  completed: { symbol: "✓", color: "#2bd4a0" },
  // "Running" gets the brand accent rather than the info blue — the one
  // state where something is actively happening reads as *the* signature
  // colour, not one status among many.
  running: { symbol: "◌", color: "#8b7bff" },
  failed: { symbol: "✕", color: "#fb7185" },
  pending: { symbol: "○", color: "#6e6b82" },
  skipped: { symbol: "–", color: "#6e6b82" },
};

// IOC type display

export const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#5b9dff",
  domain: "#8b7bff",
  url: "#f2a93c",
  hash: "#948fb0",
  email: "#2bd4a0",
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
