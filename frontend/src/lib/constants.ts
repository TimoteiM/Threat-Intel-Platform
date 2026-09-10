/**
 * Design tokens and display configuration.
 */

import { Classification, SOCAction, CollectorStatus } from "./types";

export const APP_BRAND = "Threat Analyzer";
export const APP_SUBTITLE = "Threat Intelligence and Investigation Platform";
export const APP_SHELL_MAX_WIDTH = 1680;
export const APP_VERSION = "v2.0";

/** Icon keys, resolved to inline SVG in the sidebar. Kept as names rather
 *  than components so this file stays free of JSX and can be imported from
 *  anywhere, including the server. */
export type NavIcon =
  | "grid" | "cases" | "bulk" | "watch"
  | "detections" | "alerts" | "exclusions"
  | "email" | "alertBody" | "ip" | "assistant" | "clients" | "settings";

export type AppNavLink = {
  href: string;
  label: string;
  /** Sidebar section. An analyst's day splits three ways: the case work
   *  itself, what the estate is reporting, and the single-purpose lookups. */
  group?: "workspace" | "detection" | "tools";
  icon?: NavIcon;
};

export const APP_NAV_SECTIONS = [
  { id: "workspace", title: "Workspace" },
  { id: "detection", title: "Detection" },
  { id: "tools", title: "Tools" },
] as const;

export type AppFooterLink = AppNavLink & {
  external?: boolean;
};

export type AppFooterLinkGroup = {
  title: string;
  links: readonly AppFooterLink[];
};

export const APP_NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard", group: "workspace", icon: "grid" },
  { href: "/investigations", label: "All Cases", group: "workspace", icon: "cases" },
  { href: "/batches", label: "Bulk Analysis", group: "workspace", icon: "bulk" },
  { href: "/watchlist", label: "Watchlist", group: "workspace", icon: "watch" },
  { href: "/detections", label: "Detections", group: "detection", icon: "detections" },
  { href: "/alerts", label: "Alerts", group: "detection", icon: "alerts" },
  { href: "/exclusions", label: "Exclusions", group: "detection", icon: "exclusions" },
  { href: "/email-investigations", label: "Email Analysis", group: "tools", icon: "email" },
  // Alert Body is a first-class intake path, not a variant of Email Analysis:
  // it takes a pasted alert body and runs every indicator inside it.
  { href: "/alert-investigations", label: "Alert Body", group: "tools", icon: "alertBody" },
  { href: "/ip-lookup", label: "IP Lookup", group: "tools", icon: "ip" },
  { href: "/assistant", label: "AI Assistant", group: "tools", icon: "assistant" },
  { href: "/clients", label: "Clients", group: "tools", icon: "clients" },
  { href: "/settings", label: "Settings", group: "tools", icon: "settings" },
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
  benign: { color: "#2ecc71", bg: "rgba(46,204,113,0.12)", label: "BENIGN" },
  suspicious: { color: "#f0a050", bg: "rgba(240,160,80,0.12)", label: "SUSPICIOUS" },
  malicious: { color: "#f07050", bg: "rgba(240,112,80,0.12)", label: "MALICIOUS" },
  inconclusive: { color: "#8a90a6", bg: "rgba(138,144,166,0.12)", label: "INCONCLUSIVE" },
};

// SOC Action display

export const ACTION_CONFIG: Record<SOCAction, {
  color: string;
  icon: string;
}> = {
  monitor: { color: "#2ecc71", icon: "◉" },
  investigate: { color: "#f0a050", icon: "⬡" },
  block: { color: "#f07050", icon: "⊘" },
  hunt: { color: "#fb923c", icon: "◎" },
};

// Severity display

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f07050",
  high: "#f07050",
  medium: "#f0a050",
  low: "#5b9dff",
  info: "#8a90a6",
};

// Collector status display

export const COLLECTOR_STATUS_CONFIG: Record<CollectorStatus, {
  symbol: string;
  color: string;
}> = {
  completed: { symbol: "✓", color: "#2ecc71" },
  // "Running" gets the brand accent rather than the info blue — the one
  // state where something is actively happening reads as *the* signature
  // colour, not one status among many.
  running: { symbol: "◌", color: "#4f6ef7" },
  failed: { symbol: "✕", color: "#f07050" },
  pending: { symbol: "○", color: "#6a6f82" },
  skipped: { symbol: "–", color: "#6a6f82" },
};

// IOC type display

export const IOC_TYPE_COLORS: Record<string, string> = {
  ip: "#5b9dff",
  domain: "#4f6ef7",
  url: "#f0a050",
  hash: "#8a90a6",
  email: "#2ecc71",
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
