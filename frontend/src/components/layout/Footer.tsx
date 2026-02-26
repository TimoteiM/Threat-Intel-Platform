"use client";

import React from "react";

const YEAR = 2026;

export default function Footer() {
  return (
    <footer
      style={{
        borderTop: "1px solid var(--border)",
        background: "rgba(15, 23, 42, 0.6)",
        marginTop: 64,
      }}
    >
      <div
        style={{
          maxWidth: 1320,
          margin: "0 auto",
          padding: "32px 24px",
        }}
      >
        {/* Top row: brand + nav links */}
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 32,
            flexWrap: "wrap",
            marginBottom: 28,
          }}
        >
          {/* Brand */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: 7,
                  background: "linear-gradient(135deg, #60a5fa 0%, #818cf8 100%)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 13,
                  fontWeight: 700,
                  color: "#fff",
                  boxShadow: "0 2px 8px rgba(96, 165, 250, 0.25)",
                  flexShrink: 0,
                }}
              >
                ⬡
              </div>
              <span
                style={{
                  fontSize: 14,
                  fontWeight: 700,
                  color: "var(--text)",
                  fontFamily: "var(--font-sans)",
                  letterSpacing: "0.01em",
                }}
              >
                Threat Investigator
              </span>
            </div>
            <p
              style={{
                fontSize: 12,
                color: "var(--text-muted)",
                fontFamily: "var(--font-sans)",
                lineHeight: 1.6,
                maxWidth: 280,
                margin: 0,
              }}
            >
              AI-powered domain threat analysis platform.
              Evidence-based classification with MITRE ATT&CK mapping
              and full IOC extraction.
            </p>
          </div>

          {/* Nav columns */}
          <div
            style={{
              display: "flex",
              gap: 48,
              flexWrap: "wrap",
            }}
          >
            <FooterColumn title="Platform">
              <FooterLink href="/">New Investigation</FooterLink>
              <FooterLink href="/investigations">All Cases</FooterLink>
              <FooterLink href="/batches">Bulk Analysis</FooterLink>
              <FooterLink href="/dashboard">Dashboard</FooterLink>
            </FooterColumn>

            <FooterColumn title="Tools">
              <FooterLink href="/ip-lookup">IP Lookup</FooterLink>
              <FooterLink href="/watchlist">Domain Watchlist</FooterLink>
              <FooterLink href="/alerts">Alerts</FooterLink>
              <FooterLink href="/clients">Client Management</FooterLink>
            </FooterColumn>

            <FooterColumn title="Technology">
              <FooterExternalLink href="https://www.virustotal.com">VirusTotal</FooterExternalLink>
              <FooterExternalLink href="https://www.abuseipdb.com">AbuseIPDB</FooterExternalLink>
              <FooterExternalLink href="https://urlscan.io">URLScan.io</FooterExternalLink>
              <FooterExternalLink href="https://attack.mitre.org">MITRE ATT&CK</FooterExternalLink>
            </FooterColumn>
          </div>
        </div>

        {/* Divider */}
        <div style={{ borderTop: "1px solid var(--border-dim)", marginBottom: 20 }} />

        {/* Bottom row: copyright + badges */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              fontFamily: "var(--font-sans)",
            }}
          >
            &copy; {YEAR} Threat Investigator by Timotei Moscaliuc. All rights reserved.
          </span>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Badge color="#60a5fa">AI-Powered</Badge>
            <Badge color="#818cf8">Evidence-Based</Badge>
            <Badge color="#34d399">MITRE ATT&CK</Badge>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
                color: "var(--text-muted)",
                padding: "2px 8px",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                letterSpacing: "0.04em",
              }}
            >
              v1.0
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}

function FooterColumn({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          color: "var(--text-dim)",
          letterSpacing: "0.07em",
          textTransform: "uppercase",
          fontFamily: "var(--font-sans)",
          marginBottom: 12,
        }}
      >
        {title}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {children}
      </div>
    </div>
  );
}

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      style={{
        fontSize: 12,
        color: "var(--text-muted)",
        textDecoration: "none",
        fontFamily: "var(--font-sans)",
        transition: "color 0.15s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
      onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
    >
      {children}
    </a>
  );
}

function FooterExternalLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        fontSize: 12,
        color: "var(--text-muted)",
        textDecoration: "none",
        fontFamily: "var(--font-sans)",
        display: "flex",
        alignItems: "center",
        gap: 4,
        transition: "color 0.15s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
      onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
    >
      {children}
      <svg width="9" height="9" viewBox="0 0 12 12" fill="none" style={{ opacity: 0.5 }}>
        <path d="M2 10L10 2M10 2H4M10 2V8" stroke="currentColor" strokeWidth="1.5"
          strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </a>
  );
}

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span
      style={{
        fontSize: 10,
        fontWeight: 600,
        fontFamily: "var(--font-sans)",
        color: color,
        padding: "2px 8px",
        background: `${color}12`,
        border: `1px solid ${color}30`,
        borderRadius: 20,
        letterSpacing: "0.03em",
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
      }}
    >
      <span
        style={{
          width: 4,
          height: 4,
          borderRadius: "50%",
          background: color,
          flexShrink: 0,
          display: "inline-block",
        }}
      />
      {children}
    </span>
  );
}
