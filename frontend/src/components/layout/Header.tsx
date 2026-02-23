"use client";

import React from "react";

export default function Header() {
  return (
    <header
      style={{
        borderBottom: "1px solid var(--border)",
        background: "rgba(15, 23, 42, 0.85)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
        position: "sticky",
        top: 0,
        zIndex: 50,
      }}
    >
      <div style={{
        maxWidth: 1320,
        margin: "0 auto",
        padding: "0 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        height: 56,
      }}>
        <a
          href="/"
          style={{ display: "flex", alignItems: "center", gap: 12, textDecoration: "none" }}
        >
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: "linear-gradient(135deg, #60a5fa 0%, #818cf8 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 15,
              fontWeight: 700,
              color: "#fff",
              boxShadow: "0 2px 8px rgba(96, 165, 250, 0.3)",
            }}
          >
            ⬡
          </div>
          <div>
            <div style={{
              fontSize: 14,
              fontWeight: 700,
              letterSpacing: "0.02em",
              color: "var(--text)",
              fontFamily: "var(--font-sans)",
            }}>
              Threat Investigator
            </div>
            <div style={{
              fontSize: 10,
              color: "var(--text-muted)",
              letterSpacing: "0.01em",
              fontFamily: "var(--font-sans)",
              fontWeight: 500,
            }}>
              Domain Analysis Platform
            </div>
          </div>
        </a>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
        }}>
          <NavLink href="/dashboard">Dashboard</NavLink>
          <NavLink href="/investigations">All Cases</NavLink>
          <NavLink href="/batches">Bulk Analysis</NavLink>
          <NavLink href="/watchlist">Watchlist</NavLink>
          <span style={{
            fontSize: 11,
            color: "var(--text-muted)",
            fontFamily: "var(--font-mono)",
            padding: "2px 8px",
            background: "var(--bg-elevated)",
            borderRadius: "var(--radius-sm)",
          }}>v1.0</span>
        </div>
      </div>
    </header>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      style={{
        color: "var(--text-dim)", textDecoration: "none",
        fontSize: 13, fontWeight: 500,
        fontFamily: "var(--font-sans)",
        padding: "6px 12px",
        borderRadius: "var(--radius-sm)",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = "var(--accent)";
        e.currentTarget.style.background = "var(--accent-glow)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = "var(--text-dim)";
        e.currentTarget.style.background = "transparent";
      }}
    >
      {children}
    </a>
  );
}
