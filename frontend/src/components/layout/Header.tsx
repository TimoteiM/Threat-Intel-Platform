"use client";

import React from "react";

export default function Header() {
  return (
    <header
      style={{
        borderBottom: "1px solid var(--border)",
        padding: "14px 0",
        background: "linear-gradient(180deg, rgba(59,130,246,0.02) 0%, transparent 100%)",
      }}
    >
      <div style={{
        maxWidth: 1320,
        margin: "0 auto",
        padding: "0 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 30,
              height: 30,
              borderRadius: 6,
              background: "linear-gradient(135deg, #3b82f6 0%, #6366f1 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 14,
              fontWeight: 700,
              color: "#fff",
            }}
          >
            ⬡
          </div>
          <div>
            <div style={{
              fontSize: 13,
              fontWeight: 700,
              letterSpacing: "0.08em",
              color: "var(--text)",
              fontFamily: "var(--font-mono)",
            }}>
              THREAT INVESTIGATOR
            </div>
            <div style={{
              fontSize: 9,
              color: "var(--text-muted)",
              letterSpacing: "0.12em",
              fontFamily: "var(--font-mono)",
            }}>
              DOMAIN ANALYSIS PLATFORM
            </div>
          </div>
        </div>
        <div style={{
          fontSize: 10,
          color: "var(--text-muted)",
          fontFamily: "var(--font-mono)",
          display: "flex",
          alignItems: "center",
          gap: 16,
        }}>
          <a href="/investigations" style={{
            color: "var(--text-dim)", textDecoration: "none",
            fontSize: 10, letterSpacing: "0.08em", fontWeight: 600,
            transition: "color 0.15s",
          }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-dim)")}
          >
            ALL CASES
          </a>
          <span>v1.0.0</span>
        </div>
      </div>
    </header>
  );
}
