"use client";

import React from "react";
import { CollectorStatus } from "@/lib/types";
import { COLLECTOR_STATUS_CONFIG, COLLECTOR_NAMES } from "@/lib/constants";

interface Props {
  collectors: Record<string, CollectorStatus>;
  analystDone: boolean;
}

const ALL_COLLECTORS = ["dns", "tls", "http", "whois", "asn", "intel", "vt"];

export default function ProgressTimeline({ collectors, analystDone }: Props) {
  return (
    <div
      style={{
        display: "flex",
        gap: 8,
        padding: "20px 0",
        borderBottom: "1px solid var(--border)",
        marginBottom: 24,
      }}
    >
      {ALL_COLLECTORS.map((name) => {
        const status = collectors[name] || "pending";
        const config = COLLECTOR_STATUS_CONFIG[status] || COLLECTOR_STATUS_CONFIG.pending;

        return (
          <div
            key={name}
            style={{
              flex: 1,
              padding: "10px 12px",
              background:
                status === "completed"
                  ? "rgba(52,211,153,0.06)"
                  : "transparent",
              border: `1px solid ${status === "completed" ? "rgba(52,211,153,0.18)" : "var(--border)"}`,
              borderRadius: "var(--radius)",
              textAlign: "center",
            }}
          >
            <div style={{ color: config.color, fontSize: 16, marginBottom: 4 }}>
              {status === "running" ? (
                <span className="animate-pulse">{config.symbol}</span>
              ) : (
                config.symbol
              )}
            </div>
            <div
              style={{
                fontSize: 10,
                fontWeight: 600,
                color: "var(--text)",
                letterSpacing: "0.06em",
              }}
            >
              {COLLECTOR_NAMES[name] || name.toUpperCase()}
            </div>
          </div>
        );
      })}

      {/* Analyst status */}
      <div
        style={{
          flex: 1,
          padding: "10px 12px",
          background: analystDone ? "rgba(167,139,250,0.06)" : "transparent",
          border: `1px solid ${analystDone ? "rgba(167,139,250,0.18)" : "var(--border)"}`,
          borderRadius: "var(--radius)",
          textAlign: "center",
        }}
      >
        <div
          style={{
            color: analystDone ? "var(--purple)" : "var(--text-muted)",
            fontSize: 16,
            marginBottom: 4,
          }}
        >
          {analystDone ? "✓" : "○"}
        </div>
        <div
          style={{
            fontSize: 10,
            fontWeight: 600,
            color: "var(--text)",
            letterSpacing: "0.06em",
          }}
        >
          ANALYST
        </div>
      </div>
    </div>
  );
}
