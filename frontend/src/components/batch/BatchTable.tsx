"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { BatchInvestigation } from "@/lib/types";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

interface Props {
  investigations: BatchInvestigation[];
}

type SortKey = "domain" | "classification" | "risk_score" | "state";

export default function BatchTable({ investigations }: Props) {
  const router = useRouter();
  const [sortKey, setSortKey] = useState<SortKey>("domain");
  const [sortAsc, setSortAsc] = useState(true);

  const sorted = [...investigations].sort((a, b) => {
    let cmp = 0;
    switch (sortKey) {
      case "domain":
        cmp = (a.domain || "").localeCompare(b.domain || "");
        break;
      case "classification":
        cmp = (a.classification || "").localeCompare(b.classification || "");
        break;
      case "risk_score":
        cmp = (a.risk_score ?? -1) - (b.risk_score ?? -1);
        break;
      case "state":
        cmp = (a.state || "").localeCompare(b.state || "");
        break;
    }
    return sortAsc ? cmp : -cmp;
  });

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  return (
    <div style={{
      background: "var(--bg-card)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius-lg)",
      overflow: "hidden",
    }}>
      {/* Header row */}
      <div style={{
        display: "grid", gridTemplateColumns: "2fr 1fr 80px 1fr",
        padding: "10px 16px",
        borderBottom: "1px solid var(--border)",
        background: "var(--bg-elevated)",
      }}>
        {(["domain", "classification", "risk_score", "state"] as SortKey[]).map((key) => (
          <button
            key={key}
            onClick={() => toggleSort(key)}
            style={{
              background: "none", border: "none", cursor: "pointer",
              fontSize: 11, fontWeight: 600, color: sortKey === key ? "var(--accent)" : "var(--text-muted)",
              fontFamily: "var(--font-sans)", textAlign: "left", padding: 0,
              textTransform: "capitalize",
            }}
          >
            {key === "risk_score" ? "Risk" : key}
            {sortKey === key && (sortAsc ? " \u2191" : " \u2193")}
          </button>
        ))}
      </div>

      {/* Rows */}
      {sorted.length === 0 ? (
        <div style={{
          padding: 24, textAlign: "center",
          fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)",
        }}>
          No investigations yet
        </div>
      ) : (
        sorted.map((inv, i) => {
          const classConfig = CLASSIFICATION_CONFIG[inv.classification as keyof typeof CLASSIFICATION_CONFIG];
          return (
            <div
              key={inv.id}
              onClick={() => router.push(`/investigations/${inv.id}`)}
              style={{
                display: "grid", gridTemplateColumns: "2fr 1fr 80px 1fr",
                padding: "12px 16px",
                borderBottom: i < sorted.length - 1 ? "1px solid var(--border-dim)" : "none",
                cursor: "pointer",
                transition: "background 0.15s",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-card-hover)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{
                fontSize: 12, fontWeight: 600, color: "var(--text)",
                fontFamily: "var(--font-mono)",
              }}>
                {inv.domain}
              </span>
              <span>
                {classConfig ? (
                  <span style={{
                    fontSize: 10, fontWeight: 600,
                    padding: "2px 8px",
                    background: classConfig.bg,
                    color: classConfig.color,
                    borderRadius: "var(--radius-sm)",
                    fontFamily: "var(--font-sans)",
                  }}>
                    {classConfig.label}
                  </span>
                ) : (
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>—</span>
                )}
              </span>
              <span style={{
                fontSize: 12, fontWeight: 600,
                color: inv.risk_score != null
                  ? inv.risk_score >= 70 ? "var(--red)"
                    : inv.risk_score >= 40 ? "var(--yellow)"
                      : "var(--green)"
                  : "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}>
                {inv.risk_score != null ? inv.risk_score : "—"}
              </span>
              <span style={{
                fontSize: 11, color: inv.state === "concluded" ? "var(--green)" : "var(--text-muted)",
                fontFamily: "var(--font-sans)", fontWeight: 500,
              }}>
                {inv.state}
              </span>
            </div>
          );
        })
      )}
    </div>
  );
}
