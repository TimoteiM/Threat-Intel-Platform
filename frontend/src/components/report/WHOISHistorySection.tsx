"use client";

import React, { useState, useEffect } from "react";
import * as api from "@/lib/api";

interface Props {
  domain: string;
}

export default function WHOISHistorySection({ domain }: Props) {
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!domain) return;
    setLoading(true);
    api.getWhoisHistory(domain)
      .then(setSnapshots)
      .catch(() => setSnapshots([]))
      .finally(() => setLoading(false));
  }, [domain]);

  if (loading) {
    return (
      <div style={{ padding: 16, fontSize: 12, color: "var(--text-dim)" }}>
        Loading WHOIS history...
      </div>
    );
  }

  if (snapshots.length <= 1) {
    return null; // Only show if there are multiple snapshots to compare
  }

  return (
    <div style={{ marginTop: 24 }}>
      <div style={{
        fontSize: 13, fontWeight: 600, color: "var(--accent)",
        letterSpacing: "0.01em", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-sans)",
      }}>
        WHOIS History ({snapshots.length} snapshots)
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {snapshots.map((snap, idx) => {
          const changes = snap.changes_from_previous;
          const hasChanges = changes && Object.keys(changes).length > 0;

          return (
            <div
              key={snap.id}
              style={{
                padding: "12px 16px",
                background: "var(--bg-input)",
                border: `1px solid ${hasChanges ? "rgba(245,158,11,0.3)" : "var(--border)"}`,
                borderRadius: "var(--radius)",
                borderLeft: hasChanges ? "3px solid var(--yellow)" : "3px solid var(--border)",
              }}
            >
              {/* Header */}
              <div style={{
                display: "flex", justifyContent: "space-between",
                alignItems: "center", marginBottom: hasChanges ? 8 : 0,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{
                    fontSize: 11, fontWeight: 600, color: "var(--text)",
                    fontFamily: "var(--font-mono)",
                  }}>
                    {snap.captured_at
                      ? new Date(snap.captured_at).toLocaleString()
                      : "Unknown date"}
                  </span>
                  {idx === 0 && (
                    <span style={{
                      fontSize: 9, padding: "1px 6px", fontWeight: 600,
                      background: "rgba(59,130,246,0.1)", color: "var(--accent)",
                      borderRadius: "var(--radius-sm)", letterSpacing: "0.06em",
                    }}>
                      LATEST
                    </span>
                  )}
                  {hasChanges && (
                    <span style={{
                      fontSize: 9, padding: "1px 6px", fontWeight: 600,
                      background: "rgba(245,158,11,0.1)", color: "var(--yellow)",
                      borderRadius: "var(--radius-sm)", letterSpacing: "0.06em",
                    }}>
                      CHANGED
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", gap: 8, fontSize: 10, color: "var(--text-dim)" }}>
                  {snap.whois_json?.registrar && (
                    <span>Registrar: {snap.whois_json.registrar}</span>
                  )}
                </div>
              </div>

              {/* Changes diff */}
              {hasChanges && (
                <div style={{
                  display: "flex", flexDirection: "column", gap: 4,
                  paddingTop: 8, borderTop: "1px solid var(--border)",
                }}>
                  {Object.entries(changes).map(([field, diff]: [string, any]) => (
                    <div key={field} style={{
                      display: "flex", gap: 8, alignItems: "center",
                      fontSize: 11, fontFamily: "var(--font-mono)",
                    }}>
                      <span style={{
                        color: "var(--text-muted)", minWidth: 120, fontWeight: 600,
                      }}>
                        {field}
                      </span>
                      <span style={{ color: "var(--red)", textDecoration: "line-through" }}>
                        {formatValue(diff.old)}
                      </span>
                      <span style={{ color: "var(--text-dim)" }}>&rarr;</span>
                      <span style={{ color: "var(--green)", fontWeight: 600 }}>
                        {formatValue(diff.new)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function formatValue(val: any): string {
  if (val === null || val === undefined) return "—";
  if (Array.isArray(val)) return val.join(", ");
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}
