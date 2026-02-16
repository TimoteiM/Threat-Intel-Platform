"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import InvestigationInput from "@/components/investigation/InvestigationInput";
import { createInvestigation, listInvestigations } from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

export default function HomePage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [recent, setRecent] = useState<any[]>([]);

  useEffect(() => {
    listInvestigations({ limit: 10 })
      .then(setRecent)
      .catch(() => {}); // silently fail if API not available
  }, []);

  const handleSubmit = useCallback(
    async (domain: string, context?: string) => {
      setLoading(true);
      try {
        const result = await createInvestigation({ domain, context });
        router.push(`/investigations/${result.investigation_id}`);
      } catch (e: any) {
        alert(`Failed: ${e.message}`);
        setLoading(false);
      }
    },
    [router]
  );

  return (
    <div style={{ paddingBottom: 80 }}>
      <InvestigationInput onSubmit={handleSubmit} loading={loading} />

      {recent.length > 0 && (
        <div style={{ marginTop: 40 }}>
          <div
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: "var(--text-dim)",
              letterSpacing: "0.08em",
              marginBottom: 16,
            }}
          >
            RECENT INVESTIGATIONS
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {recent.map((inv) => {
              const classConfig =
                CLASSIFICATION_CONFIG[inv.classification as keyof typeof CLASSIFICATION_CONFIG];
              return (
                <button
                  key={inv.id}
                  onClick={() => router.push(`/investigations/${inv.id}`)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 16,
                    padding: "12px 16px",
                    background: "var(--bg-card)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius)",
                    cursor: "pointer",
                    textAlign: "left",
                    fontFamily: "var(--font-mono)",
                    color: "var(--text)",
                    width: "100%",
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-card)")}
                >
                  <span style={{ fontSize: 13, fontWeight: 600, flex: 1 }}>
                    {inv.domain}
                  </span>
                  {classConfig && (
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: "2px 8px",
                        background: classConfig.bg,
                        color: classConfig.color,
                        borderRadius: "var(--radius-sm)",
                        letterSpacing: "0.1em",
                      }}
                    >
                      {classConfig.label}
                    </span>
                  )}
                  {inv.risk_score != null && (
                    <span style={{ fontSize: 11, color: "var(--text-dim)", minWidth: 30 }}>
                      {inv.risk_score}
                    </span>
                  )}
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{inv.state}</span>
                  <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                    {new Date(inv.created_at).toLocaleDateString()}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}