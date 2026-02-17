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
    async (
      domain: string,
      context?: string,
      clientDomain?: string,
      investigatedUrl?: string,
      clientUrl?: string,
    ) => {
      setLoading(true);
      try {
        const result = await createInvestigation({
          domain,
          context,
          client_domain: clientDomain,
          investigated_url: investigatedUrl,
          client_url: clientUrl,
        });
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
        <div style={{ marginTop: 48 }}>
          <div
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--text-dim)",
              letterSpacing: "0.01em",
              marginBottom: 16,
              fontFamily: "var(--font-sans)",
            }}
          >
            Recent Investigations
          </div>
          <div style={{
            display: "flex",
            flexDirection: "column",
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
            boxShadow: "var(--shadow-sm)",
          }}>
            {recent.map((inv, index) => {
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
                    padding: "14px 20px",
                    background: "transparent",
                    border: "none",
                    borderBottom: index < recent.length - 1 ? "1px solid var(--border-dim)" : "none",
                    borderRadius: 0,
                    cursor: "pointer",
                    textAlign: "left",
                    color: "var(--text)",
                    width: "100%",
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <span style={{
                    fontSize: 13, fontWeight: 600, flex: 1,
                    fontFamily: "var(--font-mono)",
                  }}>
                    {inv.domain}
                  </span>
                  {classConfig && (
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        padding: "3px 10px",
                        background: classConfig.bg,
                        color: classConfig.color,
                        borderRadius: "var(--radius-sm)",
                        fontFamily: "var(--font-sans)",
                      }}
                    >
                      {classConfig.label}
                    </span>
                  )}
                  {inv.risk_score != null && (
                    <span style={{
                      fontSize: 12, color: "var(--text-dim)", minWidth: 30,
                      fontFamily: "var(--font-mono)", fontWeight: 600,
                    }}>
                      {inv.risk_score}
                    </span>
                  )}
                  <span style={{
                    fontSize: 11, color: "var(--text-muted)",
                    fontFamily: "var(--font-sans)", fontWeight: 500,
                  }}>{inv.state}</span>
                  <span style={{
                    fontSize: 11, color: "var(--text-muted)",
                    fontFamily: "var(--font-sans)",
                  }}>
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