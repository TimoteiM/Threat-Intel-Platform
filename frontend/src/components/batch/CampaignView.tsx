"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { CampaignResponse } from "@/lib/types";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

interface Props {
  data: CampaignResponse;
}

const INFRA_TYPE_COLORS: Record<string, string> = {
  ip: "#60a5fa",
  certificate: "#fbbf24",
  asn: "#34d399",
  registrar: "#a78bfa",
  nameserver: "#94a3b8",
};

export default function CampaignView({ data }: Props) {
  const router = useRouter();

  if (data.campaigns.length === 0 && data.unclustered.length === 0) {
    return (
      <div style={{
        padding: 24, textAlign: "center",
        fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)",
      }}>
        No campaign patterns detected. Domains do not share infrastructure.
      </div>
    );
  }

  return (
    <div>
      {data.campaigns.map((campaign, ci) => (
        <div key={ci} style={{
          marginBottom: 20,
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
        }}>
          {/* Campaign header */}
          <div style={{
            padding: "12px 16px",
            background: "rgba(239,68,68,0.06)",
            borderBottom: "1px solid var(--border)",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <div>
              <span style={{
                fontSize: 13, fontWeight: 700, color: "var(--red)",
                fontFamily: "var(--font-sans)",
              }}>
                Campaign {ci + 1}
              </span>
              <span style={{
                fontSize: 11, color: "var(--text-muted)",
                marginLeft: 12, fontFamily: "var(--font-sans)",
              }}>
                {campaign.size} domains
              </span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {campaign.shared_infrastructure.map((si, j) => (
                <span
                  key={j}
                  style={{
                    fontSize: 10, fontWeight: 500,
                    padding: "3px 8px",
                    background: `${INFRA_TYPE_COLORS[si.type] || "#94a3b8"}15`,
                    color: INFRA_TYPE_COLORS[si.type] || "#94a3b8",
                    border: `1px solid ${INFRA_TYPE_COLORS[si.type] || "#94a3b8"}30`,
                    borderRadius: "var(--radius-sm)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {si.type}: {si.values.join(", ")}
                </span>
              ))}
            </div>
          </div>

          {/* Campaign domains */}
          {campaign.domains.map((d, di) => {
            const classConfig = CLASSIFICATION_CONFIG[d.classification as keyof typeof CLASSIFICATION_CONFIG];
            return (
              <div
                key={d.id}
                onClick={() => router.push(`/investigations/${d.id}`)}
                style={{
                  display: "flex", alignItems: "center", gap: 12,
                  padding: "10px 16px",
                  borderBottom: di < campaign.domains.length - 1 ? "1px solid var(--border-dim)" : "none",
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-card-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{
                  fontSize: 12, fontWeight: 600, flex: 1,
                  color: "var(--text)", fontFamily: "var(--font-mono)",
                }}>
                  {d.domain}
                </span>
                {classConfig && (
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
                )}
                {d.risk_score != null && (
                  <span style={{
                    fontSize: 11, fontWeight: 600,
                    color: "var(--text-dim)", fontFamily: "var(--font-mono)",
                  }}>
                    {d.risk_score}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      ))}

      {/* Unclustered domains */}
      {data.unclustered.length > 0 && (
        <div style={{
          marginTop: 16,
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
        }}>
          <div style={{
            padding: "10px 16px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-elevated)",
          }}>
            <span style={{
              fontSize: 12, fontWeight: 600, color: "var(--text-muted)",
              fontFamily: "var(--font-sans)",
            }}>
              Unclustered ({data.unclustered.length} domains — no shared infrastructure detected)
            </span>
          </div>
          {data.unclustered.map((d, i) => {
            const classConfig = CLASSIFICATION_CONFIG[d.classification as keyof typeof CLASSIFICATION_CONFIG];
            return (
              <div
                key={d.id}
                onClick={() => router.push(`/investigations/${d.id}`)}
                style={{
                  display: "flex", alignItems: "center", gap: 12,
                  padding: "10px 16px",
                  borderBottom: i < data.unclustered.length - 1 ? "1px solid var(--border-dim)" : "none",
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-card-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{
                  fontSize: 12, fontWeight: 600, flex: 1,
                  color: "var(--text)", fontFamily: "var(--font-mono)",
                }}>
                  {d.domain}
                </span>
                {classConfig && (
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
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
