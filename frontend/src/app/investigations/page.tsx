"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { listInvestigations } from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import Spinner from "@/components/shared/Spinner";
import Badge from "@/components/shared/Badge";

export default function InvestigationsListPage() {
  const router = useRouter();
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    setLoading(true);
    const params: any = { limit: 100 };
    if (filter !== "all") params.state = filter;

    listInvestigations(params)
      .then((data) => {
        setInvestigations(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filter]);

  const filters = ["all", "created", "gathering", "evaluating", "concluded", "failed"];

  return (
    <div style={{ paddingTop: 24, paddingBottom: 80 }}>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 24,
      }}>
        <div>
          <div style={{
            fontSize: 18, fontWeight: 800, color: "var(--text)",
            letterSpacing: "0.04em", fontFamily: "var(--font-mono)",
          }}>
            ALL INVESTIGATIONS
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
            {investigations.length} investigation{investigations.length !== 1 ? "s" : ""}
          </div>
        </div>
        <button
          onClick={() => router.push("/")}
          style={{
            padding: "10px 20px",
            background: "linear-gradient(135deg, #3b82f6, #2563eb)",
            border: "none", borderRadius: "var(--radius)",
            color: "#fff", fontSize: 11, fontWeight: 700,
            cursor: "pointer", fontFamily: "var(--font-mono)",
            letterSpacing: "0.06em",
          }}
        >
          + NEW INVESTIGATION
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 6, marginBottom: 20 }}>
        {filters.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: "6px 14px",
              background: filter === f ? "var(--accent)" : "var(--bg-card)",
              border: `1px solid ${filter === f ? "var(--accent)" : "var(--border)"}`,
              borderRadius: "var(--radius-sm)",
              color: filter === f ? "#fff" : "var(--text-dim)",
              fontSize: 10, fontWeight: 600, cursor: "pointer",
              fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {loading ? (
        <Spinner message="Loading investigations..." />
      ) : investigations.length === 0 ? (
        <div style={{
          textAlign: "center", padding: 60,
          color: "var(--text-dim)", fontSize: 13,
        }}>
          No investigations found.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {/* Header */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "2fr 120px 80px 100px 140px",
            gap: 12, padding: "8px 16px",
            fontSize: 9, fontWeight: 700, color: "var(--text-muted)",
            letterSpacing: "0.1em", textTransform: "uppercase",
            borderBottom: "1px solid var(--border)",
          }}>
            <div>DOMAIN</div>
            <div>CLASSIFICATION</div>
            <div>RISK</div>
            <div>STATE</div>
            <div>DATE</div>
          </div>

          {/* Rows */}
          {investigations.map((inv) => {
            const cls = inv.classification as keyof typeof CLASSIFICATION_CONFIG;
            const config = CLASSIFICATION_CONFIG[cls];

            return (
              <button
                key={inv.id}
                onClick={() => router.push(`/investigations/${inv.id}`)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "2fr 120px 80px 100px 140px",
                  gap: 12, padding: "12px 16px",
                  background: "var(--bg-card)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  cursor: "pointer", textAlign: "left",
                  fontFamily: "var(--font-mono)",
                  color: "var(--text)", width: "100%",
                  transition: "background 0.15s",
                  alignItems: "center",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-card)")}
              >
                <div style={{ fontSize: 13, fontWeight: 600 }}>{inv.domain}</div>
                <div>
                  {config ? (
                    <Badge label={config.label} color={config.color} bg={config.bg} />
                  ) : (
                    <span style={{ fontSize: 10, color: "var(--text-muted)" }}>—</span>
                  )}
                </div>
                <div style={{
                  fontSize: 13, fontWeight: 700,
                  color: config?.color || "var(--text-dim)",
                }}>
                  {inv.risk_score ?? "—"}
                </div>
                <div>
                  <span style={{
                    fontSize: 9, padding: "2px 6px",
                    background: inv.state === "concluded" ? "rgba(16,185,129,0.08)" :
                      inv.state === "failed" ? "rgba(239,68,68,0.08)" :
                        "rgba(59,130,246,0.08)",
                    color: inv.state === "concluded" ? "var(--green)" :
                      inv.state === "failed" ? "var(--red)" : "var(--accent)",
                    borderRadius: "var(--radius-sm)",
                    fontWeight: 600, letterSpacing: "0.08em",
                    textTransform: "uppercase",
                  }}>
                    {inv.state}
                  </span>
                </div>
                <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                  {inv.created_at ? new Date(inv.created_at).toLocaleString() : "—"}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}