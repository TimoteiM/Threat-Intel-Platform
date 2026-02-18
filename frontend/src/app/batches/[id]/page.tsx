"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import BatchTable from "@/components/batch/BatchTable";
import CampaignView from "@/components/batch/CampaignView";
import * as api from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

export default function BatchDetailPage() {
  const params = useParams();
  const router = useRouter();
  const batchId = params?.id as string;

  const [batch, setBatch] = useState<any>(null);
  const [campaigns, setCampaigns] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [campaignLoading, setCampaignLoading] = useState(false);
  const [activeView, setActiveView] = useState<"table" | "campaigns">("table");

  const fetchBatch = useCallback(async () => {
    if (!batchId) return;
    try {
      const data = await api.getBatch(batchId);
      setBatch(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, [batchId]);

  useEffect(() => {
    fetchBatch();
    // Poll while not completed
    const interval = setInterval(() => {
      if (batch?.status === "completed" || batch?.status === "failed") return;
      fetchBatch();
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchBatch, batch?.status]);

  const handleDetectCampaigns = async () => {
    setCampaignLoading(true);
    try {
      const data = await api.getBatchCampaigns(batchId);
      setCampaigns(data);
      setActiveView("campaigns");
    } catch (e: any) {
      alert(`Campaign detection failed: ${e.message}`);
    } finally {
      setCampaignLoading(false);
    }
  };

  if (loading && !batch) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
          Loading batch...
        </div>
      </div>
    );
  }

  if (!batch) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <div style={{ fontSize: 13, color: "var(--red)", fontFamily: "var(--font-sans)" }}>
          Batch not found
        </div>
      </div>
    );
  }

  const progress = batch.total_domains > 0
    ? Math.round((batch.completed_count / batch.total_domains) * 100)
    : 0;

  // Classification breakdown
  const classBreakdown: Record<string, number> = {};
  for (const inv of batch.investigations || []) {
    if (inv.classification) {
      classBreakdown[inv.classification] = (classBreakdown[inv.classification] || 0) + 1;
    }
  }

  return (
    <div style={{ paddingBottom: 80 }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        marginBottom: 24,
      }}>
        <div>
          <div style={{
            fontSize: 20, fontWeight: 700, color: "var(--text)",
            fontFamily: "var(--font-sans)", marginBottom: 4,
          }}>
            {batch.name || `Batch ${batchId.slice(0, 8)}`}
          </div>
          <div style={{
            fontSize: 12, color: "var(--text-muted)",
            fontFamily: "var(--font-sans)",
          }}>
            {batch.total_domains} domains
            {batch.created_at && ` \u00b7 Created ${new Date(batch.created_at).toLocaleString()}`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => router.push("/batches")}
            style={{
              padding: "7px 14px", background: "var(--bg-elevated)",
              border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
              color: "var(--text-secondary)", fontSize: 12, fontWeight: 500,
              cursor: "pointer", fontFamily: "var(--font-sans)",
            }}
          >
            All Batches
          </button>
          <button
            onClick={fetchBatch}
            style={{
              padding: "7px 14px", background: "var(--bg-elevated)",
              border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
              color: "var(--text-secondary)", fontSize: 12, fontWeight: 500,
              cursor: "pointer", fontFamily: "var(--font-sans)",
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Progress bar */}
      <div style={{
        marginBottom: 24,
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        padding: 16,
      }}>
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          marginBottom: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <StatusBadge status={batch.status} />
            <span style={{
              fontSize: 12, fontWeight: 600, color: "var(--text)",
              fontFamily: "var(--font-mono)",
            }}>
              {batch.completed_count} / {batch.total_domains} completed
            </span>
          </div>
          <span style={{
            fontSize: 12, fontWeight: 700, color: "var(--accent)",
            fontFamily: "var(--font-mono)",
          }}>
            {progress}%
          </span>
        </div>
        <div style={{
          height: 6, background: "var(--bg-elevated)",
          borderRadius: 3, overflow: "hidden",
        }}>
          <div style={{
            height: "100%", width: `${progress}%`,
            background: batch.status === "completed"
              ? "var(--green)"
              : "linear-gradient(90deg, var(--accent), #818cf8)",
            borderRadius: 3,
            transition: "width 0.5s ease",
          }} />
        </div>
      </div>

      {/* Classification breakdown */}
      {Object.keys(classBreakdown).length > 0 && (
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8,
          marginBottom: 24,
        }}>
          {(["malicious", "suspicious", "benign", "inconclusive"] as const).map((cls) => {
            const config = CLASSIFICATION_CONFIG[cls];
            const count = classBreakdown[cls] || 0;
            return (
              <div key={cls} style={{
                padding: "14px 16px",
                background: count > 0 ? `${config.color}0a` : "var(--bg-input)",
                border: `1px solid ${count > 0 ? `${config.color}33` : "var(--border)"}`,
                borderRadius: "var(--radius)",
                textAlign: "center",
              }}>
                <div style={{
                  fontSize: 24, fontWeight: 800,
                  color: count > 0 ? config.color : "var(--text-dim)",
                  fontFamily: "var(--font-mono)",
                }}>
                  {count}
                </div>
                <div style={{
                  fontSize: 11, fontWeight: 600,
                  color: count > 0 ? config.color : "var(--text-muted)",
                  letterSpacing: "0.01em", marginTop: 4,
                  fontFamily: "var(--font-sans)",
                }}>
                  {config.label}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* View toggle + Campaign detection */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: 16,
      }}>
        <div style={{ display: "flex", gap: 8 }}>
          <ViewButton
            active={activeView === "table"}
            onClick={() => setActiveView("table")}
          >
            Investigation Table
          </ViewButton>
          <ViewButton
            active={activeView === "campaigns"}
            onClick={() => {
              if (campaigns) {
                setActiveView("campaigns");
              } else {
                handleDetectCampaigns();
              }
            }}
          >
            {campaignLoading ? "Detecting..." : "Campaign Detection"}
          </ViewButton>
        </div>
      </div>

      {/* Content */}
      {activeView === "table" && (
        <BatchTable investigations={batch.investigations || []} />
      )}
      {activeView === "campaigns" && campaigns && (
        <CampaignView data={campaigns} />
      )}
      {activeView === "campaigns" && !campaigns && !campaignLoading && (
        <div style={{
          padding: 40, textAlign: "center",
          background: "var(--bg-card)", border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
        }}>
          <div style={{
            fontSize: 13, color: "var(--text-dim)",
            fontFamily: "var(--font-sans)", marginBottom: 16,
          }}>
            Campaign detection analyzes shared infrastructure across all domains in this batch.
          </div>
          <button
            onClick={handleDetectCampaigns}
            disabled={batch.status !== "completed"}
            style={{
              padding: "10px 24px",
              background: batch.status === "completed" ? "var(--accent)" : "var(--bg-elevated)",
              color: batch.status === "completed" ? "#fff" : "var(--text-muted)",
              border: "none", borderRadius: "var(--radius-sm)",
              fontSize: 13, fontWeight: 600, cursor: batch.status === "completed" ? "pointer" : "not-allowed",
              fontFamily: "var(--font-sans)",
            }}
          >
            {batch.status === "completed" ? "Detect Campaigns" : "Waiting for batch to complete..."}
          </button>
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    created: { bg: "rgba(148,163,184,0.12)", color: "var(--text-muted)" },
    processing: { bg: "rgba(96,165,250,0.12)", color: "var(--accent)" },
    completed: { bg: "rgba(52,211,153,0.12)", color: "var(--green)" },
    failed: { bg: "rgba(248,113,113,0.12)", color: "var(--red)" },
  };
  const c = colors[status] || colors.created;

  return (
    <span style={{
      fontSize: 10, fontWeight: 600,
      padding: "3px 10px",
      background: c.bg, color: c.color,
      borderRadius: "var(--radius-sm)",
      fontFamily: "var(--font-sans)",
      textTransform: "uppercase",
      letterSpacing: "0.04em",
    }}>
      {status}
    </span>
  );
}

function ViewButton({
  active, onClick, children,
}: {
  active: boolean; onClick: () => void; children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "7px 16px",
        background: active ? "var(--accent)" : "var(--bg-elevated)",
        border: active ? "1px solid var(--accent)" : "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        color: active ? "#fff" : "var(--text-dim)",
        fontSize: 12, fontWeight: 500, cursor: "pointer",
        fontFamily: "var(--font-sans)",
      }}
    >
      {children}
    </button>
  );
}
