"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import BatchUpload from "@/components/batch/BatchUpload";
import * as api from "@/lib/api";

export default function BatchesPage() {
  const router = useRouter();
  const [batches, setBatches] = useState<any[]>([]);
  const [uploading, setUploading] = useState(false);

  const fetchBatches = useCallback(() => {
    api.listBatches({ limit: 50 }).then(setBatches).catch(() => {});
  }, []);

  useEffect(() => {
    fetchBatches();
  }, [fetchBatches]);

  const handleUpload = async (
    file: File,
    metadata: { name?: string; context?: string; client_domain?: string },
  ) => {
    setUploading(true);
    try {
      const result = await api.uploadBatch(file, metadata);
      router.push(`/batches/${result.batch_id}`);
    } catch (e: any) {
      alert(`Upload failed: ${e.message}`);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ paddingBottom: 40 }}>
      <BatchUpload onUpload={handleUpload} loading={uploading} />

      {batches.length > 0 && (
        <div className="animate-fade-up" style={{ marginTop: 24 }}>
          <div style={{
            fontSize: 13, fontWeight: 600, color: "var(--text-dim)",
            letterSpacing: "0.01em", marginBottom: 10,
            fontFamily: "var(--font-sans)",
          }}>
            Recent Batches
          </div>
          <div style={{
            display: "flex", flexDirection: "column",
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            overflow: "hidden",
            boxShadow: "var(--shadow-sm)",
          }}>
            {batches.map((batch, i) => (
              <button
                key={batch.id}
                className="row-hover"
                onClick={() => router.push(`/batches/${batch.id}`)}
                style={{
                  display: "flex", alignItems: "center", gap: 16,
                  padding: "14px 20px",
                  background: "transparent", border: "none",
                  borderBottom: i < batches.length - 1 ? "1px solid var(--border-dim)" : "none",
                  cursor: "pointer", textAlign: "left",
                  color: "var(--text)", width: "100%",
                }}
              >
                <span style={{
                  fontSize: 13, fontWeight: 600, flex: 1,
                  fontFamily: "var(--font-sans)",
                }}>
                  {batch.name || `Batch ${batch.id.slice(0, 8)}`}
                </span>
                <span style={{
                  fontSize: 11, color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}>
                  {batch.completed_count}/{batch.total_domains}
                </span>
                <StatusBadge status={batch.status} />
                <span style={{
                  fontSize: 11, color: "var(--text-muted)",
                  fontFamily: "var(--font-sans)",
                }}>
                  {batch.created_at ? new Date(batch.created_at).toLocaleDateString() : ""}
                </span>
              </button>
            ))}
          </div>
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
