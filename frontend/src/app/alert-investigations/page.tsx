"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import ConsoleModule from "@/components/ui/ConsoleModule";
import PageHero from "@/components/ui/PageHero";
import {
  alertInvestigationExportUrl,
  deleteAlertInvestigation,
  listAlertInvestigations,
} from "@/lib/api";
import type { AlertInvestigationRun } from "@/lib/types";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#f87171",
  suspicious: "#fbbf24",
  benign: "#34d399",
  inconclusive: "#94a3b8",
};

const VERDICT_FILTERS = ["all", "malicious", "suspicious", "benign", "inconclusive"];

export default function AlertInvestigationsPage() {
  const router = useRouter();
  const [items, setItems] = useState<AlertInvestigationRun[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("all");
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listAlertInvestigations({ limit: 50, search, verdict });
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [search, verdict]);

  useEffect(() => {
    const timer = setTimeout(load, 250);
    return () => clearTimeout(timer);
  }, [load]);

  const handleDelete = async (run: AlertInvestigationRun) => {
    const spawned = run.spawned_investigation_count || 0;
    const consequence = spawned
      ? `\n\nThis also deletes the ${spawned} investigation${spawned === 1 ? "" : "s"} this run started, ` +
        "with their reports and evidence. Investigations it reused, or that another alert run also " +
        "references, are kept."
      : "";
    if (!window.confirm(`Delete "${run.title}"?${consequence}`)) return;

    setDeletingId(run.run_id);
    try {
      const result = await deleteAlertInvestigation(run.run_id);
      if (result?.kept_investigations?.length) {
        alert(
          `Run deleted. ${result.kept_investigations.length} investigation(s) were kept because ` +
            "another alert run still references them.",
        );
      }
      await load();
    } catch (e: any) {
      alert(`Failed to delete: ${e?.message || e}`);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 18, paddingBottom: 56 }}>
      <PageHero
        title="Alert Body Investigations"
        description="Paste a raw alert on the New Investigation page — every IOC it contains is extracted, run through the collectors, and returned as a list of JSON reports."
        actions={
          <button onClick={() => router.push("/")} style={primaryButtonStyle}>
            New alert investigation
          </button>
        }
        stats={
          <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
            {total} run{total === 1 ? "" : "s"}
          </span>
        }
      />

      <ConsoleModule
        title="Runs"
        actions={
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title or alert text"
              style={{
                padding: "7px 12px",
                borderRadius: 8,
                border: "1px solid var(--border)",
                background: "var(--bg-input)",
                color: "var(--text)",
                fontSize: 12,
                minWidth: 220,
                outline: "none",
              }}
            />
            <select
              value={verdict}
              onChange={(e) => setVerdict(e.target.value)}
              style={{
                padding: "7px 10px",
                borderRadius: 8,
                border: "1px solid var(--border)",
                background: "var(--bg-input)",
                color: "var(--text)",
                fontSize: 12,
                outline: "none",
              }}
            >
              {VERDICT_FILTERS.map((option) => (
                <option key={option} value={option}>
                  {option === "all" ? "All verdicts" : option}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {loading ? (
          <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>Loading…</div>
        ) : items.length === 0 ? (
          <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
            No alert body investigations yet.
          </div>
        ) : (
          /* Some runs are titled with a whole flattened log line — 255
             characters, unwrappable. Without a capped track, that one row sets
             the column width and every other row overflows the card with it. */
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 8 }}>
            {items.map((run) => (
              <div
                key={run.run_id}
                role="button"
                tabIndex={0}
                onClick={() => router.push(`/alert-investigations/${run.run_id}`)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    router.push(`/alert-investigations/${run.run_id}`);
                  }
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  minWidth: 0,
                  padding: "11px 14px",
                  borderRadius: 12,
                  border: "1px solid var(--panel-divider-strong)",
                  borderLeft: `3px solid ${VERDICT_COLORS[String(run.overall_verdict)] || "var(--border)"}`,
                  background: "var(--bg-elevated)",
                  cursor: "pointer",
                }}
              >
                <span
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 12.5,
                    fontFamily: "var(--font-mono)",
                    color: "var(--text)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {run.title}
                </span>

                <span style={{ fontSize: 10.5, color: "var(--text-muted)", fontFamily: "var(--font-sans)", flexShrink: 0 }}>
                  {run.indicator_count} indicator{run.indicator_count === 1 ? "" : "s"}
                </span>

                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: "0.05em",
                    textTransform: "uppercase",
                    color: VERDICT_COLORS[String(run.overall_verdict)] || "var(--text-muted)",
                    fontFamily: "var(--font-sans)",
                    minWidth: 80,
                    textAlign: "right",
                    flexShrink: 0,
                  }}
                >
                  {run.overall_verdict || run.status}
                </span>

                <span
                  style={{
                    fontSize: 10.5,
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-sans)",
                    minWidth: 130,
                    textAlign: "right",
                    flexShrink: 0,
                  }}
                >
                  {run.created_at ? new Date(run.created_at).toLocaleString() : "—"}
                </span>

                <a
                  href={alertInvestigationExportUrl(run.run_id)}
                  onClick={(event) => event.stopPropagation()}
                  title="Download this run's JSON report list"
                  style={{
                    border: "1px solid var(--border)",
                    background: "var(--bg-input)",
                    color: "var(--text-secondary)",
                    borderRadius: 6,
                    padding: "5px 8px",
                    fontSize: 9,
                    fontWeight: 800,
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    textDecoration: "none",
                    flexShrink: 0,
                  }}
                >
                  Export
                </a>

                <button
                  type="button"
                  disabled={deletingId === run.run_id}
                  onClick={(event) => {
                    event.stopPropagation();
                    handleDelete(run);
                  }}
                  style={{
                    border: "1px solid rgba(251, 113, 133, 0.28)",
                    background: "rgba(127, 29, 29, 0.14)",
                    color: "#fda4af",
                    borderRadius: 6,
                    padding: "5px 8px",
                    fontSize: 9,
                    fontWeight: 800,
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    cursor: deletingId === run.run_id ? "wait" : "pointer",
                    flexShrink: 0,
                  }}
                >
                  {deletingId === run.run_id ? "Deleting" : "Delete"}
                </button>
              </div>
            ))}
          </div>
        )}
      </ConsoleModule>
    </div>
  );
}

const primaryButtonStyle: React.CSSProperties = {
  padding: "8px 16px",
  borderRadius: 8,
  border: "none",
  background: "linear-gradient(135deg, #60a5fa, #818cf8)",
  color: "#fff",
  fontSize: 12,
  fontWeight: 600,
  fontFamily: "var(--font-sans)",
  cursor: "pointer",
};
