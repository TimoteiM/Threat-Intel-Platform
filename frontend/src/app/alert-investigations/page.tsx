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

const PAGE_SIZES = [25, 50, 100];

export default function AlertInvestigationsPage() {
  const router = useRouter();
  const [items, setItems] = useState<AlertInvestigationRun[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  // Typing is debounced; paging and filtering are not. Sharing one debounce
  // would put a quarter-second lag on every Next click for no reason.
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [verdict, setVerdict] = useState("all");
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Any change to what is being listed starts again at the first page —
  // narrowing a filter while on page 4 would otherwise land on an empty page
  // that reads as "no results". The offset is reset in the same update as the
  // change rather than in a following effect, so the two settle in one render
  // instead of firing a throwaway request at the old offset first.
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setOffset(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [search]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listAlertInvestigations({
        limit: pageSize,
        offset,
        search: debouncedSearch,
        verdict,
      });
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [debouncedSearch, verdict, pageSize, offset]);

  useEffect(() => {
    load();
  }, [load]);

  // Deleting the last row of the last page leaves the offset past the end,
  // which would render an empty list rather than the page that is now last.
  useEffect(() => {
    if (!loading && offset > 0 && offset >= total) {
      setOffset(Math.max(0, (Math.ceil(total / pageSize) - 1) * pageSize));
    }
  }, [loading, offset, total, pageSize]);

  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.floor(offset / pageSize) + 1;
  const canGoPrevious = offset > 0;
  const canGoNext = offset + pageSize < total;
  const rangeStart = total === 0 ? 0 : offset + 1;
  const rangeEnd = Math.min(offset + pageSize, total);

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
              onChange={(e) => {
                setVerdict(e.target.value);
                setOffset(0);
              }}
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
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setOffset(0);
              }}
              aria-label="Runs per page"
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
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size} per page
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

        {total > 0 ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 10,
              marginTop: 14,
              paddingTop: 12,
              borderTop: "1px solid var(--panel-divider)",
            }}
          >
            <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
              {rangeStart}–{rangeEnd} of {total}
              {pageCount > 1 ? ` · page ${currentPage} of ${pageCount}` : ""}
            </span>

            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                onClick={() => setOffset((prev) => Math.max(0, prev - pageSize))}
                disabled={!canGoPrevious || loading}
                style={pageButtonStyle(canGoPrevious && !loading)}
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setOffset((prev) => prev + pageSize)}
                disabled={!canGoNext || loading}
                style={pageButtonStyle(canGoNext && !loading)}
              >
                Next
              </button>
            </div>
          </div>
        ) : null}
      </ConsoleModule>
    </div>
  );
}

function pageButtonStyle(enabled: boolean): React.CSSProperties {
  return {
    minWidth: 92,
    padding: "6px 14px",
    borderRadius: 8,
    border: `1px solid ${enabled ? "var(--panel-divider-strong)" : "var(--panel-divider)"}`,
    background: enabled ? "var(--panel-card-bg)" : "var(--bg-elevated)",
    color: enabled ? "var(--text)" : "var(--text-muted)",
    fontSize: 11.5,
    fontWeight: 600,
    fontFamily: "var(--font-sans)",
    cursor: enabled ? "pointer" : "not-allowed",
  };
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
