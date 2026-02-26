"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listInvestigations } from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import Spinner from "@/components/shared/Spinner";
import Badge from "@/components/shared/Badge";

const PAGE_SIZE_OPTIONS = [10, 25, 50];

export default function InvestigationsListPage() {
  const router = useRouter();
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounce search input
  const handleSearchChange = useCallback((value: string) => {
    setSearch(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(value);
      setPage(0);
    }, 300);
  }, []);

  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  useEffect(() => {
    setLoading(true);
    const params: any = { limit: pageSize, offset: page * pageSize };
    if (filter !== "all") params.state = filter;
    if (debouncedSearch) params.search = debouncedSearch;

    listInvestigations(params)
      .then((data) => {
        setInvestigations(data.items);
        setTotal(data.total);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filter, debouncedSearch, page, pageSize]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const showingFrom = total === 0 ? 0 : page * pageSize + 1;
  const showingTo = Math.min((page + 1) * pageSize, total);

  const filters = ["all", "created", "gathering", "evaluating", "concluded", "failed"];

  return (
    <div style={{ paddingTop: 20, paddingBottom: 40 }}>
      <div className="animate-in" style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 16,
      }}>
        <div>
          <div style={{
            fontSize: 18, fontWeight: 800, color: "var(--text)",
            letterSpacing: "0.04em", fontFamily: "var(--font-mono)",
          }}>
            ALL INVESTIGATIONS
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
            {total} investigation{total !== 1 ? "s" : ""}
            {debouncedSearch && ` matching "${debouncedSearch}"`}
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

      {/* Search bar */}
      <div className="animate-in stagger-1" style={{ marginBottom: 12 }}>
        <input
          type="text"
          value={search}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search by domain..."
          style={{
            width: "100%",
            padding: "10px 16px",
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
            color: "var(--text)",
            fontSize: 13,
            fontFamily: "var(--font-mono)",
            outline: "none",
          }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        />
      </div>

      {/* Filters */}
      <div className="animate-in stagger-2" style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {filters.map((f) => (
          <button
            key={f}
            onClick={() => { setFilter(f); setPage(0); }}
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
        <div className="animate-fade-up" style={{ display: "flex", flexDirection: "column", gap: 4 }}>
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
                className="row-hover"
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
                  alignItems: "center",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, fontFamily: "var(--font-mono)" }}>{inv.domain}</span>
                  {inv.observable_type && inv.observable_type !== "domain" && (
                    <span style={{
                      fontSize: 9, fontWeight: 700,
                      padding: "1px 5px",
                      background: "rgba(129,140,248,0.12)",
                      color: "#818cf8",
                      border: "1px solid rgba(129,140,248,0.25)",
                      borderRadius: 3,
                      fontFamily: "var(--font-mono)",
                      textTransform: "uppercase" as const,
                    }}>
                      {inv.observable_type}
                    </span>
                  )}
                </div>
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

      {/* Pagination controls */}
      {total > 0 && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          marginTop: 16, padding: "12px 0",
          borderTop: "1px solid var(--border)",
        }}>
          {/* Left: showing info + page size selector */}
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {showingFrom}–{showingTo} of {total}
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 10, color: "var(--text-dim)" }}>Per page:</span>
              <select
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
                style={{
                  padding: "4px 8px",
                  background: "var(--bg-card)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  color: "var(--text)",
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  cursor: "pointer",
                  outline: "none",
                }}
              >
                {PAGE_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Right: page navigation */}
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <button
              onClick={() => setPage(0)}
              disabled={page === 0}
              style={{
                padding: "6px 10px",
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: page === 0 ? "var(--text-dim)" : "var(--text)",
                fontSize: 11, fontWeight: 600, cursor: page === 0 ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                opacity: page === 0 ? 0.4 : 1,
              }}
            >
              &laquo;
            </button>
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              style={{
                padding: "6px 12px",
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: page === 0 ? "var(--text-dim)" : "var(--text)",
                fontSize: 11, fontWeight: 600, cursor: page === 0 ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                opacity: page === 0 ? 0.4 : 1,
              }}
            >
              Prev
            </button>

            {/* Page numbers */}
            {(() => {
              const pages: number[] = [];
              const maxVisible = 5;
              let start = Math.max(0, page - Math.floor(maxVisible / 2));
              let end = Math.min(totalPages, start + maxVisible);
              if (end - start < maxVisible) {
                start = Math.max(0, end - maxVisible);
              }
              for (let i = start; i < end; i++) pages.push(i);
              return pages.map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  style={{
                    padding: "6px 10px",
                    background: p === page ? "var(--accent)" : "var(--bg-card)",
                    border: `1px solid ${p === page ? "var(--accent)" : "var(--border)"}`,
                    borderRadius: "var(--radius-sm)",
                    color: p === page ? "#fff" : "var(--text-muted)",
                    fontSize: 11, fontWeight: 600, cursor: "pointer",
                    fontFamily: "var(--font-mono)",
                    minWidth: 32,
                  }}
                >
                  {p + 1}
                </button>
              ));
            })()}

            <button
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
              style={{
                padding: "6px 12px",
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: page >= totalPages - 1 ? "var(--text-dim)" : "var(--text)",
                fontSize: 11, fontWeight: 600, cursor: page >= totalPages - 1 ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                opacity: page >= totalPages - 1 ? 0.4 : 1,
              }}
            >
              Next
            </button>
            <button
              onClick={() => setPage(totalPages - 1)}
              disabled={page >= totalPages - 1}
              style={{
                padding: "6px 10px",
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: page >= totalPages - 1 ? "var(--text-dim)" : "var(--text)",
                fontSize: 11, fontWeight: 600, cursor: page >= totalPages - 1 ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                opacity: page >= totalPages - 1 ? 0.4 : 1,
              }}
            >
              &raquo;
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
