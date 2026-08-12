"use client";

/**
 * Exclusion list — indicators answered from policy instead of from collectors.
 *
 * Everything listed here is reported benign in alert investigations without a
 * collector, a VirusTotal call or an AI token being spent on it. The page is
 * built around that being a consequential thing to do: a reason is required,
 * every row shows what it has actually skipped (`hit_count`), and an entry can
 * be given an expiry so a temporary exclusion lapses on its own.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "@/lib/api";
import type { Exclusion } from "@/lib/types";
import Spinner from "@/components/shared/Spinner";
import { Button, MetaDot, Page, PageHeader } from "@/components/ui/Primitives";

/* ─── Style constants ─── */

const TYPE_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  domain: { color: "#818cf8", bg: "rgba(129,140,248,0.08)", border: "rgba(129,140,248,0.2)" },
  ip: { color: "#38bdf8", bg: "rgba(56,189,248,0.08)", border: "rgba(56,189,248,0.2)" },
  url: { color: "#c084fc", bg: "rgba(192,132,252,0.08)", border: "rgba(192,132,252,0.2)" },
  hash: { color: "#fbbf24", bg: "rgba(251,191,36,0.08)", border: "rgba(251,191,36,0.2)" },
};

const TYPE_OPTIONS = [
  { value: "domain", label: "Domain", placeholder: "expertware.net" },
  { value: "ip", label: "IP / CIDR", placeholder: "10.0.0.0/8" },
  { value: "url", label: "URL", placeholder: "https://intranet.expertware.net/login" },
  { value: "hash", label: "Hash", placeholder: "MD5, SHA-1 or SHA-256 digest" },
];

const INPUT_STYLE: React.CSSProperties = {
  padding: "10px 16px",
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text)",
  fontSize: 13,
  fontFamily: "var(--font-mono)",
  outline: "none",
};

/* ─── Helpers ─── */

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function scopeLabel(entry: Exclusion): string | null {
  if (entry.indicator_type === "domain") {
    return entry.match_subdomains ? "+ subdomains" : "exact host";
  }
  if (entry.indicator_type === "ip" && entry.normalized_value.includes("/")) {
    return "range";
  }
  return null;
}

/* ─── Main page ─── */

export default function ExclusionsPage() {
  const [entries, setEntries] = useState<Exclusion[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [typeFilter, setTypeFilter] = useState<string | undefined>(undefined);
  const [search, setSearch] = useState("");
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Add form
  const [showAddForm, setShowAddForm] = useState(false);
  const [newType, setNewType] = useState("domain");
  const [newValue, setNewValue] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newSubdomains, setNewSubdomains] = useState(true);
  const [newExpiry, setNewExpiry] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const pageSize = 25;

  const fetchData = useCallback(() => {
    setLoading(true);
    api
      .listExclusions({
        limit: pageSize,
        offset: page * pageSize,
        indicator_type: typeFilter,
        search: search || undefined,
      })
      .then((data) => {
        setEntries(data.items);
        setTotal(data.total);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, typeFilter, search]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSearchChange = (val: string) => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setSearch(val);
      setPage(0);
    }, 300);
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim() || newReason.trim().length < 3) return;
    setAdding(true);
    setAddError(null);
    setNotice(null);
    try {
      const created = await api.createExclusion({
        indicator_type: newType,
        value: newValue.trim(),
        reason: newReason.trim(),
        match_subdomains: newSubdomains,
        expires_at: newExpiry ? new Date(newExpiry).toISOString() : null,
      });
      setNotice(
        created.already_listed
          ? `${created.value} was already listed — its reason and scope were updated.`
          : `${created.value} will now be treated as benign without collection.`,
      );
      setNewValue("");
      setNewReason("");
      setNewExpiry("");
      setShowAddForm(false);
      setPage(0);
      fetchData();
    } catch (err: any) {
      setAddError(err?.message || "Failed to add exclusion");
    } finally {
      setAdding(false);
    }
  };

  const handleToggleActive = async (entry: Exclusion) => {
    await api.updateExclusion(entry.id, { active: !entry.active });
    fetchData();
  };

  const handleDelete = async (id: string) => {
    await api.deleteExclusion(id);
    setDeleteConfirmId(null);
    fetchData();
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const totalSkipped = entries.reduce((sum, entry) => sum + (entry.hit_count || 0), 0);
  const filters: Array<{ key: string | undefined; label: string }> = [
    { key: undefined, label: "All" },
    ...TYPE_OPTIONS.map((opt) => ({ key: opt.value, label: opt.label })),
  ];
  const activeType = TYPE_OPTIONS.find((opt) => opt.value === newType) ?? TYPE_OPTIONS[0];

  return (
    <Page>
      <PageHeader
        title="Exclusion list"
        subtitle="Indicators treated as benign without analysis. Anything here is never looked up."
        meta={
          <>
            <span>
              {total} entr{total !== 1 ? "ies" : "y"}
            </span>
            {totalSkipped > 0 && (
              <>
                <MetaDot />
                <span>
                  {totalSkipped} lookup{totalSkipped !== 1 ? "s" : ""} saved on this page
                </span>
              </>
            )}
          </>
        }
        actions={
          <Button variant={showAddForm ? "secondary" : "primary"} onClick={() => setShowAddForm(!showAddForm)}>
            {showAddForm ? "Cancel" : "Add exclusion"}
          </Button>
        }
      />

      {/* Add form */}
      {showAddForm && (
        <form
          onSubmit={handleAdd}
          className="animate-slide-down ds-card"
        >
          <div
            style={{
              fontSize: "var(--font-micro)",
              fontWeight: 700,
              color: "var(--text-muted)",
              marginBottom: "var(--space-3)",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            Exclude an indicator
          </div>

          <div style={{ display: "flex", gap: "var(--space-3)", marginBottom: "var(--space-3)", flexWrap: "wrap" }}>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value)}
              style={{ ...INPUT_STYLE, width: 150, cursor: "pointer" }}
            >
              {TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <input
              type="text"
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder={activeType.placeholder}
              autoFocus
              style={{ ...INPUT_STYLE, flex: 1 }}
              onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            />
            <button
              type="submit"
              disabled={adding || !newValue.trim() || newReason.trim().length < 3}
              style={{
                padding: "10px 24px",
                background: "linear-gradient(135deg, #3b82f6, #2563eb)",
                border: "none",
                borderRadius: "var(--radius-sm)",
                color: "#fff",
                fontSize: 11,
                fontWeight: 700,
                cursor: adding ? "default" : "pointer",
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.06em",
                opacity: adding || !newValue.trim() || newReason.trim().length < 3 ? 0.5 : 1,
                whiteSpace: "nowrap",
              }}
            >
              {adding ? "ADDING..." : "ADD EXCLUSION"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <textarea
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              placeholder="Reason (required) — why is this safe to skip? e.g. corporate domain, office egress range"
              rows={2}
              style={{ ...INPUT_STYLE, flex: 1, fontSize: 12, resize: "vertical" }}
              onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            />
            <div style={{ width: 200, flexShrink: 0 }}>
              <div
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  color: "var(--text-muted)",
                  marginBottom: 6,
                  letterSpacing: "0.08em",
                }}
              >
                EXPIRES (OPTIONAL)
              </div>
              <input
                type="date"
                value={newExpiry}
                onChange={(e) => setNewExpiry(e.target.value)}
                style={{ ...INPUT_STYLE, width: "100%", fontSize: 12, cursor: "pointer" }}
              />
              {newType === "domain" && (
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginTop: 10,
                    fontSize: 11,
                    color: "var(--text-dim)",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={newSubdomains}
                    onChange={(e) => setNewSubdomains(e.target.checked)}
                  />
                  Include subdomains
                </label>
              )}
            </div>
          </div>

          {addError && (
            <div
              style={{
                marginTop: 12,
                padding: "8px 12px",
                background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.2)",
                borderRadius: "var(--radius-sm)",
                color: "#ef4444",
                fontSize: 11,
                fontFamily: "var(--font-mono)",
              }}
            >
              {addError}
            </div>
          )}
        </form>
      )}

      {notice && (
        <div
          style={{
            marginBottom: 16,
            padding: "10px 14px",
            background: "rgba(16,185,129,0.08)",
            border: "1px solid rgba(16,185,129,0.2)",
            borderRadius: "var(--radius-sm)",
            color: "#10b981",
            fontSize: 11,
            fontFamily: "var(--font-mono)",
          }}
        >
          {notice}
        </div>
      )}

      {/* Filters + search */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, alignItems: "center", flexWrap: "wrap" }}>
        {filters.map((filter) => (
          <button
            key={filter.label}
            onClick={() => {
              setTypeFilter(filter.key);
              setPage(0);
            }}
            style={{
              padding: "6px 14px",
              background: typeFilter === filter.key ? "var(--bg-hover)" : "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: typeFilter === filter.key ? "var(--text)" : "var(--text-dim)",
              fontSize: 10,
              fontWeight: 700,
              cursor: "pointer",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.06em",
            }}
          >
            {filter.label.toUpperCase()}
          </button>
        ))}
        <input
          type="text"
          placeholder="Search value or reason…"
          onChange={(e) => handleSearchChange(e.target.value)}
          style={{ ...INPUT_STYLE, marginLeft: "auto", width: 260, padding: "6px 12px", fontSize: 12 }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        />
      </div>

      {/* List */}
      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
          <Spinner />
        </div>
      ) : entries.length === 0 ? (
        <div
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--text-dim)",
            fontSize: 12,
            border: "1px dashed var(--border)",
            borderRadius: "var(--radius)",
          }}
        >
          Nothing excluded yet. Add the domains, ranges and hashes your own estate
          produces — every alert that mentions them then costs no collector time.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {entries.map((entry) => {
            const typeStyle = TYPE_STYLES[entry.indicator_type] ?? TYPE_STYLES.domain;
            const inactive = !entry.active || entry.expired;
            const scope = scopeLabel(entry);
            return (
              <div
                key={entry.id}
                style={{
                  padding: "var(--space-3) 0",
                  borderBottom: "1px solid var(--panel-divider-soft)",
                  opacity: inactive ? 0.55 : 1,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                  <span
                    style={{
                      padding: "3px 8px",
                      background: typeStyle.bg,
                      border: `1px solid ${typeStyle.border}`,
                      borderRadius: 4,
                      color: typeStyle.color,
                      fontSize: 9,
                      fontWeight: 700,
                      fontFamily: "var(--font-mono)",
                      letterSpacing: "0.08em",
                    }}
                  >
                    {entry.indicator_type.toUpperCase()}
                  </span>
                  <span
                    style={{
                      fontSize: 13,
                      fontFamily: "var(--font-mono)",
                      color: "var(--text)",
                      fontWeight: 600,
                      wordBreak: "break-all",
                    }}
                  >
                    {entry.value}
                  </span>
                  {scope && (
                    <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      {scope}
                    </span>
                  )}
                  {entry.expired && (
                    <span style={{ fontSize: 10, color: "#f59e0b", fontFamily: "var(--font-mono)" }}>
                      EXPIRED
                    </span>
                  )}
                  {!entry.active && !entry.expired && (
                    <span style={{ fontSize: 10, color: "#64748b", fontFamily: "var(--font-mono)" }}>
                      DISABLED
                    </span>
                  )}

                  <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
                    <span
                      title="Indicator lookups this entry has skipped"
                      style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}
                    >
                      {entry.hit_count} skipped
                    </span>
                    <button
                      onClick={() => handleToggleActive(entry)}
                      style={{
                        padding: "5px 10px",
                        background: "transparent",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius-sm)",
                        color: "var(--text-dim)",
                        fontSize: 10,
                        fontWeight: 700,
                        cursor: "pointer",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {entry.active ? "DISABLE" : "ENABLE"}
                    </button>
                    {deleteConfirmId === entry.id ? (
                      <>
                        <button
                          onClick={() => handleDelete(entry.id)}
                          style={{
                            padding: "5px 10px",
                            background: "rgba(239,68,68,0.12)",
                            border: "1px solid rgba(239,68,68,0.3)",
                            borderRadius: "var(--radius-sm)",
                            color: "#ef4444",
                            fontSize: 10,
                            fontWeight: 700,
                            cursor: "pointer",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          CONFIRM
                        </button>
                        <button
                          onClick={() => setDeleteConfirmId(null)}
                          style={{
                            padding: "5px 10px",
                            background: "transparent",
                            border: "1px solid var(--border)",
                            borderRadius: "var(--radius-sm)",
                            color: "var(--text-dim)",
                            fontSize: 10,
                            fontWeight: 700,
                            cursor: "pointer",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          KEEP
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirmId(entry.id)}
                        style={{
                          padding: "5px 10px",
                          background: "transparent",
                          border: "1px solid var(--border)",
                          borderRadius: "var(--radius-sm)",
                          color: "var(--text-dim)",
                          fontSize: 10,
                          fontWeight: 700,
                          cursor: "pointer",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        REMOVE
                      </button>
                    )}
                  </div>
                </div>

                <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-dim)", lineHeight: 1.5 }}>
                  {entry.reason}
                </div>
                <div
                  style={{
                    marginTop: 6,
                    fontSize: 10,
                    color: "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                    display: "flex",
                    gap: 14,
                    flexWrap: "wrap",
                  }}
                >
                  <span>added {formatDate(entry.created_at)}</span>
                  {entry.added_by && <span>by {entry.added_by}</span>}
                  {entry.expires_at && <span>expires {formatDate(entry.expires_at)}</span>}
                  {entry.last_hit_at && <span>last matched {formatDate(entry.last_hit_at)}</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "center", marginTop: 20 }}>
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            style={{
              padding: "6px 14px",
              background: "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text-dim)",
              fontSize: 10,
              fontWeight: 700,
              cursor: page === 0 ? "default" : "pointer",
              opacity: page === 0 ? 0.4 : 1,
              fontFamily: "var(--font-mono)",
            }}
          >
            PREV
          </button>
          <span
            style={{
              padding: "6px 14px",
              fontSize: 10,
              color: "var(--text-dim)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {page + 1} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            style={{
              padding: "6px 14px",
              background: "transparent",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text-dim)",
              fontSize: 10,
              fontWeight: 700,
              cursor: page >= totalPages - 1 ? "default" : "pointer",
              opacity: page >= totalPages - 1 ? 0.4 : 1,
              fontFamily: "var(--font-mono)",
            }}
          >
            NEXT
          </button>
        </div>
      )}
    </Page>
  );
}
