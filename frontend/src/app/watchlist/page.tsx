"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";
import Spinner from "@/components/shared/Spinner";

/* ─── Style constants ─── */

const STATUS_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  active: { color: "#10b981", bg: "rgba(16,185,129,0.08)", border: "rgba(16,185,129,0.2)" },
  paused: { color: "#f59e0b", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.2)" },
  removed: { color: "#64748b", bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.2)" },
};

const CLASSIFICATION_COLORS: Record<string, { color: string; bg: string }> = {
  malicious: { color: "#ef4444", bg: "rgba(239,68,68,0.1)" },
  suspicious: { color: "#f59e0b", bg: "rgba(245,158,11,0.1)" },
  clean: { color: "#10b981", bg: "rgba(16,185,129,0.1)" },
  inconclusive: { color: "#64748b", bg: "rgba(100,116,139,0.1)" },
};

const SCHEDULE_OPTIONS = [
  { value: "", label: "No schedule" },
  { value: "weekly", label: "Weekly" },
  { value: "biweekly", label: "Biweekly" },
  { value: "monthly", label: "Monthly" },
];

const SCHEDULE_BADGE_STYLE = {
  color: "#818cf8",
  bg: "rgba(129,140,248,0.08)",
  border: "rgba(129,140,248,0.2)",
};

/* ─── Helpers ─── */

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

function timeUntil(dateStr: string | null): string {
  if (!dateStr) return "—";
  const diff = new Date(dateStr).getTime() - Date.now();
  if (diff <= 0) return "due now";
  const hours = Math.floor(diff / 3600000);
  if (hours < 24) return `in ${hours}h`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `in ${days}d`;
  const months = Math.floor(days / 30);
  return `in ${months}mo`;
}

/* ─── Main Page ─── */

export default function WatchlistPage() {
  const router = useRouter();
  const [entries, setEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const [search, setSearch] = useState("");
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Add form
  const [showAddForm, setShowAddForm] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newNotes, setNewNotes] = useState("");
  const [newSchedule, setNewSchedule] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // Investigate state
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);

  // Delete confirm
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Schedule dropdown
  const [scheduleDropdownId, setScheduleDropdownId] = useState<string | null>(null);

  const pageSize = 25;

  const fetchData = useCallback(() => {
    setLoading(true);
    api.listWatchlist({
      limit: pageSize,
      offset: page * pageSize,
      status: statusFilter,
      search: search || undefined,
    })
      .then((data) => {
        setEntries(data.items);
        setTotal(data.total);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, statusFilter, search]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Close schedule dropdown on outside click
  useEffect(() => {
    if (!scheduleDropdownId) return;
    const handler = () => setScheduleDropdownId(null);
    const timer = setTimeout(() => document.addEventListener("click", handler), 0);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("click", handler);
    };
  }, [scheduleDropdownId]);

  const handleSearchChange = (val: string) => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setSearch(val);
      setPage(0);
    }, 300);
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    setAdding(true);
    setAddError(null);
    try {
      await api.createWatchlistEntry({
        domain: newDomain.trim(),
        notes: newNotes.trim() || undefined,
        schedule_interval: newSchedule || undefined,
      });
      setNewDomain("");
      setNewNotes("");
      setNewSchedule("");
      setShowAddForm(false);
      setPage(0);
      fetchData();
    } catch (err: any) {
      setAddError(err?.message || "Failed to add domain");
    } finally {
      setAdding(false);
    }
  };

  const handleToggleStatus = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === "active" ? "paused" : "active";
    await api.updateWatchlistEntry(id, { status: newStatus });
    fetchData();
  };

  const handleDelete = async (id: string) => {
    await api.deleteWatchlistEntry(id);
    setDeleteConfirmId(null);
    fetchData();
  };

  const handleInvestigate = async (id: string) => {
    setInvestigatingId(id);
    try {
      const result = await api.investigateWatchlistDomain(id);
      fetchData();
      if (result?.investigation_id) {
        router.push(`/investigations/${result.investigation_id}`);
      }
    } catch {
      // Silently handle — user will see the entry unchanged
    } finally {
      setInvestigatingId(null);
    }
  };

  const handleScheduleChange = async (id: string, interval: string) => {
    setScheduleDropdownId(null);
    await api.updateWatchlistEntry(id, {
      schedule_interval: interval || null,
    });
    fetchData();
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const filters: Array<{ key: string | undefined; label: string }> = [
    { key: undefined, label: "All" },
    { key: "active", label: "Active" },
    { key: "paused", label: "Paused" },
  ];

  return (
    <div style={{ paddingTop: 24, paddingBottom: 80, maxWidth: 1100 }}>
      {/* Header row */}
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 24,
      }}>
        <div>
          <div style={{
            fontSize: 18, fontWeight: 800, color: "var(--text)",
            letterSpacing: "0.04em", fontFamily: "var(--font-mono)",
            marginBottom: 4,
          }}>
            DOMAIN WATCHLIST
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Monitor domains for changes — {total} domain{total !== 1 ? "s" : ""} tracked
          </div>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          style={{
            padding: "10px 20px",
            background: showAddForm ? "var(--bg-card)" : "linear-gradient(135deg, #3b82f6, #2563eb)",
            border: showAddForm ? "1px solid var(--border)" : "none",
            borderRadius: "var(--radius)",
            color: showAddForm ? "var(--text-dim)" : "#fff",
            fontSize: 11, fontWeight: 700, cursor: "pointer",
            fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
          }}
        >
          {showAddForm ? "CANCEL" : "+ ADD DOMAIN"}
        </button>
      </div>

      {/* Add form (collapsible) */}
      {showAddForm && (
        <form onSubmit={handleAdd} style={{
          padding: 20,
          background: "var(--bg-card)", border: "1px solid var(--border)",
          borderRadius: "var(--radius)", marginBottom: 20,
        }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", marginBottom: 12, letterSpacing: "0.08em" }}>
            ADD DOMAIN TO WATCHLIST
          </div>
          <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              autoFocus
              style={{
                flex: 1, padding: "10px 16px",
                background: "var(--bg-input)", border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)", color: "var(--text)",
                fontSize: 13, fontFamily: "var(--font-mono)", outline: "none",
              }}
              onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            />
            <button
              type="submit"
              disabled={adding || !newDomain.trim()}
              style={{
                padding: "10px 24px",
                background: "linear-gradient(135deg, #3b82f6, #2563eb)",
                border: "none", borderRadius: "var(--radius-sm)",
                color: "#fff", fontSize: 11, fontWeight: 700,
                cursor: adding ? "default" : "pointer",
                fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
                opacity: adding || !newDomain.trim() ? 0.5 : 1,
                whiteSpace: "nowrap",
              }}
            >
              {adding ? "ADDING..." : "ADD TO WATCHLIST"}
            </button>
          </div>

          {/* Notes + Schedule row */}
          <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <textarea
              value={newNotes}
              onChange={(e) => setNewNotes(e.target.value)}
              placeholder="Notes (optional) — why are you watching this domain?"
              rows={2}
              style={{
                flex: 1, padding: "10px 16px",
                background: "var(--bg-input)", border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)", color: "var(--text)",
                fontSize: 12, fontFamily: "var(--font-mono)", outline: "none",
                resize: "vertical",
              }}
              onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            />
            <div style={{ width: 180, flexShrink: 0 }}>
              <div style={{
                fontSize: 9, fontWeight: 700, color: "var(--text-muted)",
                marginBottom: 6, letterSpacing: "0.08em",
              }}>
                AUTO RE-CHECK
              </div>
              <select
                value={newSchedule}
                onChange={(e) => setNewSchedule(e.target.value)}
                style={{
                  width: "100%", padding: "10px 12px",
                  background: "var(--bg-input)", border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)", color: "var(--text)",
                  fontSize: 12, fontFamily: "var(--font-mono)", outline: "none",
                  cursor: "pointer",
                }}
              >
                {SCHEDULE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
          </div>

          {addError && (
            <div style={{
              padding: "8px 12px", marginTop: 12, fontSize: 12,
              color: "#ef4444", background: "rgba(239,68,68,0.08)",
              borderRadius: "var(--radius-sm)", border: "1px solid rgba(239,68,68,0.2)",
            }}>
              {addError}
            </div>
          )}
        </form>
      )}

      {/* Toolbar: search + filters */}
      <div style={{
        display: "flex", gap: 12, marginBottom: 20,
        alignItems: "center", flexWrap: "wrap",
      }}>
        <input
          type="text"
          placeholder="Search domains..."
          onChange={(e) => handleSearchChange(e.target.value)}
          style={{
            width: 260, padding: "8px 14px",
            background: "var(--bg-card)", border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)", color: "var(--text)",
            fontSize: 12, fontFamily: "var(--font-mono)", outline: "none",
          }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        />
        <div style={{ display: "flex", gap: 4 }}>
          {filters.map(({ key, label }) => (
            <button
              key={label}
              onClick={() => { setStatusFilter(key); setPage(0); }}
              style={{
                padding: "6px 14px",
                background: statusFilter === key ? "var(--accent)" : "var(--bg-card)",
                border: `1px solid ${statusFilter === key ? "var(--accent)" : "var(--border)"}`,
                borderRadius: "var(--radius-sm)",
                color: statusFilter === key ? "#fff" : "var(--text-dim)",
                fontSize: 10, fontWeight: 600, cursor: "pointer",
                fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
                textTransform: "uppercase",
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <span style={{
          fontSize: 10, color: "var(--text-muted)",
          fontFamily: "var(--font-mono)", marginLeft: "auto",
        }}>
          {total} result{total !== 1 ? "s" : ""}
        </span>
      </div>

      {/* List */}
      {loading ? (
        <Spinner message="Loading watchlist..." />
      ) : entries.length === 0 ? (
        <div style={{
          textAlign: "center", padding: "80px 40px",
          color: "var(--text-dim)",
          background: "var(--bg-card)", border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
        }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>
            {'{ }'}
          </div>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
            No domains in watchlist
          </div>
          <div style={{ fontSize: 12, marginBottom: 20 }}>
            Add domains to monitor them for changes over time.
          </div>
          {!showAddForm && (
            <button
              onClick={() => setShowAddForm(true)}
              style={{
                padding: "10px 24px",
                background: "linear-gradient(135deg, #3b82f6, #2563eb)",
                border: "none", borderRadius: "var(--radius)",
                color: "#fff", fontSize: 11, fontWeight: 700, cursor: "pointer",
                fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
              }}
            >
              + ADD FIRST DOMAIN
            </button>
          )}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {entries.map((entry) => {
            const sc = STATUS_COLORS[entry.status] || STATUS_COLORS.active;
            const latest = entry.latest_investigation;
            const cc = latest?.classification
              ? CLASSIFICATION_COLORS[latest.classification] || CLASSIFICATION_COLORS.inconclusive
              : null;
            const isInvestigating = investigatingId === entry.id;

            return (
              <div
                key={entry.id}
                style={{
                  padding: "16px 20px",
                  background: "var(--bg-card)",
                  border: `1px solid ${deleteConfirmId === entry.id ? "rgba(239,68,68,0.4)" : "var(--border)"}`,
                  borderRadius: "var(--radius)",
                  transition: "border-color 0.2s",
                }}
              >
                {/* Top row: domain + status + actions */}
                <div style={{
                  display: "flex", alignItems: "center", gap: 12,
                  marginBottom: latest || entry.schedule_interval ? 10 : 0,
                }}>
                  {/* Domain info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{
                        fontSize: 14, fontWeight: 700, color: "var(--text)",
                        fontFamily: "var(--font-mono)",
                      }}>
                        {entry.domain}
                      </span>
                      <span style={{
                        fontSize: 8, padding: "2px 6px",
                        background: sc.bg, color: sc.color,
                        border: `1px solid ${sc.border}`,
                        borderRadius: "var(--radius-sm)",
                        fontWeight: 700, letterSpacing: "0.08em",
                        textTransform: "uppercase",
                        fontFamily: "var(--font-mono)",
                      }}>
                        {entry.status}
                      </span>
                      {/* Schedule badge — clickable to change */}
                      <div style={{ position: "relative" }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setScheduleDropdownId(
                              scheduleDropdownId === entry.id ? null : entry.id
                            );
                          }}
                          style={{
                            fontSize: 8, padding: "2px 6px",
                            background: entry.schedule_interval
                              ? SCHEDULE_BADGE_STYLE.bg : "rgba(100,116,139,0.05)",
                            color: entry.schedule_interval
                              ? SCHEDULE_BADGE_STYLE.color : "var(--text-muted)",
                            border: `1px solid ${entry.schedule_interval
                              ? SCHEDULE_BADGE_STYLE.border : "var(--border)"}`,
                            borderRadius: "var(--radius-sm)",
                            fontWeight: 700, letterSpacing: "0.08em",
                            textTransform: "uppercase",
                            fontFamily: "var(--font-mono)",
                            cursor: "pointer",
                          }}
                        >
                          {entry.schedule_interval || "NO SCHEDULE"}
                        </button>
                        {/* Schedule dropdown */}
                        {scheduleDropdownId === entry.id && (
                          <div
                            onClick={(e) => e.stopPropagation()}
                            style={{
                              position: "absolute", top: "100%", left: 0,
                              marginTop: 4, zIndex: 10,
                              background: "var(--bg-card)",
                              border: "1px solid var(--border)",
                              borderRadius: "var(--radius-sm)",
                              boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
                              minWidth: 130, overflow: "hidden",
                            }}
                          >
                            {SCHEDULE_OPTIONS.map((opt) => {
                              const isActive = entry.schedule_interval === opt.value
                                || (!entry.schedule_interval && !opt.value);
                              return (
                                <button
                                  key={opt.value}
                                  onClick={() => handleScheduleChange(entry.id, opt.value)}
                                  style={{
                                    display: "block", width: "100%",
                                    padding: "8px 12px", textAlign: "left",
                                    background: isActive ? "var(--bg-input)" : "transparent",
                                    border: "none", color: "var(--text)",
                                    fontSize: 11, fontFamily: "var(--font-mono)",
                                    cursor: "pointer",
                                  }}
                                  onMouseEnter={(e) => {
                                    e.currentTarget.style.background = "var(--bg-input)";
                                  }}
                                  onMouseLeave={(e) => {
                                    if (!isActive) e.currentTarget.style.background = "transparent";
                                  }}
                                >
                                  {opt.label}
                                </button>
                              );
                            })}
                          </div>
                        )}
                      </div>
                      {entry.alert_count > 0 && (
                        <span style={{
                          fontSize: 9, padding: "2px 6px",
                          background: "rgba(239,68,68,0.1)", color: "#ef4444",
                          border: "1px solid rgba(239,68,68,0.2)",
                          borderRadius: "var(--radius-sm)",
                          fontWeight: 700, fontFamily: "var(--font-mono)",
                        }}>
                          {entry.alert_count} ALERT{entry.alert_count > 1 ? "S" : ""}
                        </span>
                      )}
                    </div>
                    {entry.notes && (
                      <div style={{
                        fontSize: 11, color: "var(--text-dim)", marginTop: 4,
                        fontFamily: "var(--font-mono)",
                      }}>
                        {entry.notes}
                      </div>
                    )}
                  </div>

                  {/* Meta: added + checked + next */}
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      added {timeAgo(entry.created_at)}
                    </div>
                    {entry.last_checked_at && (
                      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        checked {timeAgo(entry.last_checked_at)}
                      </div>
                    )}
                    {entry.schedule_interval && entry.next_check_at && (
                      <div style={{ fontSize: 10, color: "#818cf8", fontFamily: "var(--font-mono)" }}>
                        next {timeUntil(entry.next_check_at)}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                    {entry.status === "active" && (
                      <button
                        onClick={() => handleInvestigate(entry.id)}
                        disabled={isInvestigating}
                        style={{
                          padding: "6px 14px",
                          background: isInvestigating ? "var(--bg-input)" : "linear-gradient(135deg, #3b82f6, #2563eb)",
                          border: "none", borderRadius: "var(--radius-sm)",
                          color: "#fff", fontSize: 9, fontWeight: 700, cursor: isInvestigating ? "default" : "pointer",
                          fontFamily: "var(--font-mono)", letterSpacing: "0.06em",
                          opacity: isInvestigating ? 0.6 : 1,
                        }}
                      >
                        {isInvestigating ? "SCANNING..." : "INVESTIGATE"}
                      </button>
                    )}
                    <ActionButton
                      label={entry.status === "active" ? "Pause" : "Resume"}
                      onClick={() => handleToggleStatus(entry.id, entry.status)}
                    />
                    {deleteConfirmId === entry.id ? (
                      <div style={{ display: "flex", gap: 4 }}>
                        <ActionButton
                          label="Confirm"
                          onClick={() => handleDelete(entry.id)}
                          danger
                        />
                        <ActionButton
                          label="Cancel"
                          onClick={() => setDeleteConfirmId(null)}
                        />
                      </div>
                    ) : (
                      <ActionButton
                        label="Delete"
                        onClick={() => setDeleteConfirmId(entry.id)}
                        danger
                      />
                    )}
                  </div>
                </div>

                {/* Latest investigation row */}
                {latest && (
                  <div style={{
                    display: "flex", alignItems: "center", gap: 12,
                    padding: "8px 12px",
                    background: "var(--bg-input)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 11, fontFamily: "var(--font-mono)",
                  }}>
                    <span style={{ color: "var(--text-muted)", fontSize: 9, fontWeight: 600, letterSpacing: "0.06em" }}>
                      LATEST
                    </span>

                    {cc && latest.classification && (
                      <span style={{
                        fontSize: 9, padding: "2px 8px",
                        background: cc.bg, color: cc.color,
                        borderRadius: "var(--radius-sm)",
                        fontWeight: 700, letterSpacing: "0.06em",
                        textTransform: "uppercase",
                      }}>
                        {latest.classification}
                      </span>
                    )}

                    {latest.risk_score != null && (
                      <span style={{
                        color: latest.risk_score >= 70 ? "#ef4444"
                          : latest.risk_score >= 40 ? "#f59e0b" : "#10b981",
                        fontWeight: 700, fontSize: 12,
                      }}>
                        {latest.risk_score}
                        <span style={{ fontSize: 9, fontWeight: 400, color: "var(--text-muted)", marginLeft: 2 }}>
                          /100
                        </span>
                      </span>
                    )}

                    <span style={{
                      color: latest.state === "completed" ? "var(--text-dim)"
                        : latest.state === "failed" ? "#ef4444" : "#3b82f6",
                      fontSize: 10,
                    }}>
                      {latest.state}
                    </span>

                    <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                      {timeAgo(latest.created_at)}
                    </span>

                    {entry.investigation_count > 1 && (
                      <span style={{ color: "var(--text-muted)", fontSize: 9 }}>
                        ({entry.investigation_count} total)
                      </span>
                    )}

                    {latest.state === "completed" && (
                      <button
                        onClick={() => router.push(`/investigations/${latest.id}`)}
                        style={{
                          marginLeft: "auto",
                          padding: "3px 10px",
                          background: "transparent",
                          border: "1px solid var(--border)",
                          borderRadius: "var(--radius-sm)",
                          color: "var(--accent)", fontSize: 9, fontWeight: 600,
                          cursor: "pointer", fontFamily: "var(--font-mono)",
                          letterSpacing: "0.04em",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = "var(--accent)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = "var(--border)";
                        }}
                      >
                        VIEW REPORT
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {total > pageSize && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          gap: 4, marginTop: 24,
        }}>
          <PaginationButton
            label="Prev"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
          />
          {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
            let pageNum: number;
            if (totalPages <= 7) {
              pageNum = i;
            } else if (page < 3) {
              pageNum = i;
            } else if (page > totalPages - 4) {
              pageNum = totalPages - 7 + i;
            } else {
              pageNum = page - 3 + i;
            }
            return (
              <button
                key={pageNum}
                onClick={() => setPage(pageNum)}
                style={{
                  width: 32, height: 32,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: page === pageNum ? "var(--accent)" : "var(--bg-card)",
                  border: `1px solid ${page === pageNum ? "var(--accent)" : "var(--border)"}`,
                  borderRadius: "var(--radius-sm)",
                  color: page === pageNum ? "#fff" : "var(--text-dim)",
                  fontSize: 11, fontWeight: 600, cursor: "pointer",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {pageNum + 1}
              </button>
            );
          })}
          <PaginationButton
            label="Next"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
          />
        </div>
      )}
    </div>
  );
}

/* ─── Subcomponents ─── */

function ActionButton({
  label, onClick, danger,
}: { label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 10px",
        background: "transparent",
        border: `1px solid ${danger ? "rgba(239,68,68,0.3)" : "var(--border)"}`,
        borderRadius: "var(--radius-sm)",
        color: danger ? "#ef4444" : "var(--text-dim)",
        fontSize: 9, fontWeight: 600, cursor: "pointer",
        fontFamily: "var(--font-mono)", letterSpacing: "0.04em",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = danger ? "#ef4444" : "var(--accent)";
        e.currentTarget.style.color = danger ? "#ef4444" : "var(--accent)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = danger ? "rgba(239,68,68,0.3)" : "var(--border)";
        e.currentTarget.style.color = danger ? "#ef4444" : "var(--text-dim)";
      }}
    >
      {label}
    </button>
  );
}

function PaginationButton({
  label, onClick, disabled,
}: { label: string; onClick: () => void; disabled: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: "6px 12px",
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        color: disabled ? "var(--text-dim)" : "var(--text)",
        fontSize: 11, fontWeight: 600,
        cursor: disabled ? "default" : "pointer",
        fontFamily: "var(--font-mono)",
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {label}
    </button>
  );
}
