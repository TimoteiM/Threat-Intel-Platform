"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { deleteInvestigation, listInvestigations } from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import Spinner from "@/components/shared/Spinner";
import ConsoleModule from "@/components/ui/ConsoleModule";
import { MetaDot, PageHeader } from "@/components/ui/Primitives";
import StatusPill from "@/components/ui/StatusPill";
import { useSettingsPreferences } from "@/components/settings/SettingsPreferencesProvider";

const PAGE_SIZE_OPTIONS = [10, 25, 50];
const FILTERS = ["all", "created", "gathering", "evaluating", "concluded", "failed"] as const;
const CLASSIFICATION_FILTERS = ["all", "malicious", "suspicious", "benign", "inconclusive"] as const;

export default function InvestigationsListPage() {
  const router = useRouter();
  const { settings } = useSettingsPreferences();
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");
  const [classificationFilter, setClassificationFilter] = useState<string>("all");
  const [hideDuplicates, setHideDuplicates] = useState(false);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  const loadInvestigations = useCallback(() => {
    setLoading(true);
    const params: any = { limit: pageSize, offset: page * pageSize };
    if (filter !== "all") params.state = filter;
    if (classificationFilter !== "all") params.classification = classificationFilter;
    if (debouncedSearch) params.search = debouncedSearch;
    if (hideDuplicates) params.dedupe = true;

    listInvestigations(params)
      .then((data) => {
        setInvestigations(data.items);
        setTotal(data.total);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filter, classificationFilter, hideDuplicates, debouncedSearch, page, pageSize]);

  useEffect(() => {
    loadInvestigations();
  }, [loadInvestigations]);

  const handleDelete = useCallback(async (inv: any) => {
    const label = inv?.domain || "this investigation";
    if (!window.confirm(`Delete ${label}? This removes the investigation, evidence, reports, and related artifacts.`)) {
      return;
    }
    setDeletingId(inv.id);
    try {
      await deleteInvestigation(inv.id);
      const nextCount = Math.max(0, total - 1);
      const nextPage = page > 0 && page * pageSize >= nextCount ? page - 1 : page;
      if (nextPage !== page) {
        setPage(nextPage);
      } else {
        loadInvestigations();
      }
    } catch (error: any) {
      alert(`Failed to delete investigation: ${error?.message || error}`);
    } finally {
      setDeletingId(null);
    }
  }, [loadInvestigations, page, pageSize, total]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const showingFrom = total === 0 ? 0 : page * pageSize + 1;
  const showingTo = Math.min((page + 1) * pageSize, total);
  const filterLabel = formatFilterLabel(filter);
  const classificationLabel = formatFilterLabel(classificationFilter);
  const filteredHint = buildFilteredHint({
    search: debouncedSearch,
    stateLabel: filterLabel,
    classificationLabel,
    hideDuplicates,
  });

  return (
    <div
      style={{ paddingTop: 12, paddingBottom: 40 }}
      data-density={settings.listDensity}
    >
      {/* The filter state used to be reported five times over: in the hero
          copy, in four badges, in four stat cards, and in a six-field grid —
          all of it restating what the filter controls below already show. */}
      <PageHeader
        title="Investigations"
        meta={
          <>
            <span>
              {total === 0 ? "No results" : `${showingFrom}–${showingTo} of ${total}`}
            </span>
            {totalPages > 1 && (
              <>
                <MetaDot />
                <span>
                  Page {page + 1} of {totalPages}
                </span>
              </>
            )}
            {debouncedSearch && (
              <>
                <MetaDot />
                <span>Search: “{debouncedSearch}”</span>
              </>
            )}
          </>
        }
        actions={
          <button onClick={() => router.push("/")} style={buttonStyle("primary")}>
            New investigation
          </button>
        }
      />

      <ConsoleModule variant="glass">
        <div className="controls-grid">
          <div className="search-panel">
            <label className="console-label" htmlFor="investigation-search">
              Search by domain
            </label>
            <input
              id="investigation-search"
              type="text"
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Search by domain..."
              style={searchInputStyle()}
            />
          </div>
        </div>

        <div style={{ height: 14 }} />

        <div className="filter-row" aria-label="Investigation filters">
          {FILTERS.map((state) => {
            const active = filter === state;
            return (
              <button
                key={state}
                onClick={() => {
                  setFilter(state);
                  setPage(0);
                }}
                style={filterButtonStyle(active, getFilterTone(state))}
              >
                {formatFilterLabel(state)}
              </button>
            );
          })}

          <div className="page-size-wrap">
            <div className="select-wrap">
              <span className="console-label" style={{ marginBottom: 0 }}>
                Classification
              </span>
              <select
                value={classificationFilter}
                onChange={(e) => {
                  setClassificationFilter(e.target.value);
                  setPage(0);
                }}
                style={selectStyle()}
              >
                {CLASSIFICATION_FILTERS.map((option) => (
                  <option key={option} value={option}>
                    {formatFilterLabel(option)}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              onClick={() => {
                setHideDuplicates((prev) => !prev);
                setPage(0);
              }}
              style={filterButtonStyle(hideDuplicates, "neutral")}
            >
              {hideDuplicates ? "Newest only" : "Hide duplicates"}
            </button>

            <span className="console-label" style={{ marginBottom: 0 }}>
              Per page
            </span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(0);
              }}
              style={selectStyle()}
            >
              {PAGE_SIZE_OPTIONS.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </div>
        </div>
      </ConsoleModule>

      <div style={{ height: 18 }} />

      {loading ? (
        <Spinner message="Loading investigations..." />
      ) : investigations.length === 0 ? (
        <ConsoleModule
          title="No investigations found"
          description="Try a broader search, clear the current filter, or adjust the page size to surface more results."
          variant="dense"
        >
          <div className="empty-state">
            <div className="empty-state__badge">
              <StatusPill tone="neutral" mono>No matches</StatusPill>
            </div>
            <div className="empty-state__hint">
              The catalog has nothing to show for the current filter combination.
            </div>
          </div>
        </ConsoleModule>
      ) : (
        <ConsoleModule
          title="Investigation catalog"
          description="Click any row to open the case. The desktop view stays dense for scanability, while the mobile view shifts to stacked cards."
          variant="solid"
          actions={
            <StatusPill tone="info" mono size="sm">
              {investigations.length} visible
            </StatusPill>
          }
        >
          <div className="catalog-desktop">
            <div className="catalog-header">
              <div>Domain</div>
              <div>Classification</div>
              <div>Risk</div>
              <div>State</div>
              <div>Date</div>
              <div>Actions</div>
            </div>

            <div className="catalog-list">
              {investigations.map((inv) => {
                const cls = inv.classification as keyof typeof CLASSIFICATION_CONFIG;
                const config = CLASSIFICATION_CONFIG[cls];
                const classificationTone = getClassificationTone(cls);
                const stateTone = getStateTone(inv.state);

                return (
                  <div
                    key={inv.id}
                    className="catalog-row"
                    role="button"
                    tabIndex={0}
                    onClick={() => router.push(`/investigations/${inv.id}`)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        router.push(`/investigations/${inv.id}`);
                      }
                    }}
                  >
                    <div className="row-domain">
                      <div className="row-domain__value">{inv.domain}</div>
                      {inv.observable_type && inv.observable_type !== "domain" ? (
                        <StatusPill tone="info" size="sm" outline mono>
                          {inv.observable_type}
                        </StatusPill>
                      ) : null}
                    </div>

                    <div className="row-cell">
                      {config ? (
                        <StatusPill tone={classificationTone} mono>
                          {config.label}
                        </StatusPill>
                      ) : (
                        <span className="muted-dash">-</span>
                      )}
                    </div>

                    <div className="row-cell row-risk">
                      <span className="risk-value" data-tone={getRiskTone(inv.risk_score)}>
                        {formatRisk(inv.risk_score)}
                      </span>
                    </div>

                    <div className="row-cell">
                      <StatusPill tone={stateTone} size="sm" mono>
                        {String(inv.state || "-")}
                      </StatusPill>
                    </div>

                    <div className="row-cell row-date">{formatDate(inv.created_at)}</div>

                    <div className="row-cell row-actions">
                      <button
                        type="button"
                        className="delete-case-button"
                        disabled={deletingId === inv.id}
                        onClick={(event) => {
                          event.stopPropagation();
                          handleDelete(inv);
                        }}
                      >
                        {deletingId === inv.id ? "Deleting" : "Delete"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="catalog-mobile">
            {investigations.map((inv) => {
              const cls = inv.classification as keyof typeof CLASSIFICATION_CONFIG;
              const config = CLASSIFICATION_CONFIG[cls];
              const classificationTone = getClassificationTone(cls);
              const stateTone = getStateTone(inv.state);

              return (
                <div
                  key={inv.id}
                  className="mobile-card"
                  role="button"
                  tabIndex={0}
                  onClick={() => router.push(`/investigations/${inv.id}`)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      router.push(`/investigations/${inv.id}`);
                    }
                  }}
                >
                  <div className="mobile-card__top">
                    <div className="mobile-card__domain">{inv.domain}</div>
                    {inv.observable_type && inv.observable_type !== "domain" ? (
                      <StatusPill tone="info" size="sm" outline mono>
                        {inv.observable_type}
                      </StatusPill>
                    ) : null}
                  </div>

                  <div className="mobile-card__pills">
                    {config ? (
                      <StatusPill tone={classificationTone} mono>
                        {config.label}
                      </StatusPill>
                    ) : null}
                    <StatusPill tone={getRiskTone(inv.risk_score)} mono>
                      Risk {formatRisk(inv.risk_score)}
                    </StatusPill>
                    <StatusPill tone={stateTone} mono>
                      {String(inv.state || "-")}
                    </StatusPill>
                  </div>

                  <div className="mobile-card__meta">
                    <span>Created</span>
                    <span>{formatDate(inv.created_at)}</span>
                  </div>

                  <button
                    type="button"
                    className="delete-case-button delete-case-button--mobile"
                    disabled={deletingId === inv.id}
                    onClick={(event) => {
                      event.stopPropagation();
                      handleDelete(inv);
                    }}
                  >
                    {deletingId === inv.id ? "Deleting" : "Delete investigation"}
                  </button>
                </div>
              );
            })}
          </div>
        </ConsoleModule>
      )}

      {total > 0 ? (
        <div className="pagination-shell">
          <div className="pagination-summary">
            <span className="pagination-summary__range">
              {showingFrom}-{showingTo} of {total}
            </span>
            <span className="pagination-summary__hint">
              {filterLabel} queue, page {page + 1} of {totalPages}
              {classificationFilter !== "all" ? ` • ${classificationLabel}` : ""}
              {hideDuplicates ? " • duplicates hidden" : ""}
            </span>
          </div>

          <div className="pagination-controls">
            <button
              onClick={() => setPage(0)}
              disabled={page === 0}
              style={paginationButtonStyle(page === 0)}
            >
              &laquo;
            </button>
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              style={paginationButtonStyle(page === 0)}
            >
              Prev
            </button>

            <div className="page-numbers">
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
                    style={paginationButtonStyle(false, p === page)}
                  >
                    {p + 1}
                  </button>
                ));
              })()}
            </div>

            <button
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
              style={paginationButtonStyle(page >= totalPages - 1)}
            >
              Next
            </button>
            <button
              onClick={() => setPage(totalPages - 1)}
              disabled={page >= totalPages - 1}
              style={paginationButtonStyle(page >= totalPages - 1)}
            >
              &raquo;
            </button>
          </div>
        </div>
      ) : null}

      <style jsx>{`
        .controls-grid {
          display: grid;
          grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr);
          gap: 14px;
          align-items: start;
        }

        .search-panel {
          display: grid;
          gap: 10px;
          min-width: 0;
        }

        .console-label {
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.14em;
          text-transform: uppercase;
          color: var(--text-dim);
        }

        .filter-row {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          align-items: center;
        }

        .page-size-wrap {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-left: auto;
          flex-wrap: wrap;
        }

        .select-wrap {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
        }

        .catalog-header {
          display: grid;
          grid-template-columns: minmax(0, 2.1fr) minmax(150px, 0.9fr) minmax(90px, 0.55fr) minmax(120px, 0.7fr) minmax(120px, 0.85fr) minmax(96px, 0.55fr);
          gap: 12px;
          padding: 0 14px 12px;
          font-size: 10px;
          font-weight: 800;
          color: var(--text-dim);
          letter-spacing: 0.16em;
          text-transform: uppercase;
          border-bottom: 1px solid rgba(120, 145, 178, 0.12);
          font-family: var(--font-mono);
        }

        .catalog-list {
          display: grid;
          gap: 10px;
          margin-top: 12px;
        }

        div[data-density="compact"] .catalog-list {
          gap: 8px;
        }

        .catalog-row {
          display: grid;
          grid-template-columns: minmax(0, 2.1fr) minmax(150px, 0.9fr) minmax(90px, 0.55fr) minmax(120px, 0.7fr) minmax(120px, 0.85fr) minmax(96px, 0.55fr);
          gap: 12px;
          align-items: center;
          padding: 16px 14px;
          border-radius: 18px;
          border: 1px solid var(--panel-divider-strong);
          background: var(--panel-card-bg);
          box-shadow: var(--panel-shadow-soft);
          color: var(--text-strong);
          text-align: left;
          transition: transform 160ms ease, border-color 160ms ease, box-shadow 160ms ease, background 160ms ease;
          cursor: pointer;
          width: 100%;
          font-family: var(--font-sans);
        }

        div[data-density="compact"] .catalog-row {
          padding: 12px 14px;
          border-radius: 16px;
        }

        .catalog-row:hover {
          transform: translateY(-1px);
          border-color: rgba(102, 168, 255, 0.28);
          box-shadow: var(--panel-shadow-card);
          background: var(--bg-card-hover);
        }

        .catalog-row:focus-visible,
        .mobile-card:focus-visible,
        .filter-row button:focus-visible,
        .pagination-controls button:focus-visible,
        .page-size-wrap select:focus-visible,
        button:focus-visible {
          outline: 2px solid rgba(102, 168, 255, 0.8);
          outline-offset: 2px;
        }

        .row-domain {
          display: grid;
          gap: 8px;
          min-width: 0;
        }

        .row-domain__value {
          font-family: var(--font-display);
          font-size: 16px;
          line-height: 1.35;
          font-weight: 700;
          color: var(--text-strong);
          word-break: break-word;
        }

        div[data-density="compact"] .row-domain__value,
        div[data-density="compact"] .mobile-card__domain {
          font-size: 14px;
        }

        .row-cell {
          min-width: 0;
        }

        .row-risk {
          display: flex;
          align-items: center;
        }

        .risk-value {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 58px;
          padding: 8px 10px;
          border-radius: 999px;
          font-family: var(--font-display);
          font-size: 14px;
          font-weight: 700;
          letter-spacing: -0.02em;
          background: rgba(120, 145, 178, 0.09);
          border: 1px solid rgba(120, 145, 178, 0.18);
        }

        .risk-value[data-tone="danger"] {
          color: #fda4af;
          background: rgba(251, 113, 133, 0.12);
          border-color: rgba(251, 113, 133, 0.28);
        }

        .risk-value[data-tone="warning"] {
          color: #fde68a;
          background: rgba(251, 191, 36, 0.12);
          border-color: rgba(251, 191, 36, 0.28);
        }

        .risk-value[data-tone="info"] {
          color: #bfdbfe;
          background: rgba(102, 168, 255, 0.12);
          border-color: rgba(102, 168, 255, 0.28);
        }

        .row-date,
        .muted-dash {
          color: var(--text-secondary);
        }

        .row-actions {
          display: flex;
          align-items: center;
          justify-content: flex-end;
        }

        .delete-case-button {
          border: 1px solid rgba(251, 113, 133, 0.28);
          background: rgba(127, 29, 29, 0.16);
          color: #fda4af;
          border-radius: 10px;
          padding: 7px 10px;
          font-size: 10px;
          font-weight: 800;
          font-family: var(--font-mono);
          letter-spacing: 0.08em;
          text-transform: uppercase;
          cursor: pointer;
          white-space: nowrap;
        }

        .delete-case-button:hover:not(:disabled) {
          background: rgba(220, 38, 38, 0.22);
          border-color: rgba(251, 113, 133, 0.52);
          color: #fecdd3;
        }

        .delete-case-button:disabled {
          cursor: wait;
          opacity: 0.62;
        }

        .mobile-card {
          display: grid;
          gap: 12px;
          padding: 16px;
          border-radius: 18px;
          border: 1px solid var(--panel-divider-strong);
          background: var(--panel-card-bg);
          box-shadow: var(--panel-shadow-soft);
          text-align: left;
          width: 100%;
          color: var(--text-strong);
          cursor: pointer;
        }

        div[data-density="compact"] .mobile-card {
          gap: 10px;
          padding: 14px;
        }

        .mobile-card__top {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: flex-start;
        }

        .mobile-card__domain {
          font-family: var(--font-display);
          font-size: 16px;
          line-height: 1.35;
          font-weight: 700;
          color: var(--text-strong);
          word-break: break-word;
          min-width: 0;
        }

        .mobile-card__pills {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .mobile-card__meta {
          display: flex;
          justify-content: space-between;
          gap: 16px;
          font-size: 12px;
          color: var(--text-secondary);
          border-top: 1px solid var(--panel-divider);
          padding-top: 12px;
        }

        .catalog-mobile {
          display: none;
          gap: 10px;
        }

        .pagination-shell {
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: center;
          margin-top: 18px;
          padding-top: 14px;
          border-top: 1px solid var(--panel-divider);
          flex-wrap: wrap;
        }

        .pagination-summary {
          display: grid;
          gap: 4px;
        }

        .pagination-summary__range {
          font-family: var(--font-display);
          font-size: 16px;
          font-weight: 700;
          color: var(--text-strong);
        }

        .pagination-summary__hint {
          font-size: 12px;
          color: var(--text-secondary);
        }

        .delete-case-button--mobile {
          width: 100%;
          margin-top: 2px;
        }

        .pagination-controls {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .page-numbers {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
        }

        .empty-state {
          display: grid;
          justify-items: center;
          gap: 14px;
          padding: 18px 0 4px;
          text-align: center;
        }

        .empty-state__badge {
          display: flex;
          justify-content: center;
        }

        .empty-state__hint {
          max-width: 680px;
          color: var(--text-secondary);
          font-size: 13px;
          line-height: 1.7;
        }

        @media (max-width: 1080px) {
          .controls-grid {
            grid-template-columns: 1fr;
          }

          .page-size-wrap {
            margin-left: 0;
          }
        }

        @media (max-width: 860px) {
          .catalog-desktop {
            display: none;
          }

          .catalog-mobile {
            display: grid;
          }

          .pagination-shell {
            align-items: flex-start;
          }
        }

        @media (max-width: 720px) {
          .mobile-card__top,
          .mobile-card__meta,
          .pagination-shell,
          .pagination-controls {
            align-items: flex-start;
          }

          .mobile-card__meta {
            flex-direction: column;
            gap: 4px;
          }

          .pagination-controls {
            width: 100%;
          }
        }
      `}</style>
    </div>
  );
}

function buttonStyle(variant: "primary" | "secondary") {
  return {
    padding: "11px 18px",
    borderRadius: 999,
    border: variant === "primary" ? "1px solid rgba(102, 168, 255, 0.35)" : "1px solid rgba(120, 145, 178, 0.2)",
    background:
      variant === "primary"
        ? "linear-gradient(135deg, #3b82f6, #2563eb)"
        : "var(--bg-elevated)",
    color: variant === "primary" ? "#fff" : "var(--text-strong)",
    fontSize: 11,
    fontWeight: 800,
    cursor: "pointer",
    fontFamily: "var(--font-mono)",
    letterSpacing: "0.08em",
    textTransform: "uppercase" as const,
    boxShadow: variant === "primary" ? "0 18px 34px rgba(37, 99, 235, 0.24)" : "none",
  } as React.CSSProperties;
}

function filterButtonStyle(active: boolean, tone: ReturnType<typeof getFilterTone>) {
  const toneColors = filterToneColors(tone);
  return {
    padding: "8px 13px",
    borderRadius: 999,
    border: `1px solid ${active ? toneColors.borderActive : toneColors.border}`,
    background: active ? toneColors.backgroundActive : toneColors.background,
    color: active ? toneColors.foregroundActive : toneColors.foreground,
    fontSize: 10,
    fontWeight: 800,
    cursor: "pointer",
    fontFamily: "var(--font-mono)",
    letterSpacing: "0.08em",
    textTransform: "uppercase" as const,
  } as React.CSSProperties;
}

function paginationButtonStyle(disabled: boolean, active = false) {
  return {
    padding: "7px 11px",
    background: active ? "var(--accent)" : "var(--bg-elevated)",
    border: `1px solid ${active ? "var(--accent)" : "rgba(120, 145, 178, 0.18)"}`,
    borderRadius: 12,
    color: active ? "#fff" : disabled ? "var(--text-dim)" : "var(--text)",
    fontSize: 11,
    fontWeight: 700,
    cursor: disabled ? "default" : "pointer",
    fontFamily: "var(--font-mono)",
    opacity: disabled ? 0.45 : 1,
    minWidth: 34,
  } as React.CSSProperties;
}

function searchInputStyle(): React.CSSProperties {
  return {
    width: "100%",
    padding: "12px 16px",
    background: "var(--bg-elevated)",
    border: "1px solid var(--panel-divider-strong)",
    borderRadius: 16,
    color: "var(--text-strong)",
    fontSize: 13,
    fontFamily: "var(--font-mono)",
    outline: "none",
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04)",
  };
}

function selectStyle(): React.CSSProperties {
  return {
    padding: "10px 12px",
    background: "var(--bg-elevated)",
    border: "1px solid var(--panel-divider-strong)",
    borderRadius: 14,
    color: "var(--text-strong)",
    fontSize: 12,
    fontFamily: "var(--font-mono)",
    cursor: "pointer",
    outline: "none",
  };
}

function formatFilterLabel(filter: string) {
  if (filter === "all") return "All";
  return filter.replace(/^\w/, (value) => value.toUpperCase());
}

function getFilterTone(filter: string) {
  switch (filter) {
    case "failed":
      return "danger";
    case "concluded":
      return "success";
    case "evaluating":
    case "gathering":
    case "created":
      return "warning";
    case "all":
    default:
      return "neutral";
  }
}

function buildFilteredHint({
  search,
  stateLabel,
  classificationLabel,
  hideDuplicates,
}: {
  search: string;
  stateLabel: string;
  classificationLabel: string;
  hideDuplicates: boolean;
}) {
  const parts = [
    search ? `Matching "${search}"` : `Viewing ${stateLabel.toLowerCase()} cases`,
    classificationLabel !== "All" ? `${classificationLabel.toLowerCase()} classification` : null,
    hideDuplicates ? "newest unique values only" : null,
  ].filter(Boolean);
  return parts.join(" • ");
}


function filterToneColors(tone: ReturnType<typeof getFilterTone>) {
  switch (tone) {
    case "success":
      return {
        foreground: "#9bf0d8",
        foregroundActive: "#08121d",
        background: "rgba(56, 217, 169, 0.08)",
        backgroundActive: "rgba(56, 217, 169, 0.92)",
        border: "rgba(56, 217, 169, 0.18)",
        borderActive: "rgba(56, 217, 169, 0.44)",
      };
    case "warning":
      return {
        foreground: "#fde68a",
        foregroundActive: "#09111d",
        background: "rgba(251, 191, 36, 0.08)",
        backgroundActive: "rgba(251, 191, 36, 0.92)",
        border: "rgba(251, 191, 36, 0.18)",
        borderActive: "rgba(251, 191, 36, 0.44)",
      };
    case "danger":
      return {
        foreground: "#fda4af",
        foregroundActive: "#09111d",
        background: "rgba(251, 113, 133, 0.08)",
        backgroundActive: "rgba(251, 113, 133, 0.92)",
        border: "rgba(251, 113, 133, 0.18)",
        borderActive: "rgba(251, 113, 133, 0.44)",
      };
    case "neutral":
    default:
      return {
        foreground: "var(--text-secondary)",
        foregroundActive: "#08121d",
        background: "rgba(120, 145, 178, 0.08)",
        backgroundActive: "rgba(120, 145, 178, 0.88)",
        border: "rgba(120, 145, 178, 0.18)",
        borderActive: "rgba(120, 145, 178, 0.38)",
      };
  }
}

function getClassificationTone(classification: string) {
  switch (classification) {
    case "malicious":
      return "danger";
    case "suspicious":
      return "warning";
    case "benign":
      return "success";
    case "all":
      return "neutral";
    case "inconclusive":
    default:
      return "neutral";
  }
}

function getStateTone(state: string) {
  switch (state) {
    case "concluded":
      return "success";
    case "failed":
      return "danger";
    case "evaluating":
    case "gathering":
    case "created":
      return "warning";
    default:
      return "neutral";
  }
}

function getRiskTone(risk: any) {
  const value = Number(risk ?? 0);
  if (value >= 75) return "danger";
  if (value >= 40) return "warning";
  if (value > 0) return "info";
  return "neutral";
}

function formatRisk(risk: any) {
  if (risk === null || risk === undefined || risk === "") return "-";
  return String(risk);
}

function formatDate(value: any) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}
