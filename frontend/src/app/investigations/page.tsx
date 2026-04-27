"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { listInvestigations } from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";
import Spinner from "@/components/shared/Spinner";
import PageHero from "@/components/ui/PageHero";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid from "@/components/ui/MetadataGrid";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

const PAGE_SIZE_OPTIONS = [10, 25, 50];
const FILTERS = ["all", "created", "gathering", "evaluating", "concluded", "failed"] as const;
const CLASSIFICATION_FILTERS = ["all", "malicious", "suspicious", "benign", "inconclusive"] as const;

export default function InvestigationsListPage() {
  const router = useRouter();
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

  useEffect(() => {
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
    <div style={{ paddingTop: 12, paddingBottom: 40 }}>
      <PageHero
        eyebrow="Investigations catalog"
        title="Investigations"
        description={
          <>
            A premium, scan-friendly catalog of cases with the same fetch, search, filter, and pagination behavior you already use.
            {debouncedSearch
              ? ` Search is narrowed to "${debouncedSearch}".`
              : ` Browse the ${buildQueueSummary(filterLabel, classificationLabel, hideDuplicates)}.`}
          </>
        }
        status={<StatusPill tone="info" mono>{total} total</StatusPill>}
        badges={
          <>
            <StatusPill tone={getFilterTone(filter)} mono>{filterLabel}</StatusPill>
            <StatusPill tone={getClassificationTone(classificationFilter)} mono>{classificationLabel}</StatusPill>
            {hideDuplicates ? <StatusPill tone="info" mono>Duplicates hidden</StatusPill> : null}
            {debouncedSearch ? <StatusPill tone="warning" mono>Search active</StatusPill> : <StatusPill tone="neutral" mono>Catalog view</StatusPill>}
          </>
        }
        actions={
          <button
            onClick={() => router.push("/")}
            style={buttonStyle("primary")}
          >
            + New Investigation
          </button>
        }
        stats={
          <>
            <SignalCard
              compact
              tone="info"
              label="Results"
              value={total}
              caption={filteredHint}
              trend="flat"
            />
            <SignalCard
              compact
              tone={loading ? "warning" : "success"}
              label="Showing"
              value={total === 0 ? "0" : `${showingFrom}-${showingTo}`}
              caption={`Page ${page + 1} of ${totalPages}`}
              trend={loading ? "flat" : "up"}
            />
            <SignalCard
              compact
              tone="neutral"
              label="Filter"
              value={filterLabel}
              caption={classificationFilter === "all" ? "All classifications" : classificationLabel}
              trend="flat"
            />
            <SignalCard
              compact
              tone={hideDuplicates ? "info" : "neutral"}
              label="Duplicates"
              value={hideDuplicates ? "Hidden" : "Shown"}
              caption={`Page size ${pageSize}`}
              trend="flat"
            />
          </>
        }
      />

      <div style={{ height: 18 }} />

      <ConsoleModule
        eyebrow="Query surface"
        title="Search and filters"
        description="Keep the investigation queue tight with a debounced search, state and classification filters, duplicate suppression, and a simple per-page selector."
        variant="glass"
        actions={
          <StatusPill tone="neutral" size="sm" mono>
            {totalPages} page{totalPages !== 1 ? "s" : ""}
          </StatusPill>
        }
      >
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

          <MetadataGrid
            compact
            columns={2}
            items={[
              { label: "Active state", value: filterLabel, tone: getFilterTone(filter), mono: true },
              { label: "Classification", value: classificationLabel, tone: getClassificationTone(classificationFilter), mono: true },
              { label: "Page size", value: `${pageSize} rows`, tone: "info", mono: true },
              { label: "Duplicates", value: hideDuplicates ? "Newest only" : "All cases", tone: hideDuplicates ? "info" : "neutral", mono: true },
              { label: "Page", value: `${page + 1} / ${totalPages}`, tone: "neutral", mono: true },
              { label: "Query", value: debouncedSearch || "All investigated values", tone: debouncedSearch ? "warning" : "neutral", mono: true },
            ]}
          />
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
          eyebrow="Catalog empty"
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
          eyebrow="Case queue"
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
            </div>

            <div className="catalog-list">
              {investigations.map((inv) => {
                const cls = inv.classification as keyof typeof CLASSIFICATION_CONFIG;
                const config = CLASSIFICATION_CONFIG[cls];
                const classificationTone = getClassificationTone(cls);
                const stateTone = getStateTone(inv.state);

                return (
                  <button
                    key={inv.id}
                    className="catalog-row"
                    onClick={() => router.push(`/investigations/${inv.id}`)}
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
                  </button>
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
                <button
                  key={inv.id}
                  className="mobile-card"
                  onClick={() => router.push(`/investigations/${inv.id}`)}
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
                </button>
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
          grid-template-columns: minmax(0, 2.1fr) minmax(150px, 0.9fr) minmax(90px, 0.55fr) minmax(120px, 0.7fr) minmax(120px, 0.85fr);
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

        .catalog-row {
          display: grid;
          grid-template-columns: minmax(0, 2.1fr) minmax(150px, 0.9fr) minmax(90px, 0.55fr) minmax(120px, 0.7fr) minmax(120px, 0.85fr);
          gap: 12px;
          align-items: center;
          padding: 16px 14px;
          border-radius: 18px;
          border: 1px solid rgba(120, 145, 178, 0.16);
          background: linear-gradient(180deg, rgba(17, 28, 46, 0.92), rgba(10, 16, 28, 0.98));
          box-shadow: 0 16px 34px rgba(3, 8, 20, 0.16);
          color: var(--text-strong);
          text-align: left;
          transition: transform 160ms ease, border-color 160ms ease, box-shadow 160ms ease, background 160ms ease;
          cursor: pointer;
          width: 100%;
          font-family: var(--font-sans);
        }

        .catalog-row:hover {
          transform: translateY(-1px);
          border-color: rgba(102, 168, 255, 0.28);
          box-shadow: 0 20px 44px rgba(3, 8, 20, 0.24);
          background: linear-gradient(180deg, rgba(19, 31, 50, 0.98), rgba(10, 16, 28, 1));
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

        .mobile-card {
          display: grid;
          gap: 12px;
          padding: 16px;
          border-radius: 18px;
          border: 1px solid rgba(120, 145, 178, 0.16);
          background: linear-gradient(180deg, rgba(17, 28, 46, 0.94), rgba(10, 16, 28, 0.98));
          box-shadow: 0 16px 34px rgba(3, 8, 20, 0.16);
          text-align: left;
          width: 100%;
          color: var(--text-strong);
          cursor: pointer;
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
          border-top: 1px solid rgba(120, 145, 178, 0.12);
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
          border-top: 1px solid rgba(120, 145, 178, 0.12);
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
        : "rgba(10, 16, 28, 0.72)",
    color: "#fff",
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
    background: active ? "var(--accent)" : "rgba(10, 16, 28, 0.72)",
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
    background: "rgba(10, 16, 28, 0.72)",
    border: "1px solid rgba(120, 145, 178, 0.22)",
    borderRadius: 16,
    color: "var(--text-strong)",
    fontSize: 13,
    fontFamily: "var(--font-mono)",
    outline: "none",
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
  };
}

function selectStyle(): React.CSSProperties {
  return {
    padding: "10px 12px",
    background: "rgba(10, 16, 28, 0.72)",
    border: "1px solid rgba(120, 145, 178, 0.22)",
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

function buildQueueSummary(stateLabel: string, classificationLabel: string, hideDuplicates: boolean) {
  const parts = [
    stateLabel.toLowerCase(),
    classificationLabel !== "All" ? classificationLabel.toLowerCase() : null,
    hideDuplicates ? "deduped" : null,
    "queue",
  ].filter(Boolean);
  return parts.join(" ");
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
