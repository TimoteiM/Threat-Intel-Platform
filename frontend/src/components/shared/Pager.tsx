"use client";

/**
 * Page through a list that is too long to read at once.
 *
 * Says where you are in words rather than only in arrows — "26–50 of 749" is
 * the thing an analyst actually wants to know, and a pair of chevrons with no
 * count leaves them guessing whether the end is one page away or thirty.
 *
 * The page size is a control, not a constant: 25 is a screenful, and somebody
 * triaging a quiet morning would rather see a hundred.
 */

import React from "react";

export const PAGE_SIZES = [25, 50, 100] as const;

export default function Pager({
  total,
  page,
  pageSize,
  onPage,
  onPageSize,
  noun = "cases",
}: {
  total: number;
  /** Zero-based. */
  page: number;
  pageSize: number;
  onPage: (next: number) => void;
  onPageSize: (next: number) => void;
  noun?: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages - 1);
  const first = total === 0 ? 0 : current * pageSize + 1;
  const last = Math.min(total, (current + 1) * pageSize);

  return (
    <div
      style={{
        display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center",
        paddingTop: 10, borderTop: "1px solid var(--panel-divider, var(--border))",
      }}
    >
      <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
        {total === 0 ? `No ${noun}` : `${first}–${last} of ${total} ${noun}`}
      </span>

      <div style={{ display: "flex", gap: 4, marginLeft: "auto", alignItems: "center" }}>
        <button
          type="button"
          onClick={() => onPage(Math.max(0, current - 1))}
          disabled={current <= 0}
          style={pageBtn(current <= 0)}
          aria-label="Previous page"
        >
          ← Previous
        </button>
        <span style={{ fontSize: 12, color: "var(--text-muted)", padding: "0 6px" }}>
          Page {current + 1} of {pages}
        </span>
        <button
          type="button"
          onClick={() => onPage(Math.min(pages - 1, current + 1))}
          disabled={current >= pages - 1}
          style={pageBtn(current >= pages - 1)}
          aria-label="Next page"
        >
          Next →
        </button>
      </div>

      <label style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 11.5, color: "var(--text-muted)" }}>
        per page
        <select
          value={pageSize}
          onChange={(e) => onPageSize(Number(e.target.value))}
          aria-label={`${noun} per page`}
          style={{
            borderRadius: 7, border: "1px solid var(--panel-divider-strong, var(--border))",
            background: "var(--panel-card-bg, transparent)", color: "var(--text-strong, var(--text))",
            padding: "3px 6px", fontSize: 12,
          }}
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>{size}</option>
          ))}
        </select>
      </label>
    </div>
  );
}

function pageBtn(disabled: boolean): React.CSSProperties {
  return {
    padding: "4px 11px",
    borderRadius: 7,
    fontSize: 12,
    cursor: disabled ? "default" : "pointer",
    opacity: disabled ? 0.4 : 1,
    border: "1px solid var(--panel-divider-strong, var(--border))",
    background: "transparent",
    color: "var(--text)",
  };
}
