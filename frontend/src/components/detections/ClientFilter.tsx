"use client";

/**
 * Which client's data is on screen.
 *
 * One control, used by every page that lists alert-derived data, because a
 * selector that looks the same in two places and means two different things is
 * worse than no selector. The options come from the server: it is the only side
 * that knows which clients this account may read, and an account covering
 * everything carries an empty tenant list rather than a list of all of them.
 */

import React from "react";
import type { TenantOption } from "@/lib/api";

export default function ClientFilter({
  options,
  value,
  onChange,
}: {
  options: TenantOption[];
  value: string;
  onChange: (tenant: string) => void;
}) {
  // Nothing to choose between. One client is the normal case today and a
  // selector offering a single option is furniture.
  if (!options || options.length < 2) return null;

  const total = options.reduce((sum, o) => sum + (o.run_count || 0), 0);

  return (
    <label style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
      <span
        style={{
          fontSize: "var(--font-micro, 10px)",
          fontWeight: 700,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        Client
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Filter by client"
        style={{
          borderRadius: 10,
          border: "1px solid var(--panel-divider-strong, var(--border))",
          background: "var(--panel-card-bg, transparent)",
          color: "var(--text-strong, var(--text))",
          padding: "6px 10px",
          fontSize: 13,
        }}
      >
        <option value="">All clients ({total.toLocaleString()})</option>
        {options.map((option) => (
          <option key={option.tenant_id} value={option.tenant_id}>
            {option.name} ({(option.run_count || 0).toLocaleString()})
          </option>
        ))}
      </select>
    </label>
  );
}
