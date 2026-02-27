"use client";

import React from "react";
import { CollectorStatus } from "@/lib/types";
import { COLLECTOR_NAMES } from "@/lib/constants";

export interface CollectorTimingRow {
  collector: string;
  status: CollectorStatus;
  durationMs?: number;
}

interface Props {
  rows: CollectorTimingRow[];
  totalDurationMs?: number;
  live?: boolean;
  title?: string;
}

const STATUS_COLOR: Record<CollectorStatus, string> = {
  pending: "var(--text-muted)",
  running: "var(--yellow)",
  completed: "var(--green)",
  failed: "var(--red)",
  skipped: "var(--text-muted)",
};

export default function CollectorTimingTable({
  rows,
  totalDurationMs,
  live = false,
  title = "Collector Timings",
}: Props) {
  const visibleRows = rows.filter((r) => r.status !== "pending" || live);
  if (visibleRows.length === 0) return null;

  return (
    <div style={{
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
      background: "var(--bg-card)",
      padding: 12,
      marginBottom: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>
          {title}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
          Total: {typeof totalDurationMs === "number" ? `${Math.max(0, Math.round(totalDurationMs / 1000))}s` : "running"}
          {live ? " · live" : ""}
        </div>
      </div>

      <div style={{
        display: "grid",
        gridTemplateColumns: "minmax(72px, 1fr) minmax(80px, 1fr) minmax(86px, 1fr)",
        gap: 6,
        alignItems: "center",
      }}>
        <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>COLLECTOR</div>
        <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>STATUS</div>
        <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>DURATION</div>

        {visibleRows.map((row) => (
          <React.Fragment key={row.collector}>
            <div style={{ fontSize: 11, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
              {COLLECTOR_NAMES[row.collector] || row.collector.toUpperCase()}
            </div>
            <div style={{ fontSize: 11, color: STATUS_COLOR[row.status], fontFamily: "var(--font-mono)" }}>
              {row.status}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
              {typeof row.durationMs === "number" ? `${Math.round(row.durationMs)}ms` : "—"}
            </div>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

