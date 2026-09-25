"use client";

/**
 * The estate, one machine at a time.
 *
 * These panels used to be printed inside every case — activity, most triggered
 * rules, verdicts, accounts. They describe the *device*, not the case: the same
 * five panels appeared identically on every case for a busy host, and pushed
 * the four things that were actually about the case below the fold.
 *
 * The list answers "which machine deserves attention"; opening one answers
 * "and what is this machine". Worst verdict first, because volume is a
 * workload measure and this list is read to decide where to look.
 */

import React, { useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";
import type { DeviceRow, TenantOption } from "@/lib/api";
import EntityWindow from "@/components/detections/EntityWindow";
import ClientFilter from "@/components/detections/ClientFilter";
import { EmptyState, LoadingState, Section } from "@/components/ui/Primitives";

const MONO: React.CSSProperties = { fontFamily: "var(--font-mono)" };

const VERDICT_COLOR: Record<string, string> = {
  malicious: "var(--status-critical)",
  suspicious: "var(--status-warning)",
  benign: "var(--status-ok, var(--status-info))",
};

const VERDICTS = ["malicious", "suspicious", "benign"] as const;

function ago(iso: string | null): string {
  if (!iso) return "—";
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function DevicesTab({ days }: { days: number }) {
  const [rows, setRows] = useState<DeviceRow[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState<string>("");
  const [openHost, setOpenHost] = useState<string | null>(null);
  const [tenant, setTenant] = useState("");
  const [tenants, setTenants] = useState<TenantOption[]>([]);

  // Debounced, because this is a group-by over every alert row in the window
  // and a keystroke is not a question.
  const [applied, setApplied] = useState("");
  useEffect(() => {
    const t = window.setTimeout(() => setApplied(search.trim()), 250);
    return () => window.clearTimeout(t);
  }, [search]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .listDevices({ days, search: applied, verdict: verdict || undefined, tenant: tenant || undefined })
      .then((data) => {
        if (cancelled) return;
        setRows(data.items || []);
        setTenants(data.available_tenants || []);
        setError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        setRows(null);
        setError(err instanceof Error ? err.message : "Could not load devices.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [days, applied, verdict, tenant]);

  const total = useMemo(
    () => (rows || []).reduce((sum, r) => sum + r.alerts, 0),
    [rows],
  );

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div className="ds-toolbar" style={{ gap: 8, flexWrap: "wrap" }}>
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by hostname"
          aria-label="Search devices by hostname"
          style={{
            flex: "1 1 220px",
            minWidth: 180,
            borderRadius: 10,
            border: "1px solid var(--panel-divider-strong, var(--border))",
            background: "var(--panel-card-bg, transparent)",
            color: "var(--text-strong, var(--text))",
            padding: "7px 10px",
            fontSize: 13,
          }}
        />
        <ClientFilter options={tenants} value={tenant} onChange={setTenant} />
        <div role="group" aria-label="Filter by worst verdict" style={{ display: "flex", gap: 6 }}>
          {VERDICTS.map((v) => (
            <button
              key={v}
              type="button"
              aria-pressed={verdict === v}
              onClick={() => setVerdict(verdict === v ? "" : v)}
              style={{
                border: `1px solid ${verdict === v ? VERDICT_COLOR[v] : "var(--border)"}`,
                background: verdict === v ? "var(--accent-glow, transparent)" : "transparent",
                color: verdict === v ? VERDICT_COLOR[v] : "var(--text-dim)",
                borderRadius: 999,
                padding: "5px 12px",
                fontSize: 12,
                cursor: "pointer",
                textTransform: "capitalize",
              }}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {loading && !rows ? (
        <LoadingState />
      ) : error ? (
        <EmptyState title="Could not load devices" hint={error} />
      ) : !rows || rows.length === 0 ? (
        <EmptyState
          title="No device has produced an alert in this window"
          hint={
            applied || verdict
              ? "No machine matches these filters. Widen the window or clear the filter."
              : undefined
          }
        />
      ) : (
        <Section
          title={`${rows.length} device${rows.length === 1 ? "" : "s"}`}
          hint={`${total.toLocaleString()} alert(s) across the last ${days} days. Worst verdict first.`}
        >
          <div style={{ display: "grid", gap: 6 }}>
            {rows.map((row) => (
              <button
                key={`${row.tenant_id ?? "-"}:${row.host}`}
                type="button"
                onClick={() => setOpenHost(row.host)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(0,2fr) repeat(4, minmax(0,1fr))",
                  gap: 10,
                  alignItems: "center",
                  textAlign: "left",
                  padding: "9px 12px",
                  borderRadius: 10,
                  border: "1px solid var(--border)",
                  borderLeft: `3px solid ${
                    row.worst_verdict ? VERDICT_COLOR[row.worst_verdict] ?? "var(--border)" : "var(--border)"
                  }`,
                  background: "transparent",
                  color: "var(--text)",
                  cursor: "pointer",
                }}
              >
                <span style={{ ...MONO, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {row.host}
                </span>
                <Cell label="Alerts" value={row.alerts.toLocaleString()} />
                <Cell
                  label="Worst"
                  value={row.worst_verdict ?? "—"}
                  color={row.worst_verdict ? VERDICT_COLOR[row.worst_verdict] : undefined}
                />
                <Cell label="Users" value={String(row.users)} />
                <Cell label="Last seen" value={ago(row.last_seen)} />
              </button>
            ))}
          </div>
        </Section>
      )}

      {openHost && <EntityWindow host={openHost} onClose={() => setOpenHost(null)} />}
    </div>
  );
}

function Cell({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <span style={{ display: "grid", gap: 1, minWidth: 0 }}>
      <span
        style={{
          fontSize: "var(--font-micro, 10px)",
          fontWeight: 700,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        {label}
      </span>
      <span style={{ color: color ?? "var(--text)", textTransform: "capitalize" }}>{value}</span>
    </span>
  );
}
