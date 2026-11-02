"use client";

/**
 * Confirm the clients the ingest created for itself.
 *
 * When an alert arrives naming a `tenant_id` with no row, the platform creates
 * one rather than refusing the alert — a refused alert is not retried and is
 * simply gone. But it marks the row `provisional`, with a name derived
 * mechanically from the id, because **a sender naming itself in a URL is not a
 * decision to onboard a client.** A mistyped id then shows up as an obviously
 * unconfirmed client holding a handful of alerts, instead of quietly becoming a
 * second place real alerts live.
 *
 * That safeguard had no way out of it. Clearing `provisional` meant a
 * hand-written UPDATE — the same shape as the owner account that could only be
 * disabled at the database, where the guard exists and the action that resolves
 * it does not. This is the action.
 *
 * It sits beside the client selector rather than inside it: a `<select>` holds
 * options, not decisions, and the decision is the point.
 */

import React, { useState } from "react";
import { onboardTenant, type TenantOption } from "@/lib/api";

export default function OnboardClients({
  options,
  canOnboard,
  onDone,
}: {
  options: TenantOption[];
  /** Administrators only — the route refuses anyone else, and offering a
   *  control that will 403 is worse than not offering it. */
  canOnboard: boolean;
  onDone: () => void;
}) {
  const pending = (options || []).filter((o) => o.provisional);
  const [open, setOpen] = useState(false);
  const [names, setNames] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  if (pending.length === 0) return null;

  const confirm = async (option: TenantOption) => {
    setBusy(option.tenant_id);
    setErrors((e) => ({ ...e, [option.tenant_id]: "" }));
    try {
      const typed = (names[option.tenant_id] ?? "").trim();
      await onboardTenant(option.tenant_id, {
        status: "active",
        // Only sent when it was actually edited. Posting the unchanged
        // machine-derived name would record a rename that nobody made.
        ...(typed && typed !== option.name ? { name: typed } : {}),
      });
      onDone();
    } catch (e: unknown) {
      setErrors((prev) => ({
        ...prev,
        [option.tenant_id]: String((e as Error)?.message ?? e),
      }));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div
      style={{
        border: "1px solid var(--warning)",
        borderRadius: 8,
        background: "var(--bg-input, transparent)",
        padding: "10px 12px",
        marginBottom: 12,
        fontSize: 12.5,
        lineHeight: 1.6,
      }}
    >
      <div style={{ fontWeight: 600, color: "var(--warning)" }}>
        {pending.length === 1
          ? "1 client is new and not yet onboarded"
          : `${pending.length} clients are new and not yet onboarded`}
      </div>
      <p style={{ margin: "4px 0 0", color: "var(--text-dim)" }}>
        {pending.length === 1 ? "It was" : "They were"} created by an incoming
        alert naming the id, not by anyone deciding to take the client on — so
        the name is the id in capitals and nobody has confirmed{" "}
        {pending.length === 1 ? "it is" : "they are"} real. Their alerts are
        being investigated normally in the meantime.
      </p>

      {!open && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          style={{
            marginTop: 8,
            padding: "4px 10px",
            borderRadius: 6,
            border: "1px solid var(--border)",
            background: "transparent",
            color: "var(--text)",
            fontSize: 12,
            cursor: "pointer",
          }}
        >
          {canOnboard ? "Review" : "Show which"}
        </button>
      )}

      {open && (
        <ul style={{ margin: "10px 0 0", padding: 0, listStyle: "none" }}>
          {pending.map((option) => (
            <li
              key={option.tenant_id}
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: 8,
                padding: "7px 0",
                borderTop: "1px solid var(--panel-divider-strong, var(--border))",
              }}
            >
              <code style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                {option.tenant_id}
              </code>
              <span style={{ color: "var(--text-muted)", fontSize: 11.5 }}>
                {(option.run_count || 0).toLocaleString()} alert
                {option.run_count === 1 ? "" : "s"}
              </span>
              {canOnboard ? (
                <>
                  <input
                    value={names[option.tenant_id] ?? option.name}
                    onChange={(e) =>
                      setNames((n) => ({ ...n, [option.tenant_id]: e.target.value }))
                    }
                    aria-label={`Name for ${option.tenant_id}`}
                    placeholder="Client name"
                    style={{
                      flex: "1 1 180px",
                      minWidth: 140,
                      padding: "4px 8px",
                      borderRadius: 6,
                      border: "1px solid var(--border)",
                      background: "var(--bg-input, transparent)",
                      color: "var(--text)",
                      fontSize: 12.5,
                    }}
                  />
                  <button
                    type="button"
                    disabled={busy === option.tenant_id}
                    onClick={() => void confirm(option)}
                    style={{
                      padding: "4px 10px",
                      borderRadius: 6,
                      border: "1px solid var(--success)",
                      background: "transparent",
                      color: "var(--success)",
                      fontSize: 12,
                      cursor: busy ? "default" : "pointer",
                    }}
                  >
                    {busy === option.tenant_id ? "Confirming…" : "Confirm client"}
                  </button>
                </>
              ) : (
                <span style={{ color: "var(--text-muted)", fontSize: 11.5 }}>
                  {option.name} — an administrator can confirm this client
                </span>
              )}
              {errors[option.tenant_id] && (
                <span
                  style={{ flexBasis: "100%", color: "var(--danger)", fontSize: 11.5 }}
                >
                  {errors[option.tenant_id]}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
