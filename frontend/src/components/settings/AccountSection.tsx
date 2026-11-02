"use client";

/**
 * Your own account, and changing your own password.
 *
 * This exists because /login sends anyone with `must_change_password` to
 * /settings#account — and until now there was nothing at that anchor, so a
 * person handed a generated password had no way to replace it.
 */

import React, { useCallback, useEffect, useState } from "react";
import * as api from "@/lib/api";
import { detailOf, fieldStyle, labelStyle, primaryButtonStyle } from "./accessStyles";

export default function AccountSection() {
  const [me, setMe] = useState<api.Me | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const load = useCallback(() => {
    api.getMe().then(setMe).catch(() => setMe(null));
  }, []);
  useEffect(load, [load]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError("The two new passwords do not match.");
      return;
    }
    if (next.length < 12) {
      setError("A new password must be at least 12 characters.");
      return;
    }
    setBusy(true);
    try {
      await api.changeOwnPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
      load();
    } catch (err) {
      setError(detailOf(err, "Could not change the password."));
    } finally {
      setBusy(false);
    }
  };

  if (!me) return <p style={{ color: "var(--text-dim)", fontSize: 13 }}>Loading your account…</p>;

  const microsoft = me.auth_provider === "microsoft";

  return (
    <div style={{ display: "grid", gap: 18 }}>
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", fontSize: 13 }}>
        <Fact label="Signed in as" value={me.display_name || me.username || "—"} />
        <Fact label="Username" value={me.username || "—"} />
        <Fact label="Role" value={api.roleLabel(me.role)} />
        <Fact label="Signs in with" value={microsoft ? "Microsoft account" : "Password"} />
      </div>

      {me.must_change_password && !done && (
        <Banner tone="warning">
          This password was generated for you. Replace it before using the platform further.
        </Banner>
      )}

      {microsoft ? (
        <p style={{ color: "var(--text-dim)", fontSize: 13, margin: 0 }}>
          This account signs in through Microsoft, so there is no password to change here. Manage it
          in your Microsoft account.
        </p>
      ) : (
        <form onSubmit={submit} style={{ display: "grid", gap: 12, maxWidth: 420 }}>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="current-password" style={labelStyle}>Current password</label>
            <input
              id="current-password"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
              style={fieldStyle}
            />
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="new-password" style={labelStyle}>New password</label>
            <input
              id="new-password"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              required
              minLength={12}
              style={fieldStyle}
            />
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>At least 12 characters.</span>
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="confirm-password" style={labelStyle}>Confirm new password</label>
            <input
              id="confirm-password"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
              style={fieldStyle}
            />
          </div>

          {error && <Banner tone="danger">{error}</Banner>}
          {done && <Banner tone="success">Password changed.</Banner>}

          <button type="submit" disabled={busy} style={primaryButtonStyle(busy)}>
            {busy ? "Changing…" : "Change password"}
          </button>
        </form>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ color: "var(--text-muted)", fontSize: 11, marginBottom: 2 }}>{label}</div>
      <div style={{ color: "var(--text)", fontWeight: 600 }}>{value}</div>
    </div>
  );
}

export function Banner({
  tone,
  children,
}: {
  tone: "warning" | "danger" | "success";
  children: React.ReactNode;
}) {
  const colour = {
    warning: "var(--status-warning)",
    danger: "var(--status-danger)",
    success: "var(--status-success)",
  }[tone];
  return (
    <div
      role={tone === "danger" ? "alert" : undefined}
      style={{
        fontSize: 12,
        color: colour,
        border: `1px solid ${colour}`,
        borderRadius: "var(--radius)",
        padding: "8px 10px",
        background: "color-mix(in srgb, currentColor 8%, transparent)",
      }}
    >
      {children}
    </div>
  );
}
