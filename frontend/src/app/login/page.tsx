"use client";

/**
 * Sign in.
 *
 * Deliberately the whole page rather than a modal over the app: until the
 * session cookie exists every other route returns 401, so there is nothing
 * behind it worth rendering.
 */

import React, { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import * as api from "@/lib/api";
import BrandMark from "@/components/layout/BrandMark";
import { APP_BRAND } from "@/lib/constants";

export default function LoginPage() {
  // useSearchParams opts the tree out of static prerendering unless it sits
  // under a Suspense boundary, and the build fails on /login without this.
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.login(username, password);
      // Where they were headed before the wall. Only ever a path from our own
      // router, never a full URL, so it cannot be used to bounce someone off-site.
      const next = params.get("next");
      const destination = next && next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard";
      router.replace(result.must_change_password ? "/settings#account" : destination);
      router.refresh();
    } catch {
      // One message for both "no such user" and "wrong password" — the server
      // does the same, and a form that distinguishes them enumerates accounts.
      setError("Invalid username or password.");
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: "var(--space-4)",
      }}
    >
      <form
        onSubmit={submit}
        style={{
          width: "min(380px, 100%)",
          display: "grid",
          gap: "var(--space-4)",
          padding: "var(--space-6)",
          borderRadius: "var(--shell-radius-lg)",
          border: "1px solid var(--shell-border)",
          background: "var(--shell-surface-strong)",
          boxShadow: "var(--panel-shadow-card)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <BrandMark height={26} />
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-strong)" }}>{APP_BRAND}</div>
        </div>

        <div style={{ display: "grid", gap: 6 }}>
          <label htmlFor="username" style={labelStyle}>Username</label>
          <input
            id="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            autoFocus
            required
            style={inputStyle}
          />
        </div>

        <div style={{ display: "grid", gap: 6 }}>
          <label htmlFor="password" style={labelStyle}>Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
            style={inputStyle}
          />
        </div>

        {error && (
          <div role="alert" style={{ fontSize: "var(--font-meta)", color: "var(--status-danger)" }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          style={{
            padding: "10px 16px",
            borderRadius: "var(--shell-radius-sm)",
            border: "1px solid var(--shell-accent)",
            background: busy ? "var(--bg-elevated)" : "var(--shell-accent)",
            color: busy ? "var(--text-muted)" : "#fff",
            fontSize: "var(--font-body)",
            fontWeight: 600,
            cursor: busy ? "not-allowed" : "pointer",
          }}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontSize: "var(--font-meta)",
  color: "var(--text-dim)",
};

const inputStyle: React.CSSProperties = {
  padding: "9px 11px",
  borderRadius: "var(--shell-radius-sm)",
  border: "1px solid var(--border)",
  background: "var(--bg-input)",
  color: "var(--text)",
  fontSize: "var(--font-body)",
  fontFamily: "var(--font-sans)",
};
