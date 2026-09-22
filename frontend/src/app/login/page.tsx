"use client";

/**
 * Sign in.
 *
 * Deliberately the whole page rather than a modal over the app: until the
 * session cookie exists every other route returns 401, so there is nothing
 * behind it worth rendering.
 *
 * Two ways in, and the page only offers the second one when the backend says
 * it is configured — a "Sign in with Microsoft" button on a deployment with no
 * tenant registered is a button that can only ever fail.
 */

import React, { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import * as api from "@/lib/api";
import BrandMark from "@/components/layout/BrandMark";
import { APP_BRAND } from "@/lib/constants";

/** Why a Microsoft round trip came back without signing anyone in. */
const SSO_ERRORS: Record<string, string> = {
  sso_unavailable: "Microsoft sign-in is not configured on this deployment.",
  sso_failed: "Microsoft sign-in could not be completed. Please try again.",
  sso_expired: "That sign-in attempt timed out. Please try again.",
  sso_no_account:
    "That Microsoft account is not set up on this platform. Ask an administrator to add you.",
};

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
  const [microsoft, setMicrosoft] = useState(false);

  // Where they were headed before the wall. Only ever a path from our own
  // router, never a full URL, so it cannot be used to bounce someone off-site.
  const rawNext = params.get("next");
  const destination =
    rawNext && rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/dashboard";

  // A failed Microsoft round trip lands back here with a code in the URL.
  useEffect(() => {
    const code = params.get("error");
    if (code) setError(SSO_ERRORS[code] || SSO_ERRORS.sso_failed);
  }, [params]);

  useEffect(() => {
    let cancelled = false;
    api
      .getAuthStatus()
      .then((status) => {
        if (!cancelled) setMicrosoft(Boolean(status.providers?.microsoft));
      })
      .catch(() => {
        // The password form works regardless; no button is the safe default.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.login(username, password);
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

        {microsoft && (
          <>
            <button
              type="button"
              onClick={() => api.startMicrosoftSignIn(destination)}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 10,
                padding: "10px 16px",
                borderRadius: "var(--shell-radius-sm)",
                border: "1px solid var(--border)",
                background: "var(--bg-elevated)",
                color: "var(--text-strong)",
                fontSize: "var(--font-body)",
                fontFamily: "var(--font-sans)",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              <MicrosoftMark />
              Sign in with Microsoft
            </button>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr auto 1fr",
                alignItems: "center",
                gap: 10,
                color: "var(--text-muted)",
                fontSize: "var(--font-meta)",
              }}
            >
              <span style={{ height: 1, background: "var(--shell-border)" }} />
              or sign in with a local account
              <span style={{ height: 1, background: "var(--shell-border)" }} />
            </div>
          </>
        )}

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

/** The four-square Microsoft mark, at the size their button guidance asks for. */
function MicrosoftMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" style={{ flexShrink: 0 }}>
      <rect x="0" y="0" width="7" height="7" fill="#f25022" />
      <rect x="9" y="0" width="7" height="7" fill="#7fba00" />
      <rect x="0" y="9" width="7" height="7" fill="#00a4ef" />
      <rect x="9" y="9" width="7" height="7" fill="#ffb900" />
    </svg>
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
