"use client";

/**
 * Who is signed in, and the way out.
 *
 * Renders nothing at all while the backend is in `monitor` mode and nobody has
 * signed in — during that rollout the platform still answers unauthenticated
 * callers, and a "Sign out" button for a session that does not exist would be
 * a lie about the state of the system.
 */

import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";

export default function SessionControl({ collapsed }: { collapsed: boolean }) {
  const router = useRouter();
  const [status, setStatus] = useState<api.AuthStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getAuthStatus()
      .then((next) => {
        if (!cancelled) setStatus(next);
      })
      .catch(() => {
        /* the API being unreachable is the page's problem to report, not this control's */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }, [router]);

  if (!status?.authenticated) return null;

  const who = status.username || "signed in";

  return (
    <button
      type="button"
      onClick={signOut}
      title={`Signed in as ${who} — sign out`}
      aria-label={`Signed in as ${who}. Sign out.`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        maxWidth: collapsed ? 30 : 118,
        padding: collapsed ? 0 : "4px 8px",
        width: collapsed ? 30 : undefined,
        height: collapsed ? 30 : undefined,
        justifyContent: "center",
        borderRadius: "var(--shell-radius-sm)",
        border: "1px solid var(--shell-border)",
        background: "transparent",
        color: "var(--text-dim)",
        fontSize: 11,
        fontFamily: "var(--font-sans)",
        cursor: "pointer",
        overflow: "hidden",
      }}
    >
      <svg
        viewBox="0 0 24 24"
        aria-hidden="true"
        style={{
          width: 15,
          height: 15,
          flexShrink: 0,
          fill: "none",
          stroke: "currentColor",
          strokeWidth: 1.6,
          strokeLinecap: "round",
          strokeLinejoin: "round",
        }}
      >
        <path d="M15 4h3.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H15" />
        <path d="M10 8 6 12l4 4M6 12h9" />
      </svg>
      {!collapsed && (
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {who}
        </span>
      )}
    </button>
  );
}
