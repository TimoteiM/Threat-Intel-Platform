/** Shared styling and error handling for the account and user sections. */

import React from "react";

export const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-dim)",
};

export const fieldStyle: React.CSSProperties = {
  padding: "8px 10px",
  borderRadius: "var(--radius)",
  border: "1px solid var(--border)",
  background: "var(--bg-input)",
  color: "var(--text)",
  fontSize: 13,
  fontFamily: "var(--font-sans)",
};

export function primaryButtonStyle(busy: boolean): React.CSSProperties {
  return {
    padding: "9px 14px",
    borderRadius: "var(--radius)",
    border: "1px solid var(--shell-accent)",
    background: busy ? "var(--bg-elevated)" : "var(--shell-accent)",
    color: busy ? "var(--text-muted)" : "#fff",
    fontSize: 12,
    fontWeight: 600,
    cursor: busy ? "not-allowed" : "pointer",
    justifySelf: "start",
  };
}

export function smallButtonStyle(tone: "normal" | "danger" = "normal"): React.CSSProperties {
  return {
    padding: "5px 9px",
    borderRadius: "var(--radius)",
    border: `1px solid ${tone === "danger" ? "var(--status-danger)" : "var(--border)"}`,
    background: "transparent",
    color: tone === "danger" ? "var(--status-danger)" : "var(--text-secondary)",
    fontSize: 11,
    fontWeight: 600,
    cursor: "pointer",
    whiteSpace: "nowrap",
  };
}

/**
 * The server's own explanation, when it sent one.
 *
 * These endpoints refuse things for reasons worth reading — "cannot deactivate
 * the only administrator" is guidance, not noise — so the message is shown
 * rather than replaced with a generic failure.
 */
export function detailOf(error: unknown, fallback: string): string {
  const raw = error instanceof Error ? error.message : "";
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed?.detail === "string") return parsed.detail;
  } catch {
    /* not JSON: fall through to the fallback */
  }
  return raw && raw.length < 200 ? raw : fallback;
}
