"use client";

import React from "react";

interface Row {
  [key: string]: any;
}

interface Column {
  key: string;
  label?: string;
  wrap?: boolean;
}

interface Props {
  title?: string;
  data: Row[];
  columns: Column[];
  showHeader?: boolean;
}

export default function EvidenceTable({ title, data, columns, showHeader = false }: Props) {
  if (data.length === 0) return null;

  return (
    <div style={{ marginBottom: 16 }}>
      {title && (
        <div
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: "var(--text-dim)",
            letterSpacing: "0.01em",
            marginBottom: 6,
            padding: "6px 0",
            borderBottom: "1px solid var(--border-dim)",
            fontFamily: "var(--font-sans)",
          }}
        >
          {title}
        </div>
      )}
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        {showHeader && (
          <thead>
            <tr>
              {columns.map((col, idx) => (
                <th
                  key={col.key}
                  style={{
                    textAlign: "left",
                    padding: "6px 12px",
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: "0.04em",
                    color: "var(--text-muted)",
                    borderBottom: "1px solid var(--border-dim)",
                    whiteSpace: "nowrap",
                    fontFamily: "var(--font-mono)",
                    width: idx === 0 ? "30%" : "auto",
                  }}
                >
                  {col.label || col.key.toUpperCase()}
                </th>
              ))}
            </tr>
          </thead>
        )}
        <tbody>
          {data.map((row, i) => (
            <tr key={i} style={{ borderBottom: "1px solid var(--bg-root)" }}>
              {columns.map((col, j) => {
                const val = row[col.key];
                const display: React.ReactNode =
                  val === null || val === undefined
                    ? "-"
                    : React.isValidElement(val)
                    ? val
                    : typeof val === "boolean"
                    ? val
                      ? "Yes"
                      : "No"
                    : String(val);
                const empty = isEmptyDisplay(display);

                return (
                  <td
                    key={j}
                    style={{
                      padding: "7px 12px",
                      fontSize: 11,
                      color: (() => {
                        if (j === 0) return "var(--text-dim)";
                        if (empty) return "var(--text-muted)";
                        const sev = classifySeverity(display, col.key);
                        if (sev === "malicious") return "var(--red)";
                        if (sev === "suspicious") return "var(--yellow)";
                        if (sev === "legit") return "var(--green)";
                        return "var(--text-primary)";
                      })(),
                      fontWeight: j === 0 ? 600 : 400,
                      width: j === 0 ? "30%" : "auto",
                      background: (() => {
                        if (j > 0 && !empty) {
                          const sev = classifySeverity(display, col.key);
                          if (sev === "malicious") return "rgba(239,68,68,0.14)";
                          if (sev === "suspicious") return "rgba(245,158,11,0.14)";
                          if (sev === "legit") return "rgba(52,211,153,0.10)";
                          return "transparent";
                        }
                        return i % 2 === 0 ? "transparent" : "rgba(15,23,42,0.4)";
                      })(),
                      whiteSpace: col.wrap ? "normal" : "nowrap",
                      wordBreak: col.wrap ? "break-all" : "normal",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {display}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isEmptyDisplay(value: React.ReactNode): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value !== "string") return false;
  const text = value.trim().toLowerCase();
  return (
    text === "" ||
    text === "-" ||
    text === "—" ||
    text === "n/a" ||
    text === "none" ||
    text === "unknown" ||
    text === "not present in the provided evidence."
  );
}

function classifySeverity(value: React.ReactNode, key: string): "malicious" | "suspicious" | "legit" | "neutral" {
  if (value === null || value === undefined) return "neutral";
  const text = String(value).toLowerCase();
  const k = String(key || "").toLowerCase();
  if (
    text.includes("malicious") ||
    text.includes("phishing") ||
    text.includes("critical") ||
    text.includes("high risk") ||
    (k.includes("threat_level") && /\b([2-9]|[1-9]\d+)\b/.test(text))
  ) {
    return "malicious";
  }
  if (
    text.includes("suspicious") ||
    text.includes("warning") ||
    text.includes("medium") ||
    text.includes("inconclusive")
  ) {
    return "suspicious";
  }
  if (
    text.includes("whitelisted") ||
    text.includes("legitimate") ||
    text.includes("trusted") ||
    text.includes("clean") ||
    text.includes("benign")
  ) {
    return "legit";
  }
  return "neutral";
}
