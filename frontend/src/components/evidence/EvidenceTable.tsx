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
    <div style={{ marginBottom: "var(--space-4)" }}>
      {title && (
        <div
          style={{
            fontSize: "var(--font-micro)",
            fontWeight: 700,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--text-muted)",
            marginBottom: "var(--space-1)",
          }}
        >
          {title}
        </div>
      )}
      <div className="ds-table-wrap">
        <table className="ds-table">
          {showHeader && (
            <thead>
              <tr>
                {columns.map((col, idx) => (
                  <th key={col.key} scope="col" style={{ width: idx === 0 ? "30%" : "auto" }}>
                    {col.label || col.key.toUpperCase()}
                  </th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {data.map((row, i) => (
              <tr key={i}>
                {columns.map((col, j) => {
                  const val = row[col.key];
                  const display: React.ReactNode =
                    val === null || val === undefined
                      ? "—"
                      : React.isValidElement(val)
                      ? val
                      : typeof val === "boolean"
                      ? val
                        ? "Yes"
                        : "No"
                      : String(val);
                  const empty = isEmptyDisplay(display);
                  // Severity colours the text, never the cell. Filled cells put
                  // a wall of tinted blocks behind values that mostly say
                  // "medium", and the one real finding stops standing out.
                  const severity = j > 0 && !empty ? classifySeverity(display, col.key) : "neutral";

                  return (
                    <td
                      key={j}
                      style={{
                        color:
                          j === 0
                            ? "var(--text-dim)"
                            : empty
                            ? "var(--text-muted)"
                            : severity === "malicious"
                            ? "var(--status-danger)"
                            : severity === "suspicious"
                            ? "var(--status-warning)"
                            : severity === "legit"
                            ? "var(--status-success)"
                            : "var(--text-secondary)",
                        fontWeight: j === 0 || severity === "malicious" ? 600 : 400,
                        width: j === 0 ? "30%" : "auto",
                        whiteSpace: col.wrap ? "normal" : "nowrap",
                        overflowWrap: col.wrap ? "anywhere" : "normal",
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
