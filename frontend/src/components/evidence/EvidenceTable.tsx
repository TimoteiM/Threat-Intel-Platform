"use client";

import React from "react";

interface Row {
  [key: string]: any;
}

interface Column {
  key: string;
  wrap?: boolean;
}

interface Props {
  title?: string;
  data: Row[];
  columns: Column[];
}

export default function EvidenceTable({ title, data, columns }: Props) {
  if (data.length === 0) return null;

  return (
    <div style={{ marginBottom: 16 }}>
      {title && (
        <div
          style={{
            fontSize: 10,
            fontWeight: 700,
            color: "var(--text-dim)",
            letterSpacing: "0.08em",
            marginBottom: 6,
            padding: "6px 0",
            borderBottom: "1px solid var(--border-dim)",
          }}
        >
          {title}
        </div>
      )}
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} style={{ borderBottom: "1px solid var(--bg-root)" }}>
              {columns.map((col, j) => {
                const val = row[col.key];
                const display =
                  val === null || val === undefined
                    ? "—"
                    : typeof val === "boolean"
                    ? val
                      ? "Yes"
                      : "No"
                    : String(val);

                return (
                  <td
                    key={j}
                    style={{
                      padding: "7px 12px",
                      fontSize: 11,
                      color: j === 0 ? "var(--text-dim)" : "var(--text)",
                      fontWeight: j === 0 ? 600 : 400,
                      width: j === 0 ? "30%" : "auto",
                      background:
                        i % 2 === 0 ? "transparent" : "rgba(6,10,17,0.3)",
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
