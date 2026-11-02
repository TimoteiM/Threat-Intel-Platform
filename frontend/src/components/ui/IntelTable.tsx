"use client";

import React from "react";
import type { ConsoleTone } from "@/components/ui/ConsoleModule";
import StatusPill from "@/components/ui/StatusPill";

export interface IntelColumn {
  key: string;
  label?: React.ReactNode;
  align?: "left" | "center" | "right";
  wrap?: boolean;
  width?: string | number;
  mono?: boolean;
}

export interface IntelRow {
  id?: string | number;
  tone?: ConsoleTone;
  [key: string]: any;
}

interface IntelTableProps {
  columns: IntelColumn[];
  rows: IntelRow[];
  title?: React.ReactNode;
  eyebrow?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  showHeader?: boolean;
  density?: "compact" | "comfortable";
  emptyTitle?: React.ReactNode;
  emptyDescription?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  rowKey?: string | ((row: IntelRow, index: number) => React.Key);
}

export default function IntelTable({
  columns,
  rows,
  title,
  eyebrow,
  description,
  actions,
  showHeader = true,
  density = "comfortable",
  emptyTitle = "No intelligence rows",
  emptyDescription = "This table will populate when the source returns structured data.",
  className,
  style,
  rowKey,
}: IntelTableProps) {
  const padY = density === "compact" ? 9 : 12;
  const padX = density === "compact" ? 12 : 14;

  if (!rows.length) {
    return (
      <section
        className={className}
        style={{
          borderRadius: 20,
          border: "1px solid var(--panel-divider-strong)",
          background: "var(--panel-card-bg)",
          padding: 18,
          boxShadow: "var(--panel-shadow-card)",
          ...style,
        }}
      >
        {(title || eyebrow || description || actions) ? (
          <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 14 }}>
            <div style={{ minWidth: 0 }}>
              {eyebrow ? <div style={eyebrowStyle}>{eyebrow}</div> : null}
              {title ? <div style={titleStyle}>{title}</div> : null}
              {description ? <div style={descriptionStyle}>{description}</div> : null}
            </div>
            {actions ? <div style={{ display: "flex", gap: 10, alignItems: "center" }}>{actions}</div> : null}
          </div>
        ) : null}
        <EmptyState title={emptyTitle} description={emptyDescription} />
      </section>
    );
  }

  return (
    <section
      className={className}
      style={{
        borderRadius: 20,
        border: "1px solid var(--panel-divider-strong)",
        background: "var(--panel-card-bg)",
        overflow: "hidden",
        boxShadow: "var(--panel-shadow-card)",
        ...style,
      }}
    >
      {(title || eyebrow || description || actions) ? (
        <div style={{ padding: 18, borderBottom: showHeader ? "1px solid var(--panel-divider)" : "none" }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
            <div style={{ minWidth: 0 }}>
              {eyebrow ? <div style={eyebrowStyle}>{eyebrow}</div> : null}
              {title ? <div style={titleStyle}>{title}</div> : null}
              {description ? <div style={descriptionStyle}>{description}</div> : null}
            </div>
            {actions ? <div style={{ display: "flex", gap: 10, alignItems: "center" }}>{actions}</div> : null}
          </div>
        </div>
      ) : null}

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "separate", borderSpacing: 0 }}>
          {showHeader ? (
            <thead>
              <tr>
                {columns.map((column) => (
                  <th
                    key={column.key}
                    style={{
                      textAlign: column.align || "left",
                      padding: `${padY}px ${padX}px`,
                      fontSize: 10,
                      fontWeight: 800,
                      letterSpacing: "0.14em",
                      textTransform: "uppercase",
                      color: "var(--text-dim)",
                      borderBottom: "1px solid var(--panel-divider-strong)",
                      whiteSpace: "nowrap",
                      fontFamily: "var(--font-mono)",
                      width: column.width,
                    }}
                  >
                    {column.label || column.key}
                  </th>
                ))}
              </tr>
            </thead>
          ) : null}
          <tbody>
            {rows.map((row, index) => {
              const key = resolveRowKey(row, index, rowKey);
              const tone = row.tone || "neutral";
              return (
                <tr
                  key={key}
                  style={{
                    background: index % 2 === 0 ? "transparent" : "var(--panel-row-alt)",
                  }}
                >
                  {columns.map((column, cellIndex) => {
                    const raw = row[column.key];
                    const value = formatCell(raw);
                    return (
                      <td
                        key={`${key}-${column.key}`}
                        style={{
                          padding: `${padY}px ${padX}px`,
                          borderBottom: "1px solid var(--panel-divider-soft)",
                          color: cellIndex === 0 ? "var(--text-secondary)" : "var(--text)",
                          textAlign: column.align || "left",
                          whiteSpace: column.wrap ? "normal" : "nowrap",
                          wordBreak: column.wrap ? "break-word" : "normal",
                          fontSize: 12,
                          lineHeight: 1.6,
                          fontFamily: column.mono ? "var(--font-mono)" : "var(--font-sans)",
                        }}
                      >
                        <IntelCell tone={tone} columnIndex={cellIndex} value={value} />
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function IntelCell({
  value,
  tone,
  columnIndex,
}: {
  value: React.ReactNode;
  tone: ConsoleTone;
  columnIndex: number;
}) {
  if (React.isValidElement(value)) return value;

  const text = String(value);
  const highlight = tone !== "neutral" && columnIndex > 0;

  if (text === "Yes" || text === "No") {
    return (
      <StatusPill tone={text === "Yes" ? "success" : "neutral"} size="sm" outline>
        {text}
      </StatusPill>
    );
  }

  return (
    <span
      style={{
        color: highlight ? toneToColor(tone) : "inherit",
        fontWeight: columnIndex === 0 ? 700 : 500,
      }}
    >
      {text}
    </span>
  );
}

function formatCell(value: any): React.ReactNode {
  if (value === null || value === undefined || value === "") return "-";
  if (React.isValidElement(value)) return value;
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map((item) => (typeof item === "string" ? item : String(item))).join(", ") : "-";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function resolveRowKey(row: IntelRow, index: number, rowKey?: string | ((row: IntelRow, index: number) => React.Key)) {
  if (typeof rowKey === "function") return rowKey(row, index);
  if (typeof rowKey === "string" && row[rowKey] !== undefined) return String(row[rowKey]);
  if (row.id !== undefined) return String(row.id);
  return `${index}`;
}

function toneToColor(tone: ConsoleTone) {
  switch (tone) {
    case "success":
      return "var(--green)";
    case "warning":
      return "var(--yellow)";
    case "danger":
      return "var(--red)";
    case "info":
      return "var(--accent)";
    case "neutral":
    default:
      return "var(--text-secondary)";
  }
}

function EmptyState({ title, description }: { title: React.ReactNode; description: React.ReactNode }) {
  return (
    <div
      style={{
        display: "grid",
        gap: 8,
        padding: 18,
        borderRadius: 16,
        border: "1px dashed var(--panel-divider-strong)",
        background: "var(--panel-empty-bg)",
      }}
    >
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-strong)" }}>{title}</div>
      <div style={{ fontSize: 13, lineHeight: 1.7, color: "var(--text-secondary)" }}>{description}</div>
    </div>
  );
}

const eyebrowStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.16em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
  marginBottom: 8,
};

const titleStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: 20,
  fontWeight: 700,
  color: "var(--text-strong)",
  letterSpacing: "-0.02em",
};

const descriptionStyle: React.CSSProperties = {
  marginTop: 8,
  fontSize: 13,
  lineHeight: 1.7,
  color: "var(--text-secondary)",
};
