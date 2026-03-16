"use client";

import { useMemo } from "react";
import type { AssistantEntry, AssistantMode } from "@/lib/types";

export default function AssistantEditor({
  mode,
  title,
  entries,
  onTitleChange,
  onEntryChange,
  onAddEntry,
}: {
  mode: AssistantMode;
  title: string;
  entries: AssistantEntry[];
  onTitleChange: (value: string) => void;
  onEntryChange: (index: number, value: string) => void;
  onAddEntry: () => void;
}) {
  const visibleEntries = useMemo(
    () => (mode === "alert_analysis" ? entries.slice(0, 1) : entries),
    [entries, mode],
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <input
        value={title}
        onChange={(e) => onTitleChange(e.target.value)}
        placeholder="Session title"
        style={inputStyle}
      />
      {visibleEntries.map((entry, index) => (
        <div key={entry.id || index} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
            {mode === "alert_analysis" ? "Alert input" : entry.entry_label || `Entry ${index + 1}`}
          </div>
          <textarea
            value={entry.raw_text}
            onChange={(e) => onEntryChange(index, e.target.value)}
            rows={mode === "alert_analysis" ? 14 : 8}
            style={textareaStyle}
          />
        </div>
      ))}
      {mode === "incident_correlation" ? (
        <button type="button" onClick={onAddEntry} style={buttonStyle}>
          Add Incident Entry
        </button>
      ) : null}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  border: "1px solid var(--border)",
  borderRadius: 10,
  background: "var(--panel)",
  color: "var(--text)",
  padding: "10px 12px",
  fontSize: 14,
};

const textareaStyle: React.CSSProperties = {
  width: "100%",
  border: "1px solid var(--border)",
  borderRadius: 10,
  background: "var(--panel)",
  color: "var(--text)",
  padding: 12,
  fontSize: 13,
  resize: "vertical",
  fontFamily: "var(--font-mono)",
};

const buttonStyle: React.CSSProperties = {
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid var(--border)",
  background: "var(--panel)",
  color: "var(--text)",
  cursor: "pointer",
  alignSelf: "flex-start",
};
