"use client";

import React, { useMemo } from "react";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid from "@/components/ui/MetadataGrid";
import StatusPill from "@/components/ui/StatusPill";
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
    <div style={{ display: "grid", gap: 14 }}>
      <MetadataGrid
        compact
        columns={3}
        items={[
          { label: "Mode", value: modeLabel(mode), tone: "info" },
          { label: "Visible Entries", value: visibleEntries.length, tone: "neutral" },
          { label: "Run Shape", value: mode === "alert_analysis" ? "Single alert" : "Multi-entry correlation", tone: "neutral" },
        ]}
      />

      <ConsoleModule
        eyebrow="Session Title"
        title="Label the run"
        description="Optional, but useful for keeping longer sessions easy to scan later."
        tone="info"
        compact
      >
        <div style={{ display: "grid", gap: 8 }}>
          <label style={fieldLabelStyle}>Title</label>
          <input value={title} onChange={(e) => onTitleChange(e.target.value)} placeholder="Optional title" style={titleInputStyle} />
        </div>
      </ConsoleModule>

      <div style={{ display: "grid", gap: 12 }}>
          {visibleEntries.map((entry, index) => (
          <ConsoleModule
            key={entry.id || index}
            eyebrow={mode === "alert_analysis" ? "Alert Input" : `Entry ${index + 1}`}
            title={entry.entry_label || `Payload ${index + 1}`}
            description={
              mode === "alert_analysis"
                ? "This alert is sanitized before it is sent to the assistant."
                : "Each entry is sanitized independently and combined during correlation."
            }
            tone={index === 0 ? "info" : "neutral"}
            compact
            actions={
              <StatusPill tone={mode === "alert_analysis" ? "warning" : "neutral"} outline>
                {mode === "alert_analysis" ? "Single" : "Editable"}
              </StatusPill>
            }
          >
            <div style={{ display: "grid", gap: 12 }}>
              {index === 0 ? (
                <div style={{ display: "grid", gap: 8 }}>
                  <label style={fieldLabelStyle}>Title</label>
                  <input value={title} onChange={(e) => onTitleChange(e.target.value)} placeholder="Optional title" style={titleInputStyle} />
                </div>
              ) : null}

              <textarea
                value={entry.raw_text}
                onChange={(e) => onEntryChange(index, e.target.value)}
                rows={mode === "alert_analysis" ? 14 : 8}
                style={textareaStyle}
              />
            </div>
          </ConsoleModule>
        ))}
      </div>

      {mode === "incident_correlation" ? (
        <button type="button" onClick={onAddEntry} style={addButtonStyle}>
          Add Incident Entry
        </button>
      ) : null}
    </div>
  );
}

function modeLabel(mode: AssistantMode) {
  return mode === "alert_analysis" ? "Alert Analysis" : "Incident Correlation";
}

const fieldLabelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
};

const textareaStyle: React.CSSProperties = {
  width: "100%",
  minHeight: 160,
  border: "1px solid var(--panel-divider-strong)",
  borderRadius: 16,
  background: "var(--panel-card-bg)",
  color: "var(--text-strong)",
  padding: 14,
  fontSize: 13,
  resize: "vertical",
  fontFamily: "var(--font-mono)",
  lineHeight: 1.75,
  outline: "none",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04)",
};

const titleInputStyle: React.CSSProperties = {
  width: "100%",
  border: "1px solid var(--panel-divider-strong)",
  borderRadius: 14,
  background: "var(--panel-card-bg)",
  color: "var(--text-strong)",
  padding: "12px 14px",
  fontSize: 14,
  outline: "none",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04)",
};

const addButtonStyle: React.CSSProperties = {
  padding: "11px 14px",
  borderRadius: 14,
  border: "1px solid rgba(102, 168, 255, 0.34)",
  background: "var(--panel-card-bg)",
  color: "var(--text-strong)",
  cursor: "pointer",
  alignSelf: "flex-start",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
};
