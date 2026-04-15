"use client";

import React from "react";
import StatusPill from "@/components/ui/StatusPill";
import type { AssistantSessionListItem } from "@/lib/types";

export default function AssistantSessionList({
  sessions,
  activeSessionId,
  onSelect,
  searchValue,
  onSearchChange,
  offset,
  limit,
  total,
  loading,
  onPreviousPage,
  onNextPage,
}: {
  sessions: AssistantSessionListItem[];
  activeSessionId?: string;
  onSelect: (sessionId: string) => void;
  searchValue: string;
  onSearchChange: (value: string) => void;
  offset: number;
  limit: number;
  total: number;
  loading: boolean;
  onPreviousPage: () => void;
  onNextPage: () => void;
}) {
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = total === 0 ? 0 : Math.min(offset + sessions.length, total);
  const canGoPrevious = offset > 0;
  const canGoNext = offset + limit < total;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={searchHeaderStyle}>
        <div>
          <div style={eyebrowStyle}>Session Catalog</div>
          <div style={titleStyle}>Recent sessions</div>
        </div>
        <div style={metaStyle}>{loading ? "Loading sessions..." : `Showing ${pageStart}-${pageEnd} of ${total}`}</div>
      </div>

      <input
        type="search"
        value={searchValue}
        onChange={(event) => onSearchChange(event.target.value)}
        placeholder="Search title or log content"
        style={searchInputStyle}
      />

      <div style={{ display: "grid", gap: 10 }}>
        {sessions.map((session) => {
          const active = session.id === activeSessionId;
          return (
            <button
              key={session.id}
              type="button"
              onClick={() => onSelect(session.id)}
              style={sessionButtonStyle(active)}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={sessionTitleStyle(active)}>{session.title}</div>
                  <div style={sessionSublineStyle}>
                    {modeLabel(session.mode)}
                    <span style={separatorStyle}>•</span>
                    {session.source_type}
                  </div>
                </div>
                <StatusPill tone={statusTone(session.status)} outline size="sm">
                  {session.status}
                </StatusPill>
              </div>

              <div style={pillRowStyle}>
                <StatusPill tone="neutral" outline size="sm" mono>
                  {session.mode}
                </StatusPill>
                <StatusPill tone={active ? "info" : "neutral"} outline size="sm">
                  {session.source_type}
                </StatusPill>
                <StatusPill tone="neutral" outline size="sm" mono>
                  {formatTimestamp(session.updated_at || session.completed_at || session.created_at)}
                </StatusPill>
                {session.linked_investigation_id ? (
                  <StatusPill tone="neutral" outline size="sm" mono>
                    {session.linked_investigation_id}
                  </StatusPill>
                ) : null}
              </div>
            </button>
          );
        })}
      </div>

      {!loading && sessions.length === 0 ? (
        <div style={emptyStateStyle}>
          No sessions found. Try a broader search or create a new assistant run.
        </div>
      ) : null}

      <div style={{ display: "flex", gap: 10 }}>
        <button type="button" onClick={onPreviousPage} disabled={!canGoPrevious || loading} style={pageButtonStyle(canGoPrevious && !loading)}>
          Previous
        </button>
        <button type="button" onClick={onNextPage} disabled={!canGoNext || loading} style={pageButtonStyle(canGoNext && !loading)}>
          Next
        </button>
      </div>
    </div>
  );
}

function sessionButtonStyle(active: boolean): React.CSSProperties {
  return {
    textAlign: "left",
    padding: 14,
    borderRadius: 16,
    border: `1px solid ${active ? "rgba(102, 168, 255, 0.52)" : "rgba(120, 145, 178, 0.18)"}`,
    background: active
      ? "linear-gradient(180deg, rgba(19, 34, 58, 0.96), rgba(11, 18, 31, 0.98))"
      : "linear-gradient(180deg, rgba(16, 26, 44, 0.86), rgba(11, 17, 29, 0.96))",
    color: "var(--text)",
    cursor: "pointer",
    boxShadow: active ? "0 18px 34px rgba(3, 8, 20, 0.24)" : "0 12px 24px rgba(3, 8, 20, 0.14)",
    transform: "translateY(0)",
    transition: "border-color 120ms ease, background 120ms ease, box-shadow 120ms ease, transform 120ms ease",
  };
}

function pageButtonStyle(enabled: boolean): React.CSSProperties {
  return {
    flex: 1,
    border: `1px solid ${enabled ? "rgba(120, 145, 178, 0.20)" : "rgba(120, 145, 178, 0.12)"}`,
    background: enabled ? "linear-gradient(180deg, rgba(16, 26, 44, 0.90), rgba(11, 17, 29, 0.98))" : "rgba(11, 17, 29, 0.72)",
    color: "var(--text)",
    borderRadius: 14,
    padding: "10px 12px",
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: enabled ? "pointer" : "not-allowed",
    opacity: enabled ? 1 : 0.45,
  };
}

function statusTone(status: AssistantSessionListItem["status"]) {
  switch (status) {
    case "completed":
      return "success";
    case "processing":
      return "warning";
    case "failed":
      return "danger";
    case "draft":
    default:
      return "neutral";
  }
}

function modeLabel(mode: AssistantSessionListItem["mode"]) {
  return mode === "alert_analysis" ? "Alert Analysis" : "Incident Correlation";
}

function formatTimestamp(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
  }).format(date);
}

const searchHeaderStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  gap: 12,
  alignItems: "flex-end",
  flexWrap: "wrap",
};

const eyebrowStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.16em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
  marginBottom: 6,
};

const titleStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: 18,
  fontWeight: 700,
  color: "var(--text-strong)",
  letterSpacing: "-0.02em",
};

const metaStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-dim)",
  letterSpacing: "0.04em",
};

const searchInputStyle: React.CSSProperties = {
  width: "100%",
  borderRadius: 14,
  border: "1px solid rgba(120, 145, 178, 0.18)",
  background: "linear-gradient(180deg, rgba(16, 26, 44, 0.94), rgba(11, 17, 29, 0.98))",
  color: "var(--text-strong)",
  padding: "12px 14px",
  fontSize: 13,
  outline: "none",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
};

const sessionTitleStyle = (active: boolean): React.CSSProperties => ({
  fontSize: 14,
  fontWeight: 700,
  color: active ? "var(--text-strong)" : "var(--text)",
  lineHeight: 1.35,
  wordBreak: "break-word",
});

const sessionSublineStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  fontSize: 11,
  color: "var(--text-dim)",
  marginTop: 6,
  flexWrap: "wrap",
};

const separatorStyle: React.CSSProperties = {
  color: "rgba(120, 145, 178, 0.45)",
};

const pillRowStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 8,
  marginTop: 12,
};

const emptyStateStyle: React.CSSProperties = {
  border: "1px dashed rgba(120, 145, 178, 0.18)",
  borderRadius: 16,
  padding: 14,
  color: "var(--text-dim)",
  fontSize: 12,
  lineHeight: 1.7,
  background: "rgba(9, 14, 24, 0.56)",
};
