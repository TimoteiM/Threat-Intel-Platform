"use client";

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
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <input
        type="search"
        value={searchValue}
        onChange={(event) => onSearchChange(event.target.value)}
        placeholder="Search title or log content"
        style={{
          width: "100%",
          borderRadius: 10,
          border: "1px solid var(--border)",
          background: "var(--panel)",
          color: "var(--text)",
          padding: "10px 12px",
          fontSize: 13,
        }}
      />
      <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
        {loading ? "Loading sessions..." : `Showing ${pageStart}-${pageEnd} of ${total}`}
      </div>
      {sessions.map((session) => {
        const active = session.id === activeSessionId;
        return (
          <button
            key={session.id}
            type="button"
            onClick={() => onSelect(session.id)}
            style={{
              textAlign: "left",
              padding: 12,
              borderRadius: 10,
              border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
              background: active ? "rgba(59,130,246,0.12)" : "var(--panel)",
              color: "var(--text)",
              cursor: "pointer",
            }}
          >
            <div style={{ fontSize: 13, fontWeight: 700 }}>{session.title}</div>
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
              {session.mode} · {session.status}
            </div>
          </button>
        );
      })}
      {!loading && sessions.length === 0 ? (
        <div
          style={{
            border: "1px dashed var(--border)",
            borderRadius: 10,
            padding: 12,
            color: "var(--text-dim)",
            fontSize: 12,
          }}
        >
          No sessions found.
        </div>
      ) : null}
      <div style={{ display: "flex", gap: 8 }}>
        <button
          type="button"
          onClick={onPreviousPage}
          disabled={!canGoPrevious || loading}
          style={paginationButton(canGoPrevious && !loading)}
        >
          Previous
        </button>
        <button
          type="button"
          onClick={onNextPage}
          disabled={!canGoNext || loading}
          style={paginationButton(canGoNext && !loading)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

function paginationButton(enabled: boolean): React.CSSProperties {
  return {
    flex: 1,
    border: "1px solid var(--border)",
    background: "var(--panel)",
    color: "var(--text)",
    borderRadius: 10,
    padding: "8px 10px",
    fontSize: 12,
    cursor: enabled ? "pointer" : "not-allowed",
    opacity: enabled ? 1 : 0.5,
  };
}
