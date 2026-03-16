"use client";

import type { AssistantSessionListItem } from "@/lib/types";

export default function AssistantSessionList({
  sessions,
  activeSessionId,
  onSelect,
}: {
  sessions: AssistantSessionListItem[];
  activeSessionId?: string;
  onSelect: (sessionId: string) => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
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
    </div>
  );
}
