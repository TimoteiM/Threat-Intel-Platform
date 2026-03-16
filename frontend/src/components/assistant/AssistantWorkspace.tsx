"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import * as api from "@/lib/api";
import type { AssistantEntry, AssistantMode, AssistantSessionDetail, AssistantSessionListItem } from "@/lib/types";
import AssistantSessionList from "./AssistantSessionList";
import AssistantEditor from "./AssistantEditor";
import AssistantResult from "./AssistantResult";

function newEntry(index: number): AssistantEntry {
  return {
    id: `draft-${index}`,
    session_id: "",
    entry_index: index,
    entry_label: `entry-${index + 1}`,
    raw_text: "",
    sanitized_text: "",
    token_map_json: {},
    created_at: new Date().toISOString(),
  };
}

export default function AssistantWorkspace() {
  const searchParams = useSearchParams();
  const requestedSessionId = searchParams.get("session");
  const [sessions, setSessions] = useState<AssistantSessionListItem[]>([]);
  const [activeSession, setActiveSession] = useState<AssistantSessionDetail | null>(null);
  const [mode, setMode] = useState<AssistantMode>("alert_analysis");
  const [title, setTitle] = useState("");
  const [entries, setEntries] = useState<AssistantEntry[]>([newEntry(0)]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listAssistantSessions({ limit: 20, offset: 0 })
      .then((data) => setSessions(data.items || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!requestedSessionId) return;
    void loadSession(requestedSessionId);
  }, [requestedSessionId]);

  async function loadSession(sessionId: string) {
    setLoading(true);
    try {
      const session = await api.getAssistantSession(sessionId);
      setActiveSession(session);
      setMode(session.mode);
      setTitle(session.title);
      setEntries(
        session.entries?.length
          ? session.entries
          : [newEntry(0)],
      );
    } finally {
      setLoading(false);
    }
  }

  const canRun = useMemo(
    () => entries.some((entry) => entry.raw_text.trim().length > 0),
    [entries],
  );

  async function handleCreateAndRun() {
    setLoading(true);
    try {
      const session = await api.createAssistantSession({ title, mode });
      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index];
        if (!entry.raw_text.trim()) continue;
        await api.addAssistantEntry(session.id, {
          text: entry.raw_text,
          entry_label: entry.entry_label,
          entry_index: index,
        });
      }
      const completed = await api.runAssistantSession(session.id, { model: "gpt-5-mini" });
      setActiveSession(completed);
      setSessions((prev) => [completed, ...prev.filter((item) => item.id !== completed.id)]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ paddingTop: 20, paddingBottom: 40 }}>
      <div style={{ fontSize: 20, fontWeight: 800, marginBottom: 16, color: "var(--text)" }}>
        AI Assistant
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "280px 1fr 1fr", gap: 16, alignItems: "start" }}>
        <div style={panelStyle}>
          <div style={sectionTitleStyle}>Recent Sessions</div>
          <AssistantSessionList
            sessions={sessions}
            activeSessionId={activeSession?.id}
            onSelect={(sessionId) => void loadSession(sessionId)}
          />
        </div>
        <div style={panelStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={sectionTitleStyle}>Workspace</div>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" onClick={() => setMode("alert_analysis")} style={modeButton(mode === "alert_analysis")}>
                Alert Analysis
              </button>
              <button type="button" onClick={() => setMode("incident_correlation")} style={modeButton(mode === "incident_correlation")}>
                Incident Correlation
              </button>
            </div>
          </div>
          <AssistantEditor
            mode={mode}
            title={title}
            entries={entries}
            onTitleChange={setTitle}
            onEntryChange={(index, value) =>
              setEntries((prev) => prev.map((entry, entryIndex) => (
                entryIndex === index ? { ...entry, raw_text: value } : entry
              )))
            }
            onAddEntry={() => setEntries((prev) => [...prev, newEntry(prev.length)])}
          />
          <div style={{ marginTop: 14 }}>
            <button
              type="button"
              onClick={() => void handleCreateAndRun()}
              disabled={!canRun || loading}
              style={{
                ...modeButton(true),
                opacity: !canRun || loading ? 0.5 : 1,
                cursor: !canRun || loading ? "not-allowed" : "pointer",
              }}
            >
              {loading ? "Running..." : "Create and Run"}
            </button>
          </div>
        </div>
        <div style={panelStyle}>
          <div style={sectionTitleStyle}>Assistant Output</div>
          <AssistantResult session={activeSession} />
        </div>
      </div>
    </div>
  );
}

const panelStyle: React.CSSProperties = {
  border: "1px solid var(--border)",
  borderRadius: 14,
  background: "rgba(15, 23, 42, 0.7)",
  padding: 16,
};

const sectionTitleStyle: React.CSSProperties = {
  fontSize: 13,
  color: "var(--text-dim)",
  marginBottom: 12,
  textTransform: "uppercase",
  letterSpacing: "0.08em",
};

function modeButton(active: boolean): React.CSSProperties {
  return {
    border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
    background: active ? "rgba(59,130,246,0.14)" : "var(--panel)",
    color: "var(--text)",
    borderRadius: 10,
    padding: "8px 12px",
    fontSize: 12,
  };
}
