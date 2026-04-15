"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import * as api from "@/lib/api";
import type { AssistantEntry, AssistantMode, AssistantSessionDetail, AssistantSessionListItem } from "@/lib/types";
import AssistantSessionList from "./AssistantSessionList";
import AssistantEditor from "./AssistantEditor";
import AssistantResult from "./AssistantResult";
import ConsoleModule from "@/components/ui/ConsoleModule";
import MetadataGrid from "@/components/ui/MetadataGrid";
import PageHero from "@/components/ui/PageHero";
import SignalCard from "@/components/ui/SignalCard";
import StatusPill from "@/components/ui/StatusPill";

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
  const pageSize = 10;

  const [sessions, setSessions] = useState<AssistantSessionListItem[]>([]);
  const [sessionSearch, setSessionSearch] = useState("");
  const [appliedSessionSearch, setAppliedSessionSearch] = useState("");
  const [sessionOffset, setSessionOffset] = useState(0);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [activeSession, setActiveSession] = useState<AssistantSessionDetail | null>(null);
  const [mode, setMode] = useState<AssistantMode>("alert_analysis");
  const [title, setTitle] = useState("");
  const [entries, setEntries] = useState<AssistantEntry[]>([newEntry(0)]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      setAppliedSessionSearch(sessionSearch.trim());
      setSessionOffset(0);
    }, 250);
    return () => window.clearTimeout(timeoutId);
  }, [sessionSearch]);

  useEffect(() => {
    let cancelled = false;
    setSessionsLoading(true);
    api.listAssistantSessions({
      limit: pageSize,
      offset: sessionOffset,
      search: appliedSessionSearch,
    })
      .then((data) => {
        if (cancelled) return;
        setSessions(data.items || []);
        setSessionTotal(data.total || 0);
      })
      .catch(() => {
        if (cancelled) return;
        setSessions([]);
        setSessionTotal(0);
      })
      .finally(() => {
        if (!cancelled) setSessionsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [appliedSessionSearch, sessionOffset, pageSize]);

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
      setEntries(session.entries?.length ? session.entries : [newEntry(0)]);
    } finally {
      setLoading(false);
    }
  }

  const canRun = useMemo(
    () => entries.some((entry) => entry.raw_text.trim().length > 0),
    [entries],
  );

  const visibleEntryCount = useMemo(
    () => entries.filter((entry) => entry.raw_text.trim().length > 0).length,
    [entries],
  );

  const sessionStateLabel = activeSession?.status ? capitalize(activeSession.status) : "No session selected";
  const modeLabel = mode === "alert_analysis" ? "Alert analysis" : "Incident correlation";
  const selectedTitle = activeSession?.title || (title.trim() ? title.trim() : "Draft session");
  const workspaceTone = loading ? "warning" : canRun ? "success" : "neutral";

  async function handleCreateAndRun() {
    setLoading(true);
    try {
      const session = await api.createAssistantSession({
        mode,
        ...(title.trim() ? { title: title.trim() } : {}),
      });
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
      setSessionSearch("");
      setAppliedSessionSearch("");
      setSessionOffset(0);
      setSessions((prev) => [completed, ...prev.filter((item) => item.id !== completed.id)].slice(0, pageSize));
      setSessionTotal((prev) => Math.max(prev + 1, 1));
    } finally {
      setLoading(false);
    }
  }

  const heroStats = useMemo(
    () => [
      <SignalCard
        key="sessions"
        label="Sessions in view"
        value={`${sessions.length}`}
        caption={sessionTotal ? `${sessionOffset + 1}-${Math.min(sessionOffset + sessions.length, sessionTotal)} of ${sessionTotal}` : "No sessions loaded yet"}
        tone="info"
        trend="flat"
        compact
      />,
      <SignalCard
        key="mode"
        label="Workspace mode"
        value={mode === "alert_analysis" ? "Alert" : "Correlation"}
        caption={modeLabel}
        tone={mode === "alert_analysis" ? "warning" : "success"}
        trend={mode === "alert_analysis" ? "flat" : "up"}
        compact
      />,
      <SignalCard
        key="ready"
        label="Run readiness"
        value={canRun ? "Ready" : "Waiting"}
        caption={loading ? "Processing session request" : `${visibleEntryCount} populated entr${visibleEntryCount === 1 ? "y" : "ies"}`}
        tone={canRun ? "success" : "neutral"}
        trend={loading ? "flat" : canRun ? "up" : "down"}
        compact
      />,
    ],
    [canRun, loading, mode, modeLabel, sessionOffset, sessionTotal, sessions.length, visibleEntryCount],
  );

  const heroBadges = (
    <>
      <StatusPill tone={workspaceTone} outline mono>
        {loading ? "running" : canRun ? "ready" : "draft"}
      </StatusPill>
      <StatusPill tone={mode === "alert_analysis" ? "warning" : "success"} outline>
        {modeLabel}
      </StatusPill>
      <StatusPill tone={sessionsLoading ? "warning" : "info"} outline>
        {sessionsLoading ? "Refreshing sessions" : "Session rail live"}
      </StatusPill>
    </>
  );

  return (
    <div style={workspaceStyle}>
      <PageHero
        eyebrow="Threat Analyst Console"
        title="AI Assistant"
        description="Draft investigations, switch between alert analysis and correlation workflows, and review generated intelligence without leaving the console."
        status={
          <StatusPill tone={workspaceTone} mono>
            {loading ? "Processing" : canRun ? "Ready to run" : "Draft mode"}
          </StatusPill>
        }
        badges={heroBadges}
        actions={
          <button
            type="button"
            onClick={() => void handleCreateAndRun()}
            disabled={!canRun || loading}
            style={runButtonStyle(!canRun || loading)}
          >
            {loading ? "Running..." : "Create and Run"}
          </button>
        }
        stats={heroStats}
      />

      <div style={railLayoutStyle}>
        <ConsoleModule
          eyebrow="Session rail"
          title="Recent Sessions"
          description="Search past assistant runs, page through history, and reopen any session in the workspace."
          tone="info"
          variant="solid"
          compact
          actions={<StatusPill tone="info" outline>{`${sessionTotal} total`}</StatusPill>}
          footer={
            <MetadataGrid
              compact
              columns={3}
              items={[
                { label: "Search", value: appliedSessionSearch || "All sessions", mono: true, tone: "info" },
                { label: "Page", value: `${Math.floor(sessionOffset / pageSize) + 1}`, tone: "neutral" },
                { label: "Loaded", value: sessionsLoading ? "Refreshing" : "Stable", tone: sessionsLoading ? "warning" : "success" },
              ]}
            />
          }
          style={railModuleStyle}
        >
          <AssistantSessionList
            sessions={sessions}
            activeSessionId={activeSession?.id}
            searchValue={sessionSearch}
            onSearchChange={setSessionSearch}
            offset={sessionOffset}
            limit={pageSize}
            total={sessionTotal}
            loading={sessionsLoading}
            onPreviousPage={() => setSessionOffset((prev) => Math.max(prev - pageSize, 0))}
            onNextPage={() => setSessionOffset((prev) => prev + pageSize)}
            onSelect={(sessionId) => void loadSession(sessionId)}
          />
        </ConsoleModule>

        <ConsoleModule
          eyebrow="Operational workspace"
          title="Compose Analysis"
          description="Keep the current prompt and entry flow, but frame it like an analyst workstation with clear state and mode controls."
          tone="info"
          variant="solid"
          compact
          actions={
            <div style={modeSwitcherStyle}>
              <button type="button" onClick={() => setMode("alert_analysis")} style={modeButtonStyle(mode === "alert_analysis")}>
                <StatusPill tone={mode === "alert_analysis" ? "warning" : "neutral"} size="sm" outline>
                  Alert analysis
                </StatusPill>
              </button>
              <button
                type="button"
                onClick={() => setMode("incident_correlation")}
                style={modeButtonStyle(mode === "incident_correlation")}
              >
                <StatusPill tone={mode === "incident_correlation" ? "success" : "neutral"} size="sm" outline>
                  Incident correlation
                </StatusPill>
              </button>
            </div>
          }
          footer={
            <MetadataGrid
              compact
              items={[
                { label: "Current session", value: selectedTitle, mono: true, tone: "info", span: 2 },
                { label: "Status", value: sessionStateLabel, tone: activeSession ? "success" : "neutral" },
                { label: "Entries", value: `${visibleEntryCount}/${entries.length}`, tone: canRun ? "success" : "warning" },
              ]}
            />
          }
          style={centerModuleStyle}
        >
          <div style={workspaceBodyStyle}>
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
          </div>
        </ConsoleModule>

        <ConsoleModule
          eyebrow="Analyst output"
          title="Generated Intelligence"
          description="Results are still produced exactly as before, but the shell now reads like a premium review surface."
          tone={workspaceTone}
          variant="solid"
          compact
          actions={
            <StatusPill tone={workspaceTone} outline>
              {loading ? "Running" : activeSession ? "Loaded" : "Awaiting run"}
            </StatusPill>
          }
          footer={
            <MetadataGrid
              compact
              columns={2}
              items={[
                { label: "Mode", value: modeLabel, tone: mode === "alert_analysis" ? "warning" : "success" },
                { label: "Readiness", value: canRun ? "Prepared" : "Idle", tone: canRun ? "success" : "neutral" },
              ]}
            />
          }
          style={railModuleStyle}
        >
          <AssistantResult session={activeSession} />
        </ConsoleModule>
      </div>
    </div>
  );
}

const workspaceStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: "var(--shell-max-width)",
  margin: "0 auto",
  padding: "20px 0 40px",
  display: "grid",
  gap: 18,
};

const railLayoutStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "stretch",
  flexWrap: "wrap",
  gap: 16,
};

const railModuleStyle: React.CSSProperties = {
  flex: "1 1 320px",
  minWidth: 300,
};

const centerModuleStyle: React.CSSProperties = {
  flex: "1.65 1 520px",
  minWidth: 320,
};

const workspaceBodyStyle: React.CSSProperties = {
  display: "grid",
  gap: 16,
};

const modeSwitcherStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 10,
  alignItems: "center",
  justifyContent: "flex-end",
};

function modeButtonStyle(active: boolean): React.CSSProperties {
  return {
    appearance: "none",
    border: "none",
    background: "transparent",
    padding: 0,
    cursor: "pointer",
    borderRadius: 999,
    outline: "none",
    boxShadow: active ? "0 0 0 1px rgba(102, 168, 255, 0.26)" : "none",
  };
}

function runButtonStyle(disabled: boolean): React.CSSProperties {
  return {
    appearance: "none",
    border: "1px solid rgba(102, 168, 255, 0.34)",
    background: disabled
      ? "rgba(15, 23, 42, 0.7)"
      : "linear-gradient(180deg, rgba(102, 168, 255, 0.24), rgba(59, 130, 246, 0.16))",
    color: "var(--text-strong)",
    borderRadius: 999,
    padding: "10px 14px",
    fontSize: 12,
    fontWeight: 800,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.6 : 1,
    boxShadow: disabled ? "none" : "0 16px 34px rgba(3, 8, 20, 0.24)",
  };
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
