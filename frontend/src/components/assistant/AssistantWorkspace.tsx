"use client";

import React, { useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import * as api from "@/lib/api";
import type { AssistantEntry, AssistantMode, AssistantSessionDetail, AssistantSessionListItem } from "@/lib/types";
import AssistantSessionList from "./AssistantSessionList";
import AssistantEditor from "./AssistantEditor";
import AssistantResult from "./AssistantResult";
import AssistantDailyActivity from "./AssistantDailyActivity";
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
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const requestedSessionId = searchParams.get("session");
  const pageSize = 5;

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
  const [activityRefreshKey, setActivityRefreshKey] = useState(0);

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

  function resetWorkspace() {
    setActiveSession(null);
    setMode("alert_analysis");
    setTitle("");
    setEntries([newEntry(0)]);
    if (requestedSessionId) {
      router.replace(pathname, { scroll: false });
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
      const completed = await api.runAssistantSession(session.id);
      setActiveSession(completed);
      setActivityRefreshKey((value) => value + 1);
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
        stats={heroStats}
      />

      <AssistantDailyActivity refreshKey={activityRefreshKey} />

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
              columns={1}
              style={railFooterGridStyle}
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

        <div style={mainColumnStyle}>
          <div style={workspaceBodyStyle}>
            <div style={modeSwitcherShellStyle}>
              <div style={{ display: "grid", gap: 6, minWidth: 0 }}>
                <div style={modeLabelStyle}>Compose Analysis</div>
                <div style={modeHelperStyle}>
                  Keep the current prompt flow, switch modes quickly, and write directly into the alert input below.
                </div>
              </div>
              <div style={modeSwitcherStyle}>
                <button
                  type="button"
                  onClick={() => setMode("alert_analysis")}
                  style={modeButtonStyle(mode === "alert_analysis", "warning")}
                >
                  <span style={modeButtonLabelStyle(mode === "alert_analysis")}>Alert Analysis</span>
                </button>
                <button
                  type="button"
                  onClick={() => setMode("incident_correlation")}
                  style={modeButtonStyle(mode === "incident_correlation", "success")}
                >
                  <span style={modeButtonLabelStyle(mode === "incident_correlation")}>Incident Correlation</span>
                </button>
              </div>
            </div>

            <MetadataGrid
              compact
              items={[
                { label: "Current session", value: selectedTitle, mono: true, tone: "info", span: 2 },
                { label: "Status", value: sessionStateLabel, tone: activeSession ? "success" : "neutral" },
                { label: "Entries", value: `${visibleEntryCount}/${entries.length}`, tone: canRun ? "success" : "warning" },
              ]}
            />

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

            <div style={runRowStyle}>
              <div style={runPrimaryStyle}>
                <button
                  type="button"
                  onClick={() => void handleCreateAndRun()}
                  disabled={!canRun || loading}
                  style={runButtonStyle(!canRun || loading)}
                >
                  {loading ? "Running..." : "Create and Run"}
                </button>
                {!canRun && !loading && (
                  <span style={runHintStyle}>Add alert text above to enable</span>
                )}
              </div>
              {activeSession ? (
                <button
                  type="button"
                  onClick={resetWorkspace}
                  disabled={loading}
                  style={secondaryButtonStyle(loading)}
                >
                  New log analysis
                </button>
              ) : null}
            </div>
          </div>

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
          >
            <AssistantResult session={activeSession} />
          </ConsoleModule>
        </div>
      </div>
    </div>
  );
}

const workspaceStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: "none",
  margin: "0 auto",
  padding: "20px 18px 40px",
  display: "grid",
  gap: 18,
};

const railLayoutStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "220px minmax(0, 1fr)",
  alignItems: "start",
  gap: 16,
};

const railModuleStyle: React.CSSProperties = {
  width: "100%",
  minWidth: 0,
};

const railFooterGridStyle: React.CSSProperties = {
  gap: 8,
};

const mainColumnStyle: React.CSSProperties = {
  width: "100%",
  minWidth: 0,
  display: "grid",
  gap: 16,
  alignContent: "start",
};

const workspaceBodyStyle: React.CSSProperties = {
  display: "grid",
  gap: 16,
};

const runRowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 14,
  flexWrap: "wrap",
};

const runPrimaryStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 14,
  flexWrap: "wrap",
};

const runHintStyle: React.CSSProperties = {
  fontSize: 12,
  color: "var(--text-dim)",
  fontStyle: "italic",
};

const modeSwitcherShellStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 14,
  padding: "4px 2px 2px",
};

const modeLabelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-dim)",
};

const modeHelperStyle: React.CSSProperties = {
  color: "var(--text-secondary)",
  fontSize: 13,
  lineHeight: 1.7,
  maxWidth: 520,
};

const modeSwitcherStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "flex-end",
  padding: 6,
  borderRadius: 18,
  background: "var(--panel-card-bg)",
  border: "1px solid var(--panel-divider-strong)",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.04), var(--panel-shadow-soft)",
};

function modeButtonStyle(active: boolean, tone: "warning" | "success"): React.CSSProperties {
  const palette = tone === "warning"
    ? {
        background: "linear-gradient(180deg, rgba(251, 191, 36, 0.2), rgba(245, 158, 11, 0.12))",
        border: "rgba(251, 191, 36, 0.34)",
        shadow: "0 16px 28px rgba(245, 158, 11, 0.18)",
        color: "#fde68a",
      }
    : {
        background: "linear-gradient(180deg, rgba(56, 217, 169, 0.18), rgba(16, 185, 129, 0.12))",
        border: "rgba(56, 217, 169, 0.3)",
        shadow: "0 16px 28px rgba(16, 185, 129, 0.16)",
        color: "#9bf0d8",
      };

  return {
    appearance: "none",
    border: `1px solid ${active ? palette.border : "transparent"}`,
    background: active ? palette.background : "transparent",
    padding: "14px 20px",
    cursor: "pointer",
    borderRadius: 14,
    outline: "none",
    minWidth: 200,
    minHeight: 56,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    textAlign: "center",
    transition: "background 160ms ease, border-color 160ms ease, box-shadow 160ms ease, transform 160ms ease",
    boxShadow: active ? palette.shadow : "none",
    transform: active ? "translateY(-1px)" : "none",
    color: active ? palette.color : "var(--text-secondary)",
  };
}

function modeButtonLabelStyle(active: boolean): React.CSSProperties {
  return {
    fontSize: active ? 13 : 12,
    fontWeight: active ? 800 : 700,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    lineHeight: 1.2,
  };
}

function runButtonStyle(disabled: boolean): React.CSSProperties {
  return {
    appearance: "none",
    border: "1px solid rgba(102, 168, 255, 0.34)",
    background: disabled
      ? "var(--bg-elevated)"
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
    boxShadow: disabled ? "none" : "var(--panel-shadow-card)",
  };
}

function secondaryButtonStyle(disabled: boolean): React.CSSProperties {
  return {
    appearance: "none",
    border: "1px solid rgba(120, 145, 178, 0.24)",
    background: disabled
      ? "var(--bg-elevated)"
      : "var(--panel-card-bg)",
    color: "var(--text-secondary)",
    borderRadius: 999,
    padding: "10px 14px",
    fontSize: 12,
    fontWeight: 800,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.6 : 1,
    marginLeft: "auto",
  };
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
