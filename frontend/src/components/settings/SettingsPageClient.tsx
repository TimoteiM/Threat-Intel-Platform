"use client";

import React from "react";

import { getAPIHealth } from "@/lib/api";
import { APP_VERSION } from "@/lib/constants";
import type { APIHealthResponse, APIProviderHealth, APIHealthStatus, ThemePreference, ListDensity } from "@/lib/types";
import { useSettingsPreferences } from "@/components/settings/SettingsPreferencesProvider";

const STATUS_STYLES: Record<APIHealthStatus, { label: string; color: string; bg: string }> = {
  healthy: { label: "Healthy", color: "#38d9a9", bg: "rgba(56,217,169,0.12)" },
  low_quota: { label: "Low Quota", color: "#fbbf24", bg: "rgba(251,191,36,0.14)" },
  rate_limited: { label: "Rate Limited", color: "#fb7185", bg: "rgba(251,113,133,0.14)" },
  unavailable: { label: "Unavailable", color: "#fb923c", bg: "rgba(251,146,60,0.14)" },
  not_configured: { label: "Not Configured", color: "#94a3b8", bg: "rgba(148,163,184,0.14)" },
  unsupported: { label: "Unsupported", color: "#94a3b8", bg: "rgba(148,163,184,0.14)" },
};

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string; description: string }> = [
  { value: "dark", label: "Dark", description: "Keep the current analyst-focused dark shell." },
  { value: "light", label: "Light", description: "Switch to a brighter daylight workspace." },
  { value: "system", label: "System", description: "Follow your operating system preference." },
];

const DENSITY_OPTIONS: Array<{ value: ListDensity; label: string }> = [
  { value: "comfortable", label: "Comfortable" },
  { value: "compact", label: "Compact" },
];

function formatQuota(provider: APIProviderHealth): string {
  if (provider.remaining == null && provider.limit == null) {
    return "Telemetry unavailable";
  }
  if (provider.remaining != null && provider.limit != null) {
    return `${provider.remaining} / ${provider.limit} ${provider.unit || ""}`.trim();
  }
  if (provider.remaining != null) {
    return `${provider.remaining} ${provider.unit || "remaining"}`.trim();
  }
  return `${provider.limit} ${provider.unit || "limit"}`.trim();
}

function formatDateTime(value?: string | null): string {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toLocaleString();
}

export default function SettingsPageClient() {
  const { settings, effectiveTheme, setTheme, updateSettings } = useSettingsPreferences();
  const [health, setHealth] = React.useState<APIHealthResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [refreshing, setRefreshing] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const loadHealth = React.useCallback(async (silent = false) => {
    if (silent) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const next = await getAPIHealth();
      setHealth(next);
      setError(null);
    } catch (err: any) {
      setError(err?.message || "Failed to load API health");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    void loadHealth(false);
  }, [loadHealth]);

  React.useEffect(() => {
    if (!settings.apiHealthAutoRefresh) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadHealth(true);
    }, 60000);
    return () => window.clearInterval(timer);
  }, [loadHealth, settings.apiHealthAutoRefresh]);

  const generatedAt = health?.generated_at ? formatDateTime(health.generated_at) : "N/A";
  const backendTarget = process.env.NEXT_PUBLIC_BACKEND_URL || "Proxy /api";

  return (
    <div style={{ display: "grid", gap: 22, paddingBottom: 48 }}>
      <section
        className="animate-in"
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          padding: "24px 26px",
          boxShadow: "var(--shadow-sm)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", gap: 18, flexWrap: "wrap" }}>
          <div style={{ maxWidth: 700 }}>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "4px 10px",
                borderRadius: 999,
                background: "var(--accent-glow)",
                color: "var(--accent)",
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                marginBottom: 12,
              }}
            >
              Settings
            </div>
            <h1
              style={{
                fontFamily: "var(--font-display)",
                fontSize: 30,
                lineHeight: 1.1,
                color: "var(--text)",
                marginBottom: 10,
              }}
            >
              Platform settings and API health
            </h1>
            <p style={{ color: "var(--text-dim)", fontSize: 14, maxWidth: 620 }}>
              Monitor external quota pressure, switch the workspace theme, and tune browser-local analyst defaults without exposing secrets or changing shared server state.
            </p>
          </div>

          <div
            style={{
              minWidth: 240,
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              padding: "14px 16px",
              display: "grid",
              gap: 8,
            }}
          >
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--text-muted)" }}>
              Current profile
            </div>
            <div style={{ fontSize: 14, color: "var(--text)" }}>
              Effective theme: <strong>{effectiveTheme}</strong>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
              Last API refresh: {generatedAt}
            </div>
          </div>
        </div>
      </section>

      <SectionCard title="Appearance" description="Choose how the application should render on this browser.">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
          {THEME_OPTIONS.map((option) => {
            const active = settings.theme === option.value;
            return (
              <button
                key={option.value}
                onClick={() => setTheme(option.value)}
                style={{
                  textAlign: "left",
                  padding: "16px 16px 14px",
                  background: active ? "var(--accent-glow)" : "var(--bg-elevated)",
                  border: active ? "1px solid var(--accent)" : "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  cursor: "pointer",
                  color: "var(--text)",
                }}
              >
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>{option.label}</div>
                <div style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.5 }}>{option.description}</div>
              </button>
            );
          })}
        </div>
      </SectionCard>

      <SectionCard
        title="API Health"
        description="Read-only quota visibility for the providers that power enrichment and verdicting."
        action={(
          <button
            onClick={() => void loadHealth(true)}
            disabled={refreshing}
            style={buttonStyle()}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        )}
      >
        {loading ? (
          <div style={{ color: "var(--text-dim)", fontSize: 14 }}>Loading provider health…</div>
        ) : error ? (
          <div
            style={{
              padding: "14px 16px",
              borderRadius: "var(--radius)",
              border: "1px solid rgba(251,113,133,0.22)",
              background: "rgba(251,113,133,0.1)",
              color: "var(--text)",
            }}
          >
            {error}
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14 }}>
            {(health?.providers || []).map((provider) => {
              const status = STATUS_STYLES[provider.status];
              return (
                <article
                  key={provider.provider}
                  className="card-hover"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius)",
                    padding: "16px 16px 14px",
                    display: "grid",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text)" }}>{provider.display_name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                        {provider.provider}
                      </div>
                    </div>
                    <span
                      style={{
                        padding: "5px 10px",
                        borderRadius: 999,
                        background: status.bg,
                        color: status.color,
                        fontSize: 11,
                        fontWeight: 700,
                        letterSpacing: "0.05em",
                        textTransform: "uppercase",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {status.label}
                    </span>
                  </div>

                  <div style={{ fontSize: 22, fontWeight: 800, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                    {formatQuota(provider)}
                  </div>

                  <div style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-dim)" }}>
                    <InfoRow label="Configured" value={provider.configured ? "Yes" : "No"} />
                    <InfoRow label="Last checked" value={formatDateTime(provider.last_checked_at)} />
                    <InfoRow label="Reset at" value={formatDateTime(provider.reset_at)} />
                    <InfoRow label="Source" value={provider.source || "N/A"} />
                  </div>

                  {provider.error ? (
                    <div style={{ fontSize: 12, color: "#fb923c", lineHeight: 1.5 }}>{provider.error}</div>
                  ) : null}
                </article>
              );
            })}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Workspace" description="These preferences are saved only in this browser.">
        <div style={{ display: "grid", gap: 18 }}>
          <ToggleRow
            label="Investigation auto-refresh"
            description="Allow live investigation pages to keep polling for completion details automatically."
            checked={settings.investigationAutoRefresh}
            onChange={(checked) => updateSettings({ investigationAutoRefresh: checked })}
          />
          <ToggleRow
            label="Duplicate investigation warning"
            description="Warn before opening a new case for an observable that already has a concluded result."
            checked={settings.duplicateCheckWarning}
            onChange={(checked) => updateSettings({ duplicateCheckWarning: checked })}
          />
          <ToggleRow
            label="API health auto-refresh"
            description="Refresh provider quota data every minute while this page stays open."
            checked={settings.apiHealthAutoRefresh}
            onChange={(checked) => updateSettings({ apiHealthAutoRefresh: checked })}
          />

          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>Investigation list density</div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {DENSITY_OPTIONS.map((option) => {
                const active = settings.listDensity === option.value;
                return (
                  <button
                    key={option.value}
                    onClick={() => updateSettings({ listDensity: option.value })}
                    style={{
                      ...buttonStyle(),
                      background: active ? "var(--accent-glow)" : "var(--bg-elevated)",
                      border: active ? "1px solid var(--accent)" : "1px solid var(--border)",
                      color: active ? "var(--accent)" : "var(--text-dim)",
                    }}
                  >
                    {option.label}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="System Info" description="Helpful runtime details for this browser session.">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
          <SystemTile label="App version" value={APP_VERSION} />
          <SystemTile label="Backend target" value={backendTarget} />
          <SystemTile label="Theme preference" value={settings.theme} />
          <SystemTile label="API health snapshot" value={generatedAt} />
        </div>
      </SectionCard>
    </div>
  );
}

function SectionCard({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section
      className="animate-fade-up"
      style={{
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        padding: "20px 22px",
        boxShadow: "var(--shadow-sm)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 16, alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: 20, color: "var(--text)", marginBottom: 6 }}>{title}</h2>
          <p style={{ color: "var(--text-dim)", fontSize: 13, maxWidth: 640 }}>{description}</p>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
      <span style={{ color: "var(--text-muted)" }}>{label}</span>
      <span style={{ color: "var(--text-secondary)", textAlign: "right" }}>{value}</span>
    </div>
  );
}

function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: 16,
        padding: "14px 16px",
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        cursor: "pointer",
      }}
    >
      <div>
        <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", marginBottom: 4 }}>{label}</div>
        <div style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.5 }}>{description}</div>
      </div>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
    </label>
  );
}

function SystemTile({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        padding: "14px 16px",
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ fontSize: 14, color: "var(--text)", lineHeight: 1.5 }}>{value}</div>
    </div>
  );
}

function buttonStyle(): React.CSSProperties {
  return {
    padding: "10px 14px",
    background: "var(--bg-elevated)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius)",
    color: "var(--text)",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: 12,
  };
}
