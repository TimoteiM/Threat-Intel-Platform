"use client";

/**
 * Integrations — which security tools each customer has, and whether they
 * are actually working.
 *
 * Two views, because they answer different questions:
 *   • the per-customer card grid — "what does this customer have?"
 *   • the cross-customer matrix  — "who has no EDR?"
 *
 * The word on screen is "customer"; the key underneath is `tenant_id`.
 * Credentials live on the tenant axis because that is the axis carrying
 * authorisation — `users.tenant_ids`, `api_keys.tenant_ids` — and a secret
 * on an axis with no access control is a cross-tenant leak by default.
 *
 * **No status here is a flag somebody set.** "Enabled" is the word that cost
 * this platform seven months: ThreatFox was enabled, configured, and
 * answering HTTP 401 on every call, and every flag said healthy. Each state
 * below is derived from a fact — whether a connector exists, whether a
 * credential is stored, and what the last real authenticated call returned.
 *
 * Secrets are write-only. The form sends them; nothing reads one back. A
 * configured credential shows as "set", never as a value, and leaving a
 * secret field blank means *unchanged* — the UI is never given the value, so
 * it cannot send it back, and treating blank as "clear" would wipe a
 * credential every time somebody edited a base URL.
 */

import React, { useCallback, useEffect, useState } from "react";

import { Button, Page, PageHeader } from "@/components/ui/Primitives";
import {
  getMe,
  hasAdminRights,
  type Me,
  configureIntegration,
  getIntegrationAudit,
  getIntegrationCatalogue,
  getIntegrationMatrix,
  getTenantIntegrations,
  removeIntegration,
  verifyIntegration,
} from "@/lib/api";

/** The five states, with what each one means to a reader.
 *
 * `configured_unverified` is the one that did not exist before and matters
 * most: a credential saved and never exercised is not a working integration,
 * and the old vocabulary had no way to say so.
 */
const STATE_META: Record<
  string,
  { label: string; color: string; bg: string; border: string; meaning: string }
> = {
  verified_ok: {
    label: "WORKING",
    color: "var(--green, #4ac97e)",
    bg: "rgba(74,201,126,0.06)",
    border: "rgba(74,201,126,0.22)",
    meaning: "A real authenticated call succeeded.",
  },
  stopped: {
    label: "STOPPED",
    color: "var(--red, #f07050)",
    bg: "rgba(240,112,80,0.10)",
    border: "rgba(240,112,80,0.45)",
    meaning:
      "This worked before and is not working now. An outage, not an absence " +
      "of configuration — the date it last produced a result is below.",
  },
  verified_failing: {
    label: "FAILING",
    color: "var(--red, #f07050)",
    bg: "rgba(240,112,80,0.06)",
    border: "rgba(240,112,80,0.22)",
    meaning: "A real authenticated call failed. The reason is below.",
  },
  configured_unverified: {
    label: "NOT VERIFIED",
    color: "var(--amber, #f0b050)",
    bg: "rgba(240,176,80,0.06)",
    border: "rgba(240,176,80,0.22)",
    meaning:
      "A credential is stored and no call has ever been made with it. Saved is not working.",
  },
  not_configured: {
    label: "NOT CONFIGURED",
    color: "var(--text-dim)",
    bg: "transparent",
    border: "var(--border)",
    meaning: "No credential is stored for this customer.",
  },
  not_implemented: {
    label: "NOT IMPLEMENTED",
    color: "var(--text-muted)",
    bg: "transparent",
    border: "var(--border)",
    meaning: "No connector in this platform supports this tool yet.",
  },
};

/** Headings for the tool categories, and the order they appear in.
 *
 * The category itself is declared on the collector
 * (`integration_category`), so this map is presentation only — and anything
 * it does not know still renders, under its own raw key as a heading. That
 * matters: a hand-kept list of categories here would silently drop a tool
 * whose category it had never heard of, which is the exact failure shape of
 * the eight registries in docs/design/silent-registries.md. Omission here is
 * a missing *heading*, never a missing card.
 */
const CATEGORY_META: Record<string, { label: string; blurb: string }> = {
  edr: {
    label: "Endpoint detection & response",
    blurb: "Agent telemetry and endpoint detections.",
  },
  firewall: {
    label: "Firewall & network",
    blurb: "Perimeter logs, blocklists and egress control.",
  },
  email: {
    label: "Email security",
    blurb: "Mail gateway verdicts and message tracing.",
  },
  siem: { label: "SIEM", blurb: "Log search and alert delivery." },
  sandbox: { label: "Sandbox", blurb: "Dynamic analysis of files and URLs." },
  intel: { label: "Threat intelligence", blurb: "Reputation and indicator feeds." },
  other: { label: "Other", blurb: "Uncategorised tools." },
};

const CATEGORY_ORDER = ["edr", "firewall", "email", "siem", "sandbox", "intel", "other"];

/** Group tools by category, keeping every tool even if its category is new.
 *
 * Returns the known categories in CATEGORY_ORDER first, then any unknown
 * category alphabetically, so a tool declaring `integration_category =
 * "casb"` gets a "casb" heading instead of disappearing.
 */
function groupByCategory(tools: any[]): Array<[string, any[]]> {
  const groups: Record<string, any[]> = {};
  for (const t of tools) {
    const key = String(t?.category || "other");
    (groups[key] ||= []).push(t);
  }
  const known = CATEGORY_ORDER.filter((c) => groups[c]?.length);
  const unknown = Object.keys(groups)
    .filter((c) => !CATEGORY_ORDER.includes(c))
    .sort();
  return [...known, ...unknown].map((c) => [c, groups[c]]);
}

function StateBadge({
  state,
  compact,
  qualifier,
}: {
  state: string;
  compact?: boolean;
  qualifier?: string | null;
}) {
  const m = STATE_META[state] ?? STATE_META.not_implemented;
  // "FAILING (api)" rather than "FAILING": a compound condition is one
  // consumer failing while another works, and an unqualified red badge
  // claims the whole integration is down.
  const label = qualifier ? `${m.label} (${qualifier})` : m.label;
  return (
    <span
      title={m.meaning}
      style={{
        display: "inline-block",
        padding: compact ? "1px 6px" : "2px 8px",
        fontSize: compact ? 9 : 10,
        fontWeight: 700,
        letterSpacing: "0.04em",
        fontFamily: "var(--font-mono)",
        color: m.color,
        background: m.bg,
        border: `1px solid ${m.border}`,
        borderRadius: 3,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

/** Turn a failed call into something an analyst can act on.
 *
 * `ApiError.message` is the response body verbatim, so the old error box
 * rendered `{"detail":"Not Found"}` — which tells a reader nothing about
 * which call failed or what to do. Worse, the 404 it was reporting came from
 * a doubled `/api` prefix in the client, and presented on screen as an empty
 * customer list: a client-side path bug that looked like "this customer has
 * no tools".
 *
 * So each message names the call, the status, and the next action — and a 404
 * says explicitly that the request never reached the endpoint, because that
 * is a deployment or client fault and never an empty result.
 */
function describeFailure(call: string, e: any): string {
  const status = Number(e?.status) || 0;
  const raw = String(e?.message || "").slice(0, 200);

  if (status === 401) {
    return `${call} failed: not signed in (401). The session has expired — reload the page and sign in again.`;
  }
  if (status === 403) {
    return `${call} failed: not permitted (403). Reading integration status is open to analysts; changing one requires an administrator.`;
  }
  if (status === 404) {
    return (
      `${call} failed: the request did not reach the API (404). ` +
      `This is a client or deployment fault, not an empty result — the ` +
      `endpoint exists and is reachable when called correctly. Check the ` +
      `API base path in src/lib/api.ts and that the frontend image is the ` +
      `current build.`
    );
  }
  if (status >= 500) {
    return `${call} failed: the API returned ${status}. Check the api container's logs; the request was well formed.${raw ? ` Server said: ${raw}` : ""}`;
  }
  if (!status) {
    return `${call} failed: no response from the API. The api container may be down or the proxy misconfigured.`;
  }
  return `${call} failed with ${status}.${raw ? ` Server said: ${raw}` : ""}`;
}

export default function IntegrationsPage() {
  const [catalogue, setCatalogue] = useState<any>(null);
  const [matrix, setMatrix] = useState<any>(null);
  const [tenantId, setTenantId] = useState<string>("");
  const [detail, setDetail] = useState<any>(null);
  const [audit, setAudit] = useState<any>(null);
  // A list, not one string: several calls run in parallel and losing all but
  // the last made a two-call failure look like one.
  const [failures, setFailures] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const [me, setMe] = useState<Me | null>(null);

  // Writes are admin-only and the API returns 403. The server is the gate;
  // this only stops the page offering an action that cannot succeed. An
  // analyst still sees every status — reading is the point of the page.
  const canWrite = hasAdminRights(me?.role);

  useEffect(() => {
    getMe()
      .then(setMe)
      // A failed /auth/me must not read as "admin". It leaves `me` null and
      // `canWrite` false, so the controls stay hidden rather than appearing
      // and failing — absence is not permission.
      .catch(() => setMe(null));
  }, []);

  const loadTop = useCallback(async () => {
    const problems: string[] = [];
    const [cat, mx] = await Promise.all([
      getIntegrationCatalogue().catch((e: any) => {
        problems.push(describeFailure("Loading the tool catalogue", e));
        return null;
      }),
      // Previously `.catch(() => null)`, which is why a failed matrix showed
      // as an empty customer list with no explanation — absence presented as
      // a measurement, on screen.
      getIntegrationMatrix().catch((e: any) => {
        problems.push(describeFailure("Loading the customer matrix", e));
        return null;
      }),
    ]);
    setFailures(problems);
    setCatalogue(cat);
    setMatrix(mx);
    if (!tenantId && mx?.tenants?.length) setTenantId(mx.tenants[0].tenant_id);
  }, [tenantId]);

  const loadTenant = useCallback(async (id: string) => {
    if (!id) return;
    const problems: string[] = [];
    const [d, a] = await Promise.all([
      getTenantIntegrations(id).catch((e: any) => {
        problems.push(describeFailure(`Loading integrations for ${id}`, e));
        return null;
      }),
      // The audit list is supplementary, but a silent failure here meant the
      // "Configuration history" section simply vanished.
      getIntegrationAudit(id).catch((e: any) => {
        problems.push(describeFailure(`Loading configuration history for ${id}`, e));
        return null;
      }),
    ]);
    setFailures(problems);
    setDetail(d);
    setAudit(a);
  }, []);

  useEffect(() => {
    void loadTop();
  }, [loadTop]);

  useEffect(() => {
    void loadTenant(tenantId);
  }, [tenantId, loadTenant]);

  async function onSave(tool: string, spec: any) {
    setBusy(tool);
    setFailures([]);
    try {
      const config: Record<string, string> = {};
      const secrets: Record<string, string> = {};
      Object.keys(spec.config_fields || {}).forEach((k) => {
        if (form[`c:${k}`]) config[k] = form[`c:${k}`];
      });
      Object.keys(spec.secret_fields || {}).forEach((k) => {
        // Blank means unchanged. The UI is never given the value, so it
        // cannot send it back, and treating blank as "clear" would wipe the
        // credential on every unrelated edit.
        if (form[`s:${k}`]) secrets[k] = form[`s:${k}`];
      });
      await configureIntegration(tenantId, tool, { config, secrets }, true);
      setEditing(null);
      setForm({});
      await Promise.all([loadTenant(tenantId), loadTop()]);
    } catch (e: any) {
      setFailures([describeFailure(`Saving ${tool}`, e)]);
    } finally {
      setBusy(null);
    }
  }

  async function onVerify(tool: string) {
    setBusy(tool);
    setFailures([]);
    try {
      await verifyIntegration(tenantId, tool);
      await Promise.all([loadTenant(tenantId), loadTop()]);
    } catch (e: any) {
      setFailures([describeFailure(`Testing the connection to ${tool}`, e)]);
    } finally {
      setBusy(null);
    }
  }

  async function onRemove(tool: string) {
    setBusy(tool);
    try {
      await removeIntegration(tenantId, tool);
      await Promise.all([loadTenant(tenantId), loadTop()]);
    } catch (e: any) {
      setFailures([describeFailure(`Removing ${tool}`, e)]);
    } finally {
      setBusy(null);
    }
  }

  const tenants: any[] = matrix?.tenants || [];
  const tools: any[] = detail?.tools || [];
  const specByTool: Record<string, any> = Object.fromEntries(
    (catalogue?.tools || []).map((t: any) => [t.tool, t])
  );

  return (
    <Page>
      <PageHeader
        title="Integrations"
        subtitle="Which security tools each customer has, and whether they are actually working."
      />

      {failures.length > 0 && (
        <div
          style={{
            padding: "10px 14px",
            marginBottom: 16,
            background: "rgba(240,112,80,0.05)",
            border: "1px solid rgba(240,112,80,0.2)",
            borderRadius: "var(--radius-sm)",
            fontSize: 12,
            color: "var(--red)",
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          {failures.map((f, i) => (
            <div key={i}>{f}</div>
          ))}
          {/* Said once, below the list: an empty page with a failed fetch is
              not a customer with no tools. The old box could not make that
              distinction because it rendered the response body verbatim. */}
          <div style={{ color: "var(--text-muted)", fontSize: 11 }}>
            Nothing below reflects real status while a call above is failing.
          </div>
        </div>
      )}

      {/* ── the matrix: who has no EDR ───────────────────────────────── */}
      <section style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>
          All customers
        </h2>
        <div style={{ overflowX: "auto" }}>
          <table style={{ borderCollapse: "collapse", fontSize: 12, minWidth: 420 }}>
            <thead>
              <tr>
                <th style={thStyle}>Customer</th>
                {(matrix?.tools || []).map((t: any) => (
                  <th key={t.tool} style={thStyle}>
                    {t.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tenants.map((t: any) => (
                <tr key={t.tenant_id}>
                  <td style={tdStyle}>
                    <button
                      onClick={() => setTenantId(t.tenant_id)}
                      style={{
                        background: "none",
                        border: "none",
                        padding: 0,
                        cursor: "pointer",
                        color:
                          t.tenant_id === tenantId ? "var(--accent)" : "var(--text)",
                        fontWeight: t.tenant_id === tenantId ? 600 : 400,
                        fontSize: 12,
                      }}
                    >
                      {t.name}{" "}
                      <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {t.tenant_id}
                      </span>
                    </button>
                  </td>
                  {(matrix?.tools || []).map((tool: any) => (
                    <td key={tool.tool} style={tdStyle}>
                      <StateBadge
                        state={matrix?.cells?.[t.tenant_id]?.[tool.tool]?.overall}
                        compact
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {matrix?.tenants_without_any_working?.length > 0 && (
          <div style={{ marginTop: 10, fontSize: 11, color: "var(--red)" }}>
            No working integration:{" "}
            <span style={{ fontFamily: "var(--font-mono)" }}>
              {matrix.tenants_without_any_working.join(", ")}
            </span>
          </div>
        )}
      </section>

      {/* ── the per-customer card grid ───────────────────────────────── */}
      <section>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            marginBottom: 12,
          }}
        >
          <h2 style={{ fontSize: 13, fontWeight: 600, margin: 0 }}>Customer</h2>
          <select
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            style={{
              padding: "4px 8px",
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text)",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
            }}
          >
            {tenants.map((t: any) => (
              <option key={t.tenant_id} value={t.tenant_id}>
                {t.name} ({t.tenant_id})
              </option>
            ))}
          </select>
        </div>

        {groupByCategory(tools).map(([cat, catTools]) => {
          const cm = CATEGORY_META[cat] ?? {
            label: cat,
            blurb: "Category declared by the connector.",
          };
          return (
        <div key={cat} style={{ marginBottom: 22 }}>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              gap: 8,
              paddingBottom: 6,
              marginBottom: 10,
              borderBottom: "1px solid var(--border)",
            }}
          >
            <h3
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                fontFamily: "var(--font-mono)",
                color: "var(--text-dim)",
                margin: 0,
              }}
            >
              {cm.label}
            </h3>
            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
              {cm.blurb}
            </span>
            <span
              style={{
                marginLeft: "auto",
                fontSize: 10,
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {catTools.length} {catTools.length === 1 ? "tool" : "tools"}
            </span>
          </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 14,
          }}
        >
          {catTools.map((t: any) => {
            const spec = specByTool[t.tool];
            const meta = STATE_META[t.overall] ?? STATE_META.not_implemented;
            return (
              <div
                key={t.tool}
                style={{
                  border: `1px solid ${meta.border}`,
                  background: meta.bg,
                  borderRadius: "var(--radius-sm)",
                  padding: 14,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <strong style={{ fontSize: 13 }}>{t.label}</strong>
                  {/* The qualifier names the failing CONSUMER. `FAILING`
                      alone reads as "the log store is down", which beside a
                      live collector is the misread to prevent. */}
                  <StateBadge
                    state={t.overall}
                    qualifier={t.continuity?.badge_qualifier}
                  />
                </div>

                {/* The payload's own reason wins where it exists. The
                    generic per-state copy said "A credential is stored" on
                    the log-store card, two lines above a footer saying "no
                    credential stored" — false by construction for an
                    integration configured from the deployment. */}
                <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
                  {(Object.values(t.directions || {})[0] as any)?.reason ||
                    meta.meaning}
                </div>

                {/* "Never worked" and "worked until Monday" are different
                    rows, and only the second is an incident. Without this a
                    configuration that disappears looks identical to one that
                    was never made — which is exactly how SIEM log enrichment
                    stayed off for two days reading as `not_configured`. */}
                {t.stray_credential_row && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: "6px 8px",
                      fontSize: 10,
                      color: "var(--amber, #f0b050)",
                      border: "1px solid rgba(240,176,80,0.25)",
                      borderRadius: 3,
                    }}
                  >
                    A saved configuration exists here and is <strong>not read</strong>
                    {t.stray_credential_row.configured_by
                      ? ` (saved by ${t.stray_credential_row.configured_by})`
                      : ""}
                    . This tool reads the deployment's settings, so nothing saved
                    through this page takes effect. Safe to remove.
                  </div>
                )}

                {/* What the verified_ok rests on. Rendered rather than
                    implied, because `api_ping` and `collector_output` are
                    different claims: one says the api can reach the service,
                    the other says the worker produced output. On 2026-10-14 a
                    green api ping sat beside a worker with no configuration. */}
                {(() => {
                  const dirWarrant = Object.values(t.directions || {})
                    .map((d: any) => d?.warrant)
                    .find(Boolean);
                  const w = t.continuity?.warrant || dirWarrant;
                  if (!w) return null;
                  return (
                    <div style={{ fontSize: 11, marginTop: 6 }}>
                      <span style={{ color: "var(--text-muted)" }}>
                        {w.kind === "collector_output"
                          ? "the collector produced output"
                          : "an API ping succeeded"}
                        {typeof w.age_hours === "number"
                          ? ` ${w.age_hours}h ago`
                          : ""}
                      </span>
                      <span
                        style={{
                          marginLeft: 6,
                          padding: "0 5px",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: "0.04em",
                          fontFamily: "var(--font-mono)",
                          color: "var(--text-dim)",
                          border: "1px solid var(--border)",
                          borderRadius: 3,
                        }}
                        title={w.what}
                      >
                        {String(w.process).toUpperCase()}
                      </span>
                    </div>
                  );
                })()}

                {t.continuity && (
                  <div style={{ fontSize: 11, marginTop: 6 }}>
                    {t.continuity.stopped ? (
                      <div style={{ color: "var(--red)" }}>
                        Last worked{" "}
                        {new Date(t.continuity.last_success).toLocaleString()}
                        {" — silent "}
                        {t.continuity.silent_for_hours < 48
                          ? `${t.continuity.silent_for_hours}h`
                          : `${Math.floor(t.continuity.silent_for_hours / 24)} days`}
                        .
                      </div>
                    ) : typeof t.continuity.last_success === "string" ? (
                      <div style={{ color: "var(--text-muted)" }}>
                        Last produced a result{" "}
                        {new Date(t.continuity.last_success).toLocaleString()}
                      </div>
                    ) : (
                      <div style={{ color: "var(--text-muted)" }}>
                        {/* The absence, rendered as one. Never a zero date. */}
                        Has never produced a result.
                      </div>
                    )}
                  </div>
                )}

                {/* Both directions, never one badge: a tool that answers
                    queries and delivers no detections is healthy by one
                    measure and dead by the other. */}
                {Object.entries(t.directions || {}).map(([dir, v]: [string, any]) => (
                  <div key={dir} style={{ marginTop: 8, fontSize: 11 }}>
                    <span style={{ color: "var(--text-muted)" }}>{dir}: </span>
                    <StateBadge state={v.state} compact />
                    {v.checked_at && (
                      <span style={{ color: "var(--text-muted)", marginLeft: 6 }}>
                        {new Date(v.checked_at).toLocaleString()}
                      </span>
                    )}
                    {v.reason && (
                      <div style={{ color: "var(--text-dim)", marginTop: 3 }}>
                        {v.reason}
                      </div>
                    )}
                  </div>
                ))}

                {t.configured && (
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 8 }}>
                    {t.secret_set === null || t.secret_set === undefined
                      ? "no credential needed — deployment-configured"
                      : t.secret_set
                        ? "credential set"
                        : "no credential stored"}
                    {t.configured_by && ` · by ${t.configured_by}`}
                    {t.config && Object.keys(t.config).length > 0 && (
                      <> · {Object.entries(t.config).map(([k, v]) => `${k}=${v}`).join(", ")}</>
                    )}
                  </div>
                )}

                {spec && !canWrite && (
                  <div
                    style={{
                      marginTop: 10,
                      fontSize: 10,
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Configuring an integration requires an administrator.
                  </div>
                )}

                {spec?.managed === "deployment" && (
                  <div
                    style={{
                      marginTop: 10,
                      fontSize: 10,
                      color: "var(--text-muted)",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Configured by the deployment (.env), not through this page.
                    Test connection runs a real query from the api process.
                  </div>
                )}

                {spec && canWrite && (
                  <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                    {spec?.managed !== "deployment" && (
                      <Button
                        onClick={() => {
                          setEditing(editing === t.tool ? null : t.tool);
                          setForm({});
                        }}
                        disabled={busy === t.tool}
                      >
                        {t.configured ? "Edit" : "Configure"}
                      </Button>
                    )}
                    {/* A deployment-configured tool has no stored credential,
                        so it is always testable and never removable. */}
                    {(t.configured || spec?.managed === "deployment") && (
                      <Button onClick={() => onVerify(t.tool)} disabled={busy === t.tool}>
                        {busy === t.tool ? "Testing…" : "Test connection"}
                      </Button>
                    )}
                    {t.configured && spec?.managed !== "deployment" && (
                      <Button onClick={() => onRemove(t.tool)} disabled={busy === t.tool}>
                        Remove
                      </Button>
                    )}
                  </div>
                )}

                {editing === t.tool && spec && canWrite && (
                  <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
                    {Object.entries(spec.config_fields || {}).map(
                      ([k, desc]: [string, any]) => (
                        <label key={k} style={{ fontSize: 11 }}>
                          <div style={{ color: "var(--text-dim)", marginBottom: 2 }}>
                            {k} — {desc}
                          </div>
                          <input
                            value={form[`c:${k}`] ?? (t.config?.[k] ?? "")}
                            onChange={(e) =>
                              setForm({ ...form, [`c:${k}`]: e.target.value })
                            }
                            style={inputStyle}
                          />
                        </label>
                      )
                    )}
                    {Object.entries(spec.secret_fields || {}).map(
                      ([k, desc]: [string, any]) => (
                        <label key={k} style={{ fontSize: 11 }}>
                          <div style={{ color: "var(--text-dim)", marginBottom: 2 }}>
                            {k} — {desc}
                          </div>
                          <input
                            type="password"
                            autoComplete="new-password"
                            placeholder={
                              t.secret_set ? "set — leave blank to keep" : ""
                            }
                            value={form[`s:${k}`] ?? ""}
                            onChange={(e) =>
                              setForm({ ...form, [`s:${k}`]: e.target.value })
                            }
                            style={inputStyle}
                          />
                        </label>
                      )
                    )}
                    <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                      Secrets are stored encrypted and are never shown again.
                      Saving tests the connection immediately; a credential
                      that fails is saved and shown as failing, with the
                      reason.
                    </div>
                    <div>
                      <Button onClick={() => onSave(t.tool, spec)} disabled={busy === t.tool}>
                        {busy === t.tool ? "Saving and testing…" : "Save and test"}
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
        </div>
          );
        })}
      </section>

      {/* ── who configured what ──────────────────────────────────────── */}
      {audit?.entries?.length > 0 && (
        <section style={{ marginTop: 28 }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>
            Configuration history
          </h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {audit.entries.map((e: any, i: number) => (
              <div key={i} style={{ fontSize: 11, color: "var(--text-dim)" }}>
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                  {e.at ? new Date(e.at).toLocaleString() : ""}
                </span>{" "}
                <strong style={{ color: "var(--text)" }}>{e.action}</strong> {e.tool}
                {e.actor && ` by ${e.actor}`}
                {e.actor_role && ` (${e.actor_role})`}
              </div>
            ))}
          </div>
        </section>
      )}
    </Page>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "6px 12px 6px 0",
  fontSize: 10,
  fontWeight: 600,
  letterSpacing: "0.04em",
  color: "var(--text-muted)",
  textTransform: "uppercase",
  borderBottom: "1px solid var(--border)",
  whiteSpace: "nowrap",
};

const tdStyle: React.CSSProperties = {
  padding: "7px 12px 7px 0",
  borderBottom: "1px solid var(--border)",
  whiteSpace: "nowrap",
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "4px 7px",
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 3,
  color: "var(--text)",
  fontSize: 12,
  fontFamily: "var(--font-mono)",
};
