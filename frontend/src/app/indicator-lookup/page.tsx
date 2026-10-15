"use client";

/**
 * One indicator, asked of every source that can answer it.
 *
 * The design rule, which is the whole reason this page is safe to give anyone:
 * **each source renders an answer, a named absence, or a statement that it
 * cannot be asked about this kind of indicator and why.** Never an empty
 * section where the third applies. Falcon has no alert field that holds a
 * domain, so an empty Falcon panel for `evil.com` would tell an analyst the
 * EDR has nothing when the truth is it has nowhere to look — and "no related
 * activity" is a conclusion people act on.
 *
 * The detected kind is shown next to the input, because a mistyped hash is a
 * syntactically valid hostname: routed as one it asks "is a machine called
 * this?", gets a true negative, and renders as "not found". The server refuses
 * digest-shaped values of a non-digest length for that reason, and this page
 * shows the refusal rather than hiding it.
 *
 * There is deliberately no query box, field selector or index picker. This
 * takes a value; the server decides the question. Free-form querying is
 * backlog 17.
 */

import React, { useCallback, useEffect, useState } from "react";

import { Button, Page, PageHeader } from "@/components/ui/Primitives";
import {
  getIntegrationMatrix,
  isFalconAbsence,
  lookupIndicator,
  type IndicatorLookupResult,
  type IndicatorSourceSection,
} from "@/lib/api";
import { shortStamp } from "@/lib/time";

const SOURCE_LABELS: Record<string, string> = {
  falcon: "CrowdStrike Falcon",
  estate: "Estate logs (OpenSearch)",
};

/** A named absence, as its reason and nothing else.
 *
 *  Not styled as an error: `no_field_map` and `out_of_scope` are *correct*
 *  outcomes here, and a red box would train people to dismiss the sentence
 *  that keeps them from a wrong conclusion. */
function Absence({ kind, reason }: { kind: string; reason: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        background: "var(--bg-input)",
        borderRadius: 6,
        padding: "10px 12px",
      }}
    >
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: 10.5,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--text-muted)",
          marginBottom: 5,
        }}
      >
        cannot be asked — {kind.replace(/_/g, " ")}
      </div>
      <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.6, color: "var(--text-dim)" }}>
        {reason}
      </p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div style={{ display: "flex", gap: 10, fontSize: 12.5, lineHeight: 1.7 }}>
      <span style={{ color: "var(--text-muted)", minWidth: 150 }}>{label}</span>
      <span style={{ color: "var(--text)" }}>{value}</span>
    </div>
  );
}

/** The estate's two questions, which never merge. */
function EstateAnswer({ answer }: { answer: any }) {
  const parts: Array<[string, any]> = [
    ["Endpoint DNS queries", answer.host_dns],
    ["Perimeter traffic", answer.perimeter],
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {parts.map(([label, part]) => (
        <div key={label}>
          <div
            style={{
              fontSize: 10.5,
              letterSpacing: 0.4,
              textTransform: "uppercase",
              color: "var(--text-muted)",
              marginBottom: 4,
            }}
          >
            {label}
          </div>
          {part?.absent ? (
            <Absence kind={part.kind} reason={part.reason} />
          ) : part?.observed ? (
            <div>
              <Row label="Seen" value={`yes — ${part.documents?.toLocaleString()} events`} />
              <Row label="Hosts" value={part.host_count} />
              <Row label="First seen" value={shortStamp(part.first_seen)} />
              <Row label="Last seen" value={shortStamp(part.last_seen)} />
              <Row label="Observation floor" value={shortStamp(part.observation_floor)} />
              {part.observation_floor_basis && (
                <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.55 }}>
                  {part.observation_floor_basis}
                </p>
              )}
              {part.basis && (
                <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.55 }}>
                  {part.basis}
                </p>
              )}
            </div>
          ) : (
            <div>
              <Row label="Seen" value="no events in the window" />
              {part?.coverage?.note && (
                <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.55 }}>
                  {part.coverage.note}
                </p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/** Falcon's answer. A negative never renders without its control's state. */
function FalconAnswer({ answer }: { answer: any }) {
  // The host panel shape, reused from the alert surface.
  if (answer.coverage || answer.field_control) {
    const cov = answer.coverage || {};
    const det = answer.detections || {};
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {cov.absent ? (
          <Absence kind={cov.kind} reason={cov.reason} />
        ) : cov.conditional_finding ? (
          <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.6, color: "var(--text-dim)" }}>
            {cov.conditional_finding}
          </p>
        ) : cov.managed === false ? (
          <Row label="Falcon sensor" value="none on this host — this host has no EDR coverage" />
        ) : (
          <>
            <Row label="Falcon sensor" value={`installed — ${cov.agent_version ?? ""} (${cov.status ?? ""})`} />
            <Row label="OS" value={cov.os_version} />
            <Row label="Last reported" value={shortStamp(cov.last_seen)} />
          </>
        )}
        {det.absent ? (
          <Absence kind={det.kind} reason={det.reason} />
        ) : (
          <Row
            label="Open detections"
            value={`${det.open_detection_count ?? 0} of ${det.distinct_detection_count ?? 0} distinct${
              det.counts_are_lower_bounds ? " (at least)" : ""
            }`}
          />
        )}
        {answer.field_control && (
          <p style={{ margin: 0, fontSize: 11, lineHeight: 1.55, color: "var(--text-muted)" }}>
            Field control{" "}
            <span style={{ fontWeight: 600, color: answer.field_control.passed ? "var(--success)" : "var(--warning)" }}>
              {answer.field_control.passed ? "passed" : "did not pass"}
            </span>
            {answer.field_control.checked_at ? ` at ${shortStamp(answer.field_control.checked_at)}` : ""}.{" "}
            {answer.field_control.why_it_matters}
          </p>
        )}
      </div>
    );
  }
  // The hash shape.
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <Row label="Field searched" value={answer.field} />
      <Row label="Alerts mentioning it" value={answer.detection_count} />
      {/* No negative without its warrant. */}
      <p style={{ margin: 0, fontSize: 11, lineHeight: 1.55, color: answer.negative_is_interpretable ? "var(--text-muted)" : "var(--warning)" }}>
        {answer.negative_is_interpretable
          ? "The field was confirmed to filter before this ran, so a zero here is a real negative."
          : "The field could not be confirmed, so a zero here means nothing."}
      </p>
      {(answer.notes || []).map((n: string, i: number) => (
        <p key={i} style={{ margin: 0, fontSize: 11, lineHeight: 1.55, color: "var(--text-muted)" }}>
          {n}
        </p>
      ))}
    </div>
  );
}

function Source({ name, section }: { name: string; section: IndicatorSourceSection }) {
  const answer: any = section.answer;
  return (
    <section
      style={{
        border: "1px solid var(--border)",
        borderRadius: 8,
        background: "var(--surface)",
        padding: 16,
      }}
    >
      <header style={{ marginBottom: 10 }}>
        <h3 style={{ margin: 0, fontSize: 12, fontWeight: 600, letterSpacing: 0.5, textTransform: "uppercase", color: "var(--text-dim)" }}>
          {SOURCE_LABELS[name] ?? name}
        </h3>
        <p style={{ margin: "3px 0 0", fontSize: 11.5, color: "var(--text-muted)" }}>
          Asked: {section.question}
          {section.reading_used ? (
            <>
              {" "}· read as <strong style={{ color: "var(--text-dim)" }}>{section.reading_used}</strong>
            </>
          ) : null}
        </p>
      </header>

      {isFalconAbsence(answer) ? (
        <Absence kind={answer.kind} reason={answer.reason} />
      ) : name === "falcon" ? (
        <FalconAnswer answer={answer} />
      ) : (
        <EstateAnswer answer={answer} />
      )}

      {/* The other reading's refusal, so answering one does not hide the
          other. A dotted name is both things. */}
      {section.not_answered_for ? (
        <div style={{ marginTop: 12, borderTop: "1px solid var(--panel-divider-strong)", paddingTop: 10 }}>
          <p style={{ margin: "0 0 6px", fontSize: 11, letterSpacing: 0.4, textTransform: "uppercase", color: "var(--text-muted)" }}>
            read as {section.not_answered_for.reading} — not answered
          </p>
          {isFalconAbsence(section.not_answered_for.answer) ? (
            <Absence
              kind={section.not_answered_for.answer.kind}
              reason={section.not_answered_for.answer.reason}
            />
          ) : null}
        </div>
      ) : null}

      {/* Offered, labelled, never substituted for the question that was asked. */}
      {section.narrower_claim && (
        <div style={{ marginTop: 12, borderTop: "1px solid var(--panel-divider-strong)", paddingTop: 10 }}>
          <p style={{ margin: "0 0 8px", fontSize: 11.5, lineHeight: 1.6, color: "var(--warning)" }}>
            {section.narrower_claim.claim}
          </p>
          {section.narrower_answer ? <EstateAnswer answer={section.narrower_answer} /> : null}
        </div>
      )}
    </section>
  );
}

export default function IndicatorLookupPage() {
  const [tenants, setTenants] = useState<Array<{ tenant_id: string; name?: string }>>([]);
  const [tenantId, setTenantId] = useState("");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<IndicatorLookupResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getIntegrationMatrix()
      .then((mx: any) => {
        const list = mx?.tenants ?? [];
        setTenants(list);
        if (list.length) setTenantId((t) => t || list[0].tenant_id);
      })
      // Stated, not swallowed: an empty customer list with no explanation is
      // an absence presented as a measurement.
      .catch((e: any) => setError(`The customer list could not be loaded: ${e?.message ?? e}`));
  }, []);

  const run = useCallback(async () => {
    const v = value.trim();
    if (!v || !tenantId) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await lookupIndicator(v, tenantId));
    } catch (e: any) {
      // A failed request is not an empty answer.
      setError(`${e?.message ?? e} — this is a failure to ask, not a report that nothing was found.`);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }, [value, tenantId]);

  const detected = result?.detected;
  const unparsed = detected?.kind === "unparsed";

  return (
    <Page>
      <PageHeader
        title="Indicator lookup"
        subtitle="One value, asked of every source that can answer it — and told plainly which cannot."
      />

      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-end", marginBottom: 18 }}>
        <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: 0.4, color: "var(--text-muted)" }}>
            Customer
          </span>
          <select
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            style={{
              padding: "7px 9px",
              background: "var(--bg-input)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              fontSize: 12.5,
            }}
          >
            {tenants.map((t) => (
              <option key={t.tenant_id} value={t.tenant_id}>
                {t.name || t.tenant_id}
              </option>
            ))}
          </select>
        </label>

        <label style={{ display: "flex", flexDirection: "column", gap: 4, flex: "1 1 320px" }}>
          <span style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: 0.4, color: "var(--text-muted)" }}>
            Indicator — hash, domain, address, hostname or URL
          </span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void run();
            }}
            placeholder="aka.ms · EXP-22MY264 · 8.8.8.8 · a SHA-256"
            spellCheck={false}
            style={{
              padding: "7px 9px",
              background: "var(--bg-input)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              fontSize: 12.5,
              fontFamily: "var(--font-mono)",
            }}
          />
        </label>

        <Button variant="primary" onClick={() => void run()} disabled={busy || !value.trim() || !tenantId}>
          {busy ? "Asking…" : "Look up"}
        </Button>
      </div>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <Absence kind="check_failed" reason={error} />
        </div>
      )}

      {detected && (
        <div
          style={{
            marginBottom: 16,
            padding: "10px 12px",
            border: `1px solid ${unparsed ? "var(--warning)" : "var(--border)"}`,
            borderRadius: 6,
            background: "var(--bg-input)",
          }}
        >
          {/* Shown so a misroute is the reader's to catch, not the server's to
              hide. A mistyped hash is a valid hostname. */}
          <div style={{ fontSize: 12.5, color: "var(--text)" }}>
            Detected as <strong>{detected.kind.replace(/_/g, " ")}</strong>
            {detected.how ? <span style={{ color: "var(--text-muted)" }}> — {detected.how}</span> : null}
          </div>
          {detected.ambiguity && (
            <p style={{ margin: "6px 0 0", fontSize: 12, lineHeight: 1.6, color: "var(--text-dim)" }}>
              {detected.ambiguity}
            </p>
          )}
          {detected.reason && (
            <p style={{ margin: "6px 0 0", fontSize: 12, lineHeight: 1.6, color: "var(--warning)" }}>
              {detected.reason}
            </p>
          )}
        </div>
      )}

      {result && !unparsed && (
        <div style={{ display: "grid", gap: 14, gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))" }}>
          {Object.entries(result.sources).map(([name, section]) => (
            <Source key={name} name={name} section={section} />
          ))}
        </div>
      )}

      {result && !isFalconAbsence(result.recorded) && result.recorded !== true && (
        <p style={{ marginTop: 14, fontSize: 11.5, color: "var(--text-muted)" }}>
          This lookup was answered. Whether it was recorded is unknown.
        </p>
      )}
      {result && isFalconAbsence(result.recorded) && (
        <div style={{ marginTop: 14 }}>
          <Absence kind={result.recorded.kind} reason={result.recorded.reason} />
        </div>
      )}
    </Page>
  );
}
