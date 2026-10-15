"use client";

/**
 * What this tenant's CrowdStrike Falcon knows about the host in this alert.
 *
 * Two sections that fail differently, and the difference is the whole design:
 *
 * - **Coverage** asks the Devices API, which *validates* field names (an
 *   unknown one is a 400). So "no sensor on this host" is a real negative and
 *   is rendered as a finding — a host generating alerts with no EDR is the
 *   thing worth knowing.
 * - **Detections** asks the Alerts API, which does **not** validate field
 *   names: it answers HTTP 200 with zero results. So its negative is only
 *   shown once the server's standing field control has passed, and the
 *   control's state is on screen rather than hidden, because every "nothing
 *   found" here depends on it.
 *
 * The headline number is **distinct open detections**, not rows. Measured on
 * EXP-22MY264: 1,432 raw alert rows in 30 days is 12 distinct detections, 936
 * rows of which are one developer running wsl.exe, and 996 of 1,000 already
 * closed. "1,432 detections" reads as a compromised machine. The raw count
 * lives behind a disclosure, labelled as repetition, where it cannot be
 * mistaken for severity.
 *
 * Styling note: this project uses inline styles over CSS variables and has no
 * Tailwind. The first draft of this file was written with utility classes,
 * which would have rendered the whole panel unstyled.
 */

import React, { useCallback, useEffect, useState } from "react";

import {
  getRunFalcon,
  isFalconAbsence,
  type FalconCoverage,
  type FalconDetectionGroup,
  type FalconDetections,
  type FalconHostPanel as Panel,
} from "@/lib/api";

/** A named absence, rendered as its reason and nothing else.
 *
 *  Deliberately not styled as an error: `no_field_map` and `check_failed` are
 *  correct outcomes, and a red box would train people to dismiss them. */
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
          marginBottom: 4,
        }}
      >
        {kind.replace(/_/g, " ")}
      </div>
      <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: "var(--text-dim)" }}>
        {reason}
      </p>
    </div>
  );
}

function Chip({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const color = {
    neutral: "var(--text-dim)",
    good: "var(--success)",
    warn: "var(--warning)",
    bad: "var(--danger)",
  }[tone];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 7px",
        borderRadius: 4,
        fontSize: 11,
        border: `1px solid ${color}`,
        color,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div style={{ minWidth: 0 }}>
      <div
        style={{
          fontSize: 10.5,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 12.5,
          color: "var(--text)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function Coverage({ coverage }: { coverage: FalconCoverage }) {
  // A host with alerts and no EDR sensor. This is a finding, not an empty
  // panel, and it can be stated plainly because the Devices API rejects an
  // unknown field rather than answering zero.
  if (coverage.managed === false) {
    return (
      <div
        style={{
          border: "1px solid var(--warning)",
          borderRadius: 6,
          padding: "10px 12px",
          background: "var(--bg-input)",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--warning)", marginBottom: 4 }}>
          No CrowdStrike sensor on this host
        </div>
        <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: "var(--text-dim)" }}>
          {coverage.finding}
        </p>
        <p
          style={{
            margin: "8px 0 0",
            fontSize: 11.5,
            lineHeight: 1.5,
            color: "var(--text-muted)",
          }}
        >
          {coverage.basis}
        </p>
      </div>
    );
  }

  const reporting = coverage.reporting;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        <Chip tone="good">Sensor installed</Chip>
        {coverage.prevention_applied ? (
          <Chip>prevention policy applied</Chip>
        ) : (
          <Chip tone="warn">no prevention policy applied</Chip>
        )}
        {coverage.degraded && (
          <Chip tone="warn">reduced functionality — installed but not fully protecting</Chip>
        )}
        {coverage.sensor_stale && <Chip tone="warn">sensor has not reported recently</Chip>}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
          gap: 12,
        }}
      >
        <Fact label="Host" value={coverage.hostname} />
        <Fact label="Type" value={coverage.product_type_desc} />
        <Fact
          label="OS"
          value={
            coverage.os_version
              ? `${coverage.os_version}${coverage.os_build ? ` (build ${coverage.os_build})` : ""}`
              : null
          }
        />
        <Fact label="Sensor version" value={coverage.agent_version} />
        <Fact label="Sensor status" value={coverage.status} />
        <Fact label="Site" value={coverage.site_name} />
        <Fact label="Domain" value={coverage.machine_domain} />
        <Fact label="First seen" value={coverage.first_seen?.slice(0, 10)} />
        <Fact label="Last seen" value={coverage.last_seen?.replace("T", " ").slice(0, 16)} />
      </div>

      {/* A sensor that has not reported is not a sensor that saw nothing, so
          this sits beside the detections rather than in a tooltip. */}
      {typeof reporting === "string" ? (
        <p
          style={{
            margin: 0,
            fontSize: 11.5,
            lineHeight: 1.55,
            color: coverage.sensor_stale ? "var(--warning)" : "var(--text-muted)",
          }}
        >
          {reporting}
        </p>
      ) : (
        reporting && <Absence kind={reporting.kind} reason={reporting.reason} />
      )}

      {coverage.re_enrolled && (
        <p style={{ margin: 0, fontSize: 11.5, lineHeight: 1.55, color: "var(--text-muted)" }}>
          {coverage.re_enrolled_note}
        </p>
      )}
    </div>
  );
}

function DetectionRow({ group }: { group: FalconDetectionGroup }) {
  return (
    <li
      style={{
        listStyle: "none",
        padding: "8px 0",
        borderBottom: "1px solid var(--panel-divider-strong)",
      }}
    >
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "baseline", gap: 8 }}>
        <Chip tone={group.open ? "bad" : "neutral"}>{group.open ? "open" : "closed"}</Chip>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{group.name}</span>
        {group.filename && (
          <span
            style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--text-dim)" }}
          >
            {group.filename}
          </span>
        )}
        {group.prevented && <Chip tone="good">blocked</Chip>}
      </div>
      <div
        style={{
          marginTop: 4,
          display: "flex",
          flexWrap: "wrap",
          gap: "4px 14px",
          fontSize: 11.5,
          color: "var(--text-muted)",
        }}
      >
        {group.tactic && (
          <span>
            {group.tactic}
            {group.technique ? ` · ${group.technique}` : ""}
          </span>
        )}
        {group.users.length > 0 && <span>user {group.users.join(", ")}</span>}
        {group.latest && <span>last {group.latest.replace("T", " ").slice(0, 16)}</span>}
        {/* Repetition, named as such, beside the thing it repeats. */}
        {group.rows > 1 && (
          <span>
            {group.rows} rows ({group.open_rows} open) — repeats of the same detection
          </span>
        )}
      </div>
    </li>
  );
}

function Detections({ detections }: { detections: FalconDetections }) {
  const [showRaw, setShowRaw] = useState(false);
  const atLeast = detections.counts_are_lower_bounds ? "at least " : "";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "baseline", gap: 8 }}>
        <span
          style={{
            fontSize: 26,
            fontWeight: 600,
            fontVariantNumeric: "tabular-nums",
            color: "var(--text)",
            lineHeight: 1,
          }}
        >
          {detections.open_detection_count}
        </span>
        <span style={{ fontSize: 13, color: "var(--text-dim)" }}>
          {atLeast}open detection{detections.open_detection_count === 1 ? "" : "s"}
          {detections.distinct_detection_count !== detections.open_detection_count &&
            ` of ${atLeast}${detections.distinct_detection_count} distinct`}
        </span>
      </div>
      <p style={{ margin: 0, fontSize: 11.5, lineHeight: 1.55, color: "var(--text-muted)" }}>
        {detections.counts_basis}
      </p>

      {detections.groups.length === 0 ? (
        <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: "var(--text-dim)" }}>
          Falcon has no alerts for this host in the window. {detections.basis}
        </p>
      ) : (
        <ul style={{ margin: 0, padding: 0 }}>
          {detections.groups.map((group) => (
            <DetectionRow key={`${group.name}:${group.filename ?? ""}`} group={group} />
          ))}
        </ul>
      )}

      {/* The raw row count, behind a disclosure and labelled. It is repetition,
          not severity: one process run repeatedly produces hundreds of rows. */}
      {detections.raw.rows > detections.distinct_detection_count && (
        <div>
          <button
            type="button"
            onClick={() => setShowRaw((v) => !v)}
            style={{
              background: "transparent",
              border: "none",
              padding: 0,
              fontSize: 11.5,
              color: "var(--text-muted)",
              textDecoration: "underline dotted",
              cursor: "pointer",
            }}
          >
            {showRaw ? "Hide" : "Show"} raw alert row counts
          </button>
          {showRaw && (
            <p
              style={{
                margin: "8px 0 0",
                fontSize: 11.5,
                lineHeight: 1.55,
                color: "var(--text-muted)",
              }}
            >
              {detections.raw.note}
              {detections.raw.truncated_at !== null &&
                ` Only the newest ${detections.raw.truncated_at} rows were read, so the counts above are floors.`}
            </p>
          )}
        </div>
      )}
      {detections.basis && detections.groups.length > 0 && (
        <p style={{ margin: 0, fontSize: 11, lineHeight: 1.5, color: "var(--text-muted)" }}>
          {detections.basis}
        </p>
      )}
    </div>
  );
}

export default function FalconHostPanel({ runId }: { runId: string }) {
  const [panel, setPanel] = useState<Panel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPanel(await getRunFalcon(runId));
    } catch (err) {
      // The request itself failing is distinct from Falcon answering an
      // absence, and must not render as "the EDR has nothing".
      setError(err instanceof Error ? err.message : "The Falcon panel could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [runId]);

  useEffect(() => {
    void load();
  }, [load]);

  const heading = {
    fontSize: 10.5,
    fontWeight: 600,
    letterSpacing: 0.5,
    textTransform: "uppercase" as const,
    color: "var(--text-muted)",
    marginBottom: 8,
  };

  return (
    <section
      style={{
        border: "1px solid var(--border)",
        borderRadius: 8,
        background: "var(--surface)",
        padding: 16,
      }}
    >
      <header
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: 8,
          marginBottom: 12,
        }}
      >
        <h3
          style={{
            margin: 0,
            fontSize: 12,
            fontWeight: 600,
            letterSpacing: 0.5,
            textTransform: "uppercase",
            color: "var(--text-dim)",
          }}
        >
          CrowdStrike Falcon — this host
        </h3>
        {panel?.hostname && (
          <span
            style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--text-muted)" }}
          >
            {panel.hostname} · last {panel.window_days} days
          </span>
        )}
      </header>

      {loading && (
        <p style={{ margin: 0, fontSize: 12.5, color: "var(--text-muted)" }}>Asking Falcon…</p>
      )}

      {error && (
        <Absence
          kind="check_failed"
          reason={`${error} This is a failure to ask, not a report that the EDR has nothing on this host.`}
        />
      )}

      {panel && !loading && !error && (
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div>
            <div style={heading}>EDR coverage</div>
            {isFalconAbsence(panel.coverage) ? (
              <Absence kind={panel.coverage.kind} reason={panel.coverage.reason} />
            ) : (
              <Coverage coverage={panel.coverage} />
            )}
          </div>

          <div>
            <div style={heading}>Detections</div>
            {isFalconAbsence(panel.detections) ? (
              <Absence kind={panel.detections.kind} reason={panel.detections.reason} />
            ) : (
              <Detections detections={panel.detections} />
            )}
          </div>

          {/* Shown, never hidden. Every "nothing found" above depends on it. */}
          {panel.field_control && (
            <footer
              style={{
                borderTop: "1px solid var(--panel-divider-strong)",
                paddingTop: 10,
                fontSize: 11,
                lineHeight: 1.55,
                color: "var(--text-muted)",
              }}
            >
              Field control{" "}
              <span
                style={{
                  fontWeight: 600,
                  color: panel.field_control.passed ? "var(--success)" : "var(--warning)",
                }}
              >
                {panel.field_control.passed ? "passed" : "did not pass"}
              </span>
              {panel.field_control.field ? ` on ${panel.field_control.field}` : ""}
              {panel.field_control.checked_at
                ? ` at ${panel.field_control.checked_at.replace("T", " ").slice(0, 16)}`
                : ""}
              . {panel.field_control.why_it_matters}
            </footer>
          )}
        </div>
      )}
    </section>
  );
}
