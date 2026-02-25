"use client";

import React from "react";
import { CertTimelineEvidence } from "@/lib/types";

interface Props {
  certTimeline: CertTimelineEvidence;
}

export default function CertTimelineSection({ certTimeline }: Props) {
  const [showAll, setShowAll] = React.useState(false);
  const {
    total_certs, entries, unique_issuers, cert_burst_detected,
    burst_periods, short_lived_count, earliest_cert, latest_cert, notes,
  } = certTimeline;

  const displayEntries = showAll ? entries : entries.slice(0, 15);

  return (
    <div>
      {/* Summary stats */}
      <div style={{
        display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14,
      }}>
        <StatBox label="Total Certs" value={String(total_certs)} color="var(--accent)" />
        <StatBox
          label="Short-Lived"
          value={String(short_lived_count)}
          color={short_lived_count > 0 ? "var(--yellow)" : "var(--text-muted)"}
        />
        <StatBox
          label="Cert Burst"
          value={cert_burst_detected ? "Detected" : "None"}
          color={cert_burst_detected ? "var(--red)" : "var(--green)"}
        />
        <StatBox
          label="Unique Issuers"
          value={String(unique_issuers.length)}
          color={unique_issuers.length > 3 ? "var(--yellow)" : "var(--accent)"}
        />
      </div>

      {/* Alert banners */}
      {cert_burst_detected && burst_periods.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          {burst_periods.slice(0, 3).map((bp, i) => (
            <div key={i} style={{
              padding: "8px 14px", marginBottom: 4,
              background: "rgba(248,113,113,0.06)",
              borderLeft: "3px solid var(--red)",
              borderRadius: "var(--radius-sm)",
              fontSize: 12,
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span style={{ color: "var(--red)", fontWeight: 600 }}>
                Burst: {bp.count} certs in 7-day window
              </span>
              <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                {fmtDate(bp.start)} → {fmtDate(bp.end)}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Notes */}
      {notes.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          {notes.map((note, i) => (
            <div key={i} style={{
              padding: "6px 12px", marginBottom: 3,
              background: "rgba(148,163,184,0.06)",
              borderLeft: "3px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              fontSize: 11, color: "var(--text-muted)",
            }}>
              {note}
            </div>
          ))}
        </div>
      )}

      {/* Issuers */}
      {unique_issuers.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{
            fontSize: 11, fontWeight: 600, color: "var(--text-muted)",
            letterSpacing: "0.05em", marginBottom: 6,
          }}>
            CERTIFICATE AUTHORITIES
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {unique_issuers.map((issuer, i) => (
              <span key={i} style={{
                padding: "3px 10px", fontSize: 11,
                background: "var(--bg-input)", color: "var(--text-secondary)",
                borderRadius: "var(--radius-sm)", border: "1px solid var(--border-dim)",
              }}>
                {issuer}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Date range */}
      {(earliest_cert || latest_cert) && (
        <div style={{
          display: "flex", gap: 16, marginBottom: 14,
          fontSize: 11, color: "var(--text-muted)",
        }}>
          {earliest_cert && <span>Earliest: <strong style={{ color: "var(--text-secondary)" }}>{fmtDate(earliest_cert)}</strong></span>}
          {latest_cert && <span>Latest: <strong style={{ color: "var(--text-secondary)" }}>{fmtDate(latest_cert)}</strong></span>}
        </div>
      )}

      {/* Cert table */}
      {entries.length > 0 && (
        <div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "2fr 2fr 1.5fr 1.5fr 0.8fr",
            padding: "4px 10px", marginBottom: 2,
            fontSize: 10, fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.05em",
            gap: 8,
          }}>
            <span>COMMON NAME</span>
            <span>ISSUER</span>
            <span>NOT BEFORE</span>
            <span>NOT AFTER</span>
            <span>DAYS</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {displayEntries.map((cert, i) => (
              <div key={i} style={{
                display: "grid",
                gridTemplateColumns: "2fr 2fr 1.5fr 1.5fr 0.8fr",
                padding: "6px 10px",
                background: cert.is_short_lived
                  ? "rgba(251,191,36,0.05)"
                  : i % 2 === 0 ? "var(--bg-input)" : "transparent",
                borderRadius: "var(--radius-sm)",
                borderLeft: cert.is_short_lived ? "2px solid var(--yellow)" : "2px solid transparent",
                fontSize: 11, gap: 8, alignItems: "center",
              }}>
                <span style={{
                  color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {cert.common_name}
                </span>
                <span style={{
                  color: "var(--text-muted)",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {cert.issuer_name || "—"}
                </span>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                  {fmtDate(cert.not_before)}
                </span>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                  {fmtDate(cert.not_after)}
                </span>
                <span style={{
                  color: cert.is_short_lived ? "var(--yellow)" : "var(--text-dim)",
                  fontWeight: cert.is_short_lived ? 600 : 400,
                  fontFamily: "var(--font-mono)",
                }}>
                  {cert.validity_days > 0 ? cert.validity_days : "—"}
                </span>
              </div>
            ))}
          </div>
          {entries.length > 15 && (
            <button
              onClick={() => setShowAll(!showAll)}
              style={{
                marginTop: 8, padding: "5px 14px", fontSize: 11,
                background: "var(--bg-input)", border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
                cursor: "pointer", fontFamily: "var(--font-sans)",
              }}
            >
              {showAll ? "Show Less" : `Show All ${entries.length} Certificates`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{
      padding: "12px 14px",
      background: "var(--bg-input)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
    }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.05em", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, fontWeight: 600, color }}>
        {value}
      </div>
    </div>
  );
}

function fmtDate(val: string | null | undefined): string {
  if (!val) return "—";
  try {
    return new Date(val).toLocaleDateString("en-US", {
      year: "numeric", month: "short", day: "numeric",
    });
  } catch {
    return val.slice(0, 10);
  }
}
