"use client";

import React from "react";
import { FaviconIntelEvidence } from "@/lib/types";

interface Props {
  faviconIntel: FaviconIntelEvidence;
}

export default function FaviconIntelSection({ faviconIntel }: Props) {
  const { favicon_hash, total_hosts_sharing, hosts, is_unique_favicon, is_default_favicon, notes } = faviconIntel;
  const [expanded, setExpanded] = React.useState(false);

  const riskLevel =
    is_default_favicon ? "info"
    : total_hosts_sharing > 20 ? "warning"
    : total_hosts_sharing > 5  ? "warning"
    : is_unique_favicon         ? "info"
    : "info";

  const riskColor = riskLevel === "warning" ? "var(--yellow)" : "var(--accent)";

  return (
    <div>
      {/* Header stat row */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr 1fr",
        gap: 8,
        marginBottom: 14,
      }}>
        <StatBox
          label="Favicon Hash"
          value={favicon_hash ? favicon_hash.toString() : "—"}
          mono
          color="var(--accent)"
        />
        <StatBox
          label="Hosts Sharing Hash"
          value={String(total_hosts_sharing)}
          color={total_hosts_sharing > 5 && !is_default_favicon ? "var(--yellow)" : "var(--accent)"}
        />
        <StatBox
          label="Fingerprint"
          value={is_default_favicon ? "Default / Common" : is_unique_favicon ? "Unique" : "Shared"}
          color={is_default_favicon ? "var(--text-muted)" : is_unique_favicon ? "var(--green)" : "var(--yellow)"}
        />
      </div>

      {/* Notes / warnings */}
      {notes.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          {notes.map((note, i) => (
            <div key={i} style={{
              padding: "8px 12px", marginBottom: 4,
              background: "rgba(148,163,184,0.06)",
              borderLeft: "3px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              fontSize: 11, color: "var(--text-muted)", fontStyle: "italic",
            }}>
              {note}
            </div>
          ))}
        </div>
      )}

      {/* Host list */}
      {hosts.length > 0 && (
        <div>
          <div style={{
            fontSize: 12, fontWeight: 600, color: riskColor,
            letterSpacing: "0.01em", marginBottom: 8,
            padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
            fontFamily: "var(--font-sans)",
            display: "flex", justifyContent: "space-between", alignItems: "center",
          }}>
            <span>Hosts Sharing This Favicon ({total_hosts_sharing})</span>
            {hosts.length > 10 && (
              <button
                onClick={() => setExpanded(!expanded)}
                style={{
                  fontSize: 10, padding: "3px 10px",
                  background: "var(--bg-input)", border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)", color: "var(--text-secondary)",
                  cursor: "pointer", fontFamily: "var(--font-sans)",
                }}
              >
                {expanded ? "Show Less" : `Show All ${hosts.length}`}
              </button>
            )}
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr 1fr 1fr 1fr",
            gap: "4px 0",
            marginBottom: 4,
            padding: "4px 10px",
            fontSize: 10, fontWeight: 700,
            color: "var(--text-muted)", letterSpacing: "0.05em",
          }}>
            <span>IP</span>
            <span>ORG</span>
            <span>PORT</span>
            <span>COUNTRY</span>
            <span>ASN</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {(expanded ? hosts : hosts.slice(0, 10)).map((host, i) => (
              <div key={i} style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr 1fr 1fr 1fr",
                padding: "6px 10px",
                background: i % 2 === 0 ? "var(--bg-input)" : "transparent",
                borderRadius: "var(--radius-sm)",
                fontSize: 11,
                gap: 4,
              }}>
                <span style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>
                  {host.ip}
                </span>
                <span style={{ color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {host.org || "—"}
                </span>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                  {host.port}
                </span>
                <span style={{ color: "var(--text-muted)" }}>
                  {host.country || "—"}
                </span>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                  {host.asn || "—"}
                </span>
              </div>
            ))}
          </div>
          {!expanded && hosts.length > 10 && (
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6, fontStyle: "italic" }}>
              Showing 10 of {hosts.length} results
            </div>
          )}
        </div>
      )}

      {total_hosts_sharing === 0 && (
        <div style={{
          padding: "10px 14px", fontSize: 12, color: "var(--green)",
          background: "rgba(52,211,153,0.06)", borderRadius: "var(--radius-sm)",
          borderLeft: "3px solid var(--green)",
        }}>
          No other hosts found sharing this favicon hash
        </div>
      )}
    </div>
  );
}

function StatBox({ label, value, color, mono }: { label: string; value: string; color: string; mono?: boolean }) {
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
      <div style={{
        fontSize: 12, fontWeight: 600, color,
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
      }}>
        {value}
      </div>
    </div>
  );
}
