"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";
import { PivotResponse, RelatedInvestigation, SharedInfrastructure } from "@/lib/types";

interface Props {
  investigationId: string;
}

const INFRA_TYPE_COLORS: Record<string, string> = {
  ip: "var(--accent)",
  certificate: "var(--yellow)",
  asn: "var(--green)",
  registrar: "#a78bfa",
  nameserver: "var(--text-secondary)",
};

const CLASSIFICATION_COLORS: Record<string, string> = {
  malicious: "var(--red)",
  suspicious: "var(--yellow)",
  benign: "var(--green)",
  inconclusive: "var(--text-muted)",
};

export default function InfrastructureTab({ investigationId }: Props) {
  const router = useRouter();
  const [data, setData] = useState<PivotResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    api.getPivots(investigationId)
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((err) => {
        if (!cancelled) setError(err?.message || "Failed to load pivot data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [investigationId]);

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: "center" }}>
        <div style={{
          fontSize: 12, color: "var(--text-dim)",
          fontFamily: "var(--font-sans)",
        }}>
          Analyzing infrastructure connections...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        padding: 20, background: "rgba(239,68,68,0.06)",
        borderLeft: "3px solid var(--red)", borderRadius: "var(--radius-sm)",
      }}>
        <div style={{ fontSize: 12, color: "var(--red)" }}>{error}</div>
      </div>
    );
  }

  if (!data) return null;

  const { pivot_points, related_investigations } = data;
  const hasPoints = pivot_points.ips?.length > 0 ||
    pivot_points.cert_sha256 ||
    pivot_points.asn ||
    pivot_points.registrar ||
    pivot_points.name_servers?.length > 0;

  return (
    <div>
      {/* Pivot Points */}
      <Section title="Infrastructure Pivot Points">
        {!hasPoints ? (
          <EmptyNote>No pivot points extracted from evidence.</EmptyNote>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {/* IPs */}
            {pivot_points.ips?.length > 0 && (
              <PivotRow label="IP Addresses" type="ip">
                {pivot_points.ips.map((ip) => (
                  <Badge key={ip} color={INFRA_TYPE_COLORS.ip}>{ip}</Badge>
                ))}
              </PivotRow>
            )}

            {/* Certificate */}
            {pivot_points.cert_sha256 && (
              <PivotRow label="Certificate SHA-256" type="certificate">
                <Badge color={INFRA_TYPE_COLORS.certificate}>
                  {pivot_points.cert_sha256.slice(0, 24)}...
                </Badge>
              </PivotRow>
            )}

            {/* ASN */}
            {pivot_points.asn && (
              <PivotRow label="ASN" type="asn">
                <Badge color={INFRA_TYPE_COLORS.asn}>AS{pivot_points.asn}</Badge>
              </PivotRow>
            )}

            {/* Registrar */}
            {pivot_points.registrar && (
              <PivotRow label="Registrar" type="registrar">
                <Badge color={INFRA_TYPE_COLORS.registrar}>{pivot_points.registrar}</Badge>
              </PivotRow>
            )}

            {/* Name Servers */}
            {pivot_points.name_servers?.length > 0 && (
              <PivotRow label="Name Servers" type="nameserver">
                {pivot_points.name_servers.map((ns) => (
                  <Badge key={ns} color={INFRA_TYPE_COLORS.nameserver}>{ns}</Badge>
                ))}
              </PivotRow>
            )}
          </div>
        )}
      </Section>

      {/* Related Investigations */}
      <Section title={`Related Investigations (${related_investigations.length})`}>
        {related_investigations.length === 0 ? (
          <EmptyNote>
            No other investigations share infrastructure with this domain.
            Investigate more domains to build infrastructure connections.
          </EmptyNote>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {related_investigations.map((rel) => (
              <RelatedCard
                key={rel.id}
                investigation={rel}
                onClick={() => router.push(`/investigations/${rel.id}`)}
              />
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

// ─── Sub-components ───

function RelatedCard({
  investigation,
  onClick,
}: {
  investigation: RelatedInvestigation;
  onClick: () => void;
}) {
  const classColor = CLASSIFICATION_COLORS[investigation.classification || ""] || "var(--text-muted)";

  return (
    <div
      onClick={onClick}
      style={{
        padding: "12px 16px",
        background: "var(--bg-input)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        cursor: "pointer",
        transition: "border-color 0.15s, background 0.15s",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "var(--accent)";
        e.currentTarget.style.background = "var(--accent-glow)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--border)";
        e.currentTarget.style.background = "var(--bg-input)";
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{
            fontSize: 13, fontWeight: 700, color: "var(--text)",
            fontFamily: "var(--font-mono)",
          }}>
            {investigation.domain}
          </span>
          {investigation.classification && (
            <span style={{
              fontSize: 10, fontWeight: 600, color: classColor,
              padding: "2px 8px", background: `${classColor}15`,
              borderRadius: "var(--radius-sm)", border: `1px solid ${classColor}30`,
              textTransform: "uppercase", letterSpacing: "0.04em",
              fontFamily: "var(--font-sans)",
            }}>
              {investigation.classification}
            </span>
          )}
          {investigation.risk_score != null && (
            <span style={{
              fontSize: 10, fontWeight: 600, color: "var(--text-dim)",
              fontFamily: "var(--font-mono)",
            }}>
              Risk: {investigation.risk_score}/100
            </span>
          )}
        </div>
        <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
          {investigation.created_at
            ? new Date(investigation.created_at).toLocaleDateString()
            : ""}
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {investigation.shared_infrastructure.map((si, i) => (
          <span
            key={i}
            style={{
              fontSize: 10, fontWeight: 500,
              padding: "3px 8px",
              background: `${INFRA_TYPE_COLORS[si.type] || "var(--text-muted)"}12`,
              color: INFRA_TYPE_COLORS[si.type] || "var(--text-muted)",
              border: `1px solid ${INFRA_TYPE_COLORS[si.type] || "var(--text-muted)"}25`,
              borderRadius: "var(--radius-sm)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {si.type}: {si.value}
          </span>
        ))}
      </div>
    </div>
  );
}

function PivotRow({ label, type, children }: { label: string; type: string; children: React.ReactNode }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      padding: "8px 0",
    }}>
      <div style={{
        fontSize: 11, fontWeight: 600, color: "var(--text-muted)",
        minWidth: 130, fontFamily: "var(--font-sans)",
      }}>
        {label}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {children}
      </div>
    </div>
  );
}

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span style={{
      padding: "4px 10px", fontSize: 11, fontWeight: 500,
      background: `${color}12`, color,
      border: `1px solid ${color}25`,
      borderRadius: "var(--radius-sm)",
      fontFamily: "var(--font-mono)",
    }}>
      {children}
    </span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{
        fontSize: 13, fontWeight: 600, color: "var(--accent)",
        letterSpacing: "0.01em", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-sans)",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      padding: "12px 16px", fontSize: 12, color: "var(--text-dim)",
      background: "var(--bg-input)", borderRadius: "var(--radius-sm)",
      borderLeft: "3px solid var(--text-muted)",
    }}>
      {children}
    </div>
  );
}
