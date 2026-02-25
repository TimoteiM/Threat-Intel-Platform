"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";
import { PivotResponse, RelatedInvestigation, SharedInfrastructure, CollectedEvidence } from "@/lib/types";
import GeoMap from "@/components/report/GeoMap";

interface Props {
  investigationId: string;
  evidence?: CollectedEvidence | null;
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

interface DomainModal {
  ip: string;
  domains: string[];
  total: number;
}

export default function InfrastructureTab({ investigationId, evidence }: Props) {
  const infraPivot = evidence?.infrastructure_pivot;
  const router = useRouter();
  const [data, setData] = useState<PivotResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [domainModal, setDomainModal] = useState<DomainModal | null>(null);
  const [domainSearch, setDomainSearch] = useState("");

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

      {/* Reverse IP */}
      {infraPivot && infraPivot.reverse_ip.length > 0 && (
        <Section title="Reverse IP Lookup">
          {infraPivot.reverse_ip.map((rip, i) => {
            const preview = rip.domains.slice(0, 20);
            const hasMore = rip.domains.length > 20;
            return (
              <div key={i} style={{ marginBottom: 16 }}>
                <div style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  marginBottom: 8, padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                }}>
                  <span style={{
                    fontSize: 12, fontWeight: 600,
                    color: rip.total_domains > 10 ? "var(--yellow)" : "var(--accent)",
                  }}>
                    {rip.ip} — {rip.total_domains} co-hosted domain{rip.total_domains !== 1 ? "s" : ""}
                    {rip.total_domains > 10 && " · shared hosting"}
                  </span>
                  {rip.domains.length > 20 && (
                    <button
                      onClick={() => {
                        setDomainSearch("");
                        setDomainModal({ ip: rip.ip, domains: rip.domains, total: rip.total_domains });
                      }}
                      style={{
                        padding: "4px 12px", fontSize: 11, fontWeight: 600,
                        background: "var(--bg-input)", color: "var(--accent)",
                        border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)",
                        cursor: "pointer", fontFamily: "var(--font-sans)",
                      }}
                    >
                      View all {rip.domains.length} →
                    </button>
                  )}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {preview.map((d, j) => (
                    <span key={j} style={{
                      padding: "3px 10px", fontSize: 11,
                      background: "var(--bg-input)", color: "var(--text-secondary)",
                      borderRadius: "var(--radius-sm)", border: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-mono)",
                    }}>{d}</span>
                  ))}
                  {hasMore && (
                    <button
                      onClick={() => {
                        setDomainSearch("");
                        setDomainModal({ ip: rip.ip, domains: rip.domains, total: rip.total_domains });
                      }}
                      style={{
                        padding: "3px 10px", fontSize: 11, fontWeight: 500,
                        background: "rgba(96,165,250,0.08)", color: "var(--accent)",
                        border: "1px solid rgba(96,165,250,0.25)", borderRadius: "var(--radius-sm)",
                        cursor: "pointer", fontFamily: "var(--font-mono)",
                      }}
                    >
                      +{rip.domains.length - 20} more…
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </Section>
      )}

      {/* NS Cluster */}
      {infraPivot && infraPivot.ns_clusters.length > 0 && infraPivot.ns_clusters.some(c => c.domains.length > 0) && (
        <Section title="Nameserver Clustering">
          {infraPivot.ns_clusters.map((cluster, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div style={{
                fontSize: 11, color: "var(--text-muted)", marginBottom: 6,
                fontFamily: "var(--font-mono)",
              }}>
                NS: {cluster.nameservers.slice(0, 3).join(", ")}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {cluster.domains.map((d, j) => (
                  <span key={j} style={{
                    padding: "3px 10px", fontSize: 11,
                    background: "rgba(96,165,250,0.08)", color: "var(--accent)",
                    borderRadius: "var(--radius-sm)", border: "1px solid rgba(96,165,250,0.2)",
                    fontFamily: "var(--font-mono)",
                  }}>{d}</span>
                ))}
              </div>
            </div>
          ))}
        </Section>
      )}

      {/* Registrant Pivot */}
      {infraPivot && infraPivot.registrant_pivots.length > 0 && infraPivot.registrant_pivots.some(p => p.domains.length > 0) && (
        <Section title="Registrant Pivot">
          {infraPivot.registrant_pivots.map((pivot, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                {pivot.registrar && <span>Registrar: <strong style={{ color: "var(--text-secondary)" }}>{pivot.registrar}</strong></span>}
                {pivot.registrar && pivot.registrant_org && <span style={{ margin: "0 8px" }}>·</span>}
                {pivot.registrant_org && <span>Org: <strong style={{ color: "var(--text-secondary)" }}>{pivot.registrant_org}</strong></span>}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {pivot.domains.map((d, j) => (
                  <span key={j} style={{
                    padding: "3px 10px", fontSize: 11,
                    background: "rgba(167,139,250,0.08)", color: "#a78bfa",
                    borderRadius: "var(--radius-sm)", border: "1px solid rgba(167,139,250,0.2)",
                    fontFamily: "var(--font-mono)",
                  }}>{d}</span>
                ))}
              </div>
            </div>
          ))}
        </Section>
      )}

      {/* Geolocation Map */}
      <Section title="Geolocation">
        <GeoMap investigationId={investigationId} />
      </Section>

      {/* Domain List Modal */}
      {domainModal && (
        <div
          onClick={() => setDomainModal(null)}
          style={{
            position: "fixed", inset: 0, zIndex: 1000,
            background: "rgba(0,0,0,0.65)", backdropFilter: "blur(4px)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "min(700px, 95vw)", maxHeight: "80vh",
              background: "var(--bg-surface)", border: "1px solid var(--border)",
              borderRadius: "var(--radius)", display: "flex", flexDirection: "column",
              overflow: "hidden", boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
            }}
          >
            {/* Header */}
            <div style={{
              padding: "16px 20px", borderBottom: "1px solid var(--border)",
              display: "flex", alignItems: "center", justifyContent: "space-between",
              flexShrink: 0,
            }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                  {domainModal.ip}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, fontFamily: "var(--font-sans)" }}>
                  {domainModal.domains.length} stored · {domainModal.total} total co-hosted domains
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(domainModal.domains.join("\n"));
                  }}
                  style={{
                    padding: "5px 12px", fontSize: 11, fontWeight: 600,
                    background: "rgba(96,165,250,0.08)", color: "var(--accent)",
                    border: "1px solid rgba(96,165,250,0.25)", borderRadius: "var(--radius-sm)",
                    cursor: "pointer", fontFamily: "var(--font-sans)",
                  }}
                >
                  Copy all
                </button>
                <button
                  onClick={() => setDomainModal(null)}
                  style={{
                    width: 28, height: 28, fontSize: 16, lineHeight: "28px",
                    textAlign: "center", background: "var(--bg-input)",
                    border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
                    color: "var(--text-dim)", cursor: "pointer",
                  }}
                >
                  ×
                </button>
              </div>
            </div>

            {/* Search */}
            <div style={{ padding: "10px 20px", borderBottom: "1px solid var(--border-dim)", flexShrink: 0 }}>
              <input
                autoFocus
                placeholder="Filter domains…"
                value={domainSearch}
                onChange={(e) => setDomainSearch(e.target.value)}
                style={{
                  width: "100%", padding: "7px 12px", fontSize: 12,
                  background: "var(--bg-input)", color: "var(--text)",
                  border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
                  outline: "none", fontFamily: "var(--font-mono)",
                  boxSizing: "border-box",
                }}
              />
            </div>

            {/* List */}
            <div style={{ overflowY: "auto", flex: 1, padding: "8px 0" }}>
              {(() => {
                const filtered = domainSearch.trim()
                  ? domainModal.domains.filter((d) =>
                      d.toLowerCase().includes(domainSearch.toLowerCase())
                    )
                  : domainModal.domains;
                return filtered.length === 0 ? (
                  <div style={{ padding: "20px", textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}>
                    No domains match "{domainSearch}"
                  </div>
                ) : (
                  filtered.map((d, i) => (
                    <div
                      key={i}
                      style={{
                        padding: "6px 20px", fontSize: 12,
                        fontFamily: "var(--font-mono)", color: "var(--text-secondary)",
                        borderBottom: "1px solid var(--border-dim)",
                        display: "flex", alignItems: "center", justifyContent: "space-between",
                        cursor: "default",
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-input)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      <span>{d}</span>
                      <button
                        onClick={() => navigator.clipboard.writeText(d)}
                        style={{
                          fontSize: 10, padding: "2px 8px",
                          background: "transparent", color: "var(--text-muted)",
                          border: "1px solid var(--border-dim)", borderRadius: "var(--radius-sm)",
                          cursor: "pointer", fontFamily: "var(--font-sans)",
                          opacity: 0.6,
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.opacity = "1"; }}
                        onMouseLeave={(e) => { e.currentTarget.style.opacity = "0.6"; }}
                      >
                        copy
                      </button>
                    </div>
                  ))
                );
              })()}
            </div>

            {/* Footer count */}
            <div style={{
              padding: "8px 20px", borderTop: "1px solid var(--border-dim)",
              fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)",
              flexShrink: 0,
            }}>
              {domainSearch.trim()
                ? `${domainModal.domains.filter((d) => d.toLowerCase().includes(domainSearch.toLowerCase())).length} of ${domainModal.domains.length} domains`
                : `${domainModal.domains.length} domains`}
            </div>
          </div>
        </div>
      )}
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
