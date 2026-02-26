"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import InvestigationInput from "@/components/investigation/InvestigationInput";
import { createInvestigation, uploadFileInvestigation, listInvestigations, getDashboardStats } from "@/lib/api";
import type { ObservableType } from "@/lib/types";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Stats {
  total: number;
  threats: number;
  suspicious: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

// ─── Animated counter ────────────────────────────────────────────────────────

function useCounter(target: number, duration = 900): number {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (target === 0) return;
    let start: number | null = null;
    const step = (ts: number) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration]);
  return value;
}

// ─── Stats card ──────────────────────────────────────────────────────────────

function StatCard({ value, label, accent }: { value: number; label: string; accent?: string }) {
  const count = useCounter(value);
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      padding: "14px 24px",
      background: "var(--bg-card)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius-lg)",
      minWidth: 110,
    }}>
      <span style={{
        fontSize: 26,
        fontWeight: 800,
        fontFamily: "var(--font-mono)",
        color: accent || "var(--text)",
        letterSpacing: "0.02em",
        lineHeight: 1,
      }}>
        {count.toLocaleString()}
      </span>
      <span style={{
        fontSize: 10,
        fontWeight: 600,
        color: "var(--text-muted)",
        fontFamily: "var(--font-sans)",
        letterSpacing: "0.05em",
        textTransform: "uppercase",
        marginTop: 5,
      }}>
        {label}
      </span>
    </div>
  );
}

// ─── Collector strip ─────────────────────────────────────────────────────────

const COLLECTORS = [
  { label: "DNS Resolution",       color: "#60a5fa" },
  { label: "HTTP Analysis",        color: "#a78bfa" },
  { label: "TLS Certificate",      color: "#34d399" },
  { label: "WHOIS Registration",   color: "#fbbf24" },
  { label: "ASN & Geolocation",    color: "#60a5fa" },
  { label: "VirusTotal",           color: "#f87171" },
  { label: "AbuseIPDB",            color: "#fb923c" },
  { label: "PhishTank",            color: "#f87171" },
  { label: "ThreatFox",            color: "#fb923c" },
  { label: "Email Security",       color: "#34d399" },
  { label: "Screenshot Analysis",  color: "#a78bfa" },
  { label: "Typosquatting",        color: "#fbbf24" },
  { label: "JS Sandbox",           color: "#60a5fa" },
  { label: "Redirect Analysis",    color: "#94a3b8" },
  { label: "Cert Transparency",    color: "#34d399" },
  { label: "Infra Pivot",          color: "#a78bfa" },
  { label: "MITRE ATT&CK",         color: "#f87171" },
  { label: "Favicon Intel",        color: "#fbbf24" },
];

function CollectorStrip() {
  // Duplicate the list so the CSS loop is seamless
  const items = [...COLLECTORS, ...COLLECTORS];
  return (
    <div style={{
      overflow: "hidden",
      maskImage: "linear-gradient(to right, transparent, black 8%, black 92%, transparent)",
      WebkitMaskImage: "linear-gradient(to right, transparent, black 8%, black 92%, transparent)",
      marginTop: 20,
      marginBottom: 4,
    }}>
      <div className="collector-strip" style={{ display: "flex", gap: 8, width: "max-content" }}>
        {items.map((c, i) => (
          <span key={i} style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "5px 12px",
            background: `${c.color}12`,
            border: `1px solid ${c.color}30`,
            borderRadius: 20,
            fontSize: 11,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            color: c.color,
            whiteSpace: "nowrap",
            letterSpacing: "0.02em",
          }}>
            <span style={{
              width: 5, height: 5, borderRadius: "50%",
              background: c.color, flexShrink: 0,
            }} />
            {c.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── How it works ─────────────────────────────────────────────────────────────

const STEPS = [
  {
    icon: "⬡",
    iconBg: "linear-gradient(135deg, #60a5fa, #818cf8)",
    title: "Submit a Domain",
    desc: "Enter any suspicious domain. Optionally compare against your legitimate brand to detect impersonation.",
    tags: ["+ typosquatting check", "+ visual comparison"],
  },
  {
    icon: "◎",
    iconBg: "linear-gradient(135deg, #34d399, #60a5fa)",
    title: "10+ Collectors Run",
    desc: "DNS, HTTP, TLS, WHOIS, VirusTotal, AbuseIPDB, screenshots, email security and more — all in parallel.",
    tags: ["≈ 60–90 seconds", "parallel execution"],
  },
  {
    icon: "◈",
    iconBg: "linear-gradient(135deg, #a78bfa, #f87171)",
    title: "AI Analysis",
    desc: "Claude applies a strict 5-step methodology and classifies the domain with MITRE ATT&CK-mapped findings.",
    tags: ["Benign · Suspicious · Malicious", "IOCs extracted"],
  },
];

function HowItWorks() {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "1fr auto 1fr auto 1fr",
      gap: 0,
      alignItems: "center",
      marginTop: 28,
      marginBottom: 4,
    }}>
      {STEPS.map((step, i) => (
        <React.Fragment key={i}>
          <div style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            padding: "20px 20px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div style={{
                width: 30, height: 30,
                borderRadius: 8,
                background: step.iconBg,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 14, color: "#fff", fontWeight: 700,
                flexShrink: 0,
              }}>
                {step.icon}
              </div>
              <div style={{
                fontSize: 11,
                fontWeight: 700,
                color: "var(--text-dim)",
                letterSpacing: "0.03em",
                fontFamily: "var(--font-sans)",
                textTransform: "uppercase",
              }}>
                Step {i + 1}
              </div>
            </div>
            <div style={{
              fontSize: 14, fontWeight: 700,
              color: "var(--text)",
              fontFamily: "var(--font-sans)",
              marginBottom: 6,
            }}>
              {step.title}
            </div>
            <div style={{
              fontSize: 12, color: "var(--text-dim)",
              fontFamily: "var(--font-sans)",
              lineHeight: 1.6, marginBottom: 10,
            }}>
              {step.desc}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
              {step.tags.map((tag, j) => (
                <span key={j} style={{
                  fontSize: 10, fontWeight: 600,
                  color: "var(--text-muted)",
                  background: "var(--bg-elevated)",
                  padding: "2px 8px",
                  borderRadius: 4,
                  fontFamily: "var(--font-sans)",
                  letterSpacing: "0.02em",
                }}>
                  {tag}
                </span>
              ))}
            </div>
          </div>

          {/* Arrow connector — only between steps */}
          {i < STEPS.length - 1 && (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              padding: "0 12px",
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M5 12h14M13 6l6 6-6 6" stroke="var(--border)" strokeWidth="1.5"
                  strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// ─── Recent investigations (improved) ────────────────────────────────────────

const CLS_BAR: Record<string, string> = {
  malicious:    "#f87171",
  suspicious:   "#fbbf24",
  benign:       "#34d399",
  inconclusive: "#64748b",
};

const STATE_LABEL: Record<string, { label: string; color: string }> = {
  concluded:  { label: "concluded",  color: "var(--text-muted)" },
  gathering:  { label: "gathering",  color: "#60a5fa" },
  analyzing:  { label: "analyzing",  color: "#a78bfa" },
  pending:    { label: "pending",    color: "var(--text-muted)" },
  failed:     { label: "failed",     color: "#f87171" },
};

function RecentInvestigations({ items, onOpen }: { items: any[]; onOpen: (id: string) => void }) {
  if (items.length === 0) return null;

  return (
    <div style={{ marginTop: 24 }} className="animate-fade-up">
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 10,
      }}>
        <span style={{
          fontSize: 12, fontWeight: 700,
          color: "var(--text-dim)",
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          fontFamily: "var(--font-sans)",
        }}>
          Recent Activity
        </span>
        <a href="/investigations" style={{
          fontSize: 11, color: "var(--accent)",
          textDecoration: "none", fontFamily: "var(--font-sans)",
          fontWeight: 500,
        }}>
          View all →
        </a>
      </div>

      <div style={{
        display: "flex", flexDirection: "column",
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
        boxShadow: "var(--shadow-sm)",
      }}>
        {items.map((inv, index) => {
          const clsConfig = CLASSIFICATION_CONFIG[inv.classification as keyof typeof CLASSIFICATION_CONFIG];
          const barColor = CLS_BAR[inv.classification] || "var(--border)";
          const stateInfo = STATE_LABEL[inv.state] || { label: inv.state, color: "var(--text-muted)" };
          const isLast = index === items.length - 1;

          return (
            <button
              key={inv.id}
              onClick={() => onOpen(inv.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 0,
                background: "transparent",
                border: "none",
                borderBottom: isLast ? "none" : "1px solid var(--border-dim)",
                borderRadius: 0,
                cursor: "pointer",
                textAlign: "left",
                color: "var(--text)",
                width: "100%",
                transition: "background 0.12s",
                padding: 0,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              {/* Classification left bar */}
              <div style={{
                width: 3,
                alignSelf: "stretch",
                background: barColor,
                flexShrink: 0,
                opacity: inv.classification ? 0.8 : 0.15,
              }} />

              <div style={{
                display: "flex", alignItems: "center", gap: 14,
                padding: "12px 18px",
                flex: 1, minWidth: 0,
              }}>
                {/* Domain + observable type badge */}
                <span style={{
                  fontSize: 13, fontWeight: 600,
                  fontFamily: "var(--font-mono)",
                  color: "var(--text)",
                  flex: 1, minWidth: 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {inv.domain}
                </span>
                {inv.observable_type && inv.observable_type !== "domain" && (
                  <span style={{
                    fontSize: 9, fontWeight: 700,
                    padding: "2px 6px",
                    background: "rgba(129,140,248,0.12)",
                    color: "#818cf8",
                    border: "1px solid rgba(129,140,248,0.25)",
                    borderRadius: 3,
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "0.04em",
                    flexShrink: 0,
                    textTransform: "uppercase" as const,
                  }}>
                    {inv.observable_type}
                  </span>
                )}

                {/* Classification badge */}
                {clsConfig && (
                  <span style={{
                    fontSize: 10, fontWeight: 700,
                    padding: "2px 9px",
                    background: clsConfig.bg,
                    color: clsConfig.color,
                    borderRadius: 4,
                    fontFamily: "var(--font-sans)",
                    letterSpacing: "0.04em",
                    flexShrink: 0,
                  }}>
                    {clsConfig.label}
                  </span>
                )}

                {/* Risk score */}
                {inv.risk_score != null && (
                  <span style={{
                    fontSize: 12, fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: inv.risk_score >= 75 ? "#f87171" : inv.risk_score >= 40 ? "#fbbf24" : "#34d399",
                    minWidth: 24, textAlign: "right",
                    flexShrink: 0,
                  }}>
                    {inv.risk_score}
                  </span>
                )}

                {/* State */}
                <span style={{
                  fontSize: 10, fontWeight: 600,
                  color: stateInfo.color,
                  fontFamily: "var(--font-sans)",
                  minWidth: 70, textAlign: "right",
                  flexShrink: 0,
                  letterSpacing: "0.02em",
                }}>
                  {stateInfo.label}
                </span>

                {/* Time ago */}
                <span style={{
                  fontSize: 10, color: "var(--text-muted)",
                  fontFamily: "var(--font-sans)",
                  minWidth: 52, textAlign: "right",
                  flexShrink: 0,
                }}>
                  {timeAgo(inv.created_at)}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Duplicate investigation modal ────────────────────────────────────────────

interface SubmitArgs {
  domain: string;
  context?: string;
  clientDomain?: string;
  investigatedUrl?: string;
  clientUrl?: string;
  requestedCollectors?: string[];
  observableType?: ObservableType;
  fileToUpload?: File;
}

function getTypeLabel(observableType?: string): string {
  const labels: Record<string, string> = {
    domain: "Domain",
    ip: "IP Address",
    hash: "Hash",
    email: "Email",
    file: "File",
    url: "URL",
  };
  return labels[observableType || "domain"] || (observableType || "Observable");
}

function DuplicateModal({
  existing,
  observableType,
  onViewExisting,
  onRunNew,
  onClose,
}: {
  existing: any[];
  observableType?: string;
  onViewExisting: (id: string) => void;
  onRunNew: () => void;
  onClose: () => void;
}) {
  const best = existing[0]; // most recent
  const clsConfig = CLASSIFICATION_CONFIG[best?.classification as keyof typeof CLASSIFICATION_CONFIG];
  const typeLabel = getTypeLabel(observableType);

  return (
    /* Backdrop */
    <div
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 200,
        background: "rgba(0,0,0,0.6)",
        backdropFilter: "blur(4px)",
        display: "flex", alignItems: "center", justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="animate-scale-in"
        style={{
          position: "relative",
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          padding: 28,
          maxWidth: 440,
          width: "100%",
          boxShadow: "var(--shadow-lg)",
        }}
      >
        {/* Header */}
        <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 20 }}>
          <div style={{
            width: 38, height: 38, borderRadius: 10, flexShrink: 0,
            background: "rgba(251,191,36,0.12)",
            border: "1px solid rgba(251,191,36,0.25)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18,
          }}>
            ⚠
          </div>
          <div>
            <div style={{
              fontSize: 15, fontWeight: 700,
              color: "var(--text)", fontFamily: "var(--font-sans)",
              marginBottom: 4,
            }}>
              {typeLabel} already investigated
            </div>
            <div style={{
              fontSize: 12, color: "var(--text-dim)",
              fontFamily: "var(--font-sans)", lineHeight: 1.5,
            }}>
              This {typeLabel.toLowerCase()} has {existing.length > 1 ? `${existing.length} previous investigations` : "a previous investigation"}.
              Viewing the existing report saves time and API resources.
            </div>
          </div>
        </div>

        {/* Existing investigation preview */}
        <div style={{
          background: "var(--bg-elevated)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: "14px 16px",
          marginBottom: 20,
        }}>
          <div style={{
            fontSize: 11, fontWeight: 600,
            color: "var(--text-muted)", letterSpacing: "0.05em",
            textTransform: "uppercase", fontFamily: "var(--font-sans)",
            marginBottom: 10,
          }}>
            Most Recent Result
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span style={{
              fontSize: 13, fontWeight: 600,
              fontFamily: "var(--font-mono)",
              color: "var(--text)", flex: 1, minWidth: 0,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {best?.domain}
            </span>

            {clsConfig && (
              <span style={{
                fontSize: 10, fontWeight: 700,
                padding: "3px 10px",
                background: clsConfig.bg,
                color: clsConfig.color,
                borderRadius: 4,
                fontFamily: "var(--font-sans)",
                letterSpacing: "0.04em",
                flexShrink: 0,
              }}>
                {clsConfig.label}
              </span>
            )}

            {best?.risk_score != null && (
              <span style={{
                fontSize: 13, fontWeight: 700,
                fontFamily: "var(--font-mono)",
                color: best.risk_score >= 75 ? "#f87171" : best.risk_score >= 40 ? "#fbbf24" : "#34d399",
                flexShrink: 0,
              }}>
                {best.risk_score}
              </span>
            )}
          </div>

          <div style={{
            display: "flex", gap: 16, marginTop: 8,
            fontSize: 11, color: "var(--text-muted)",
            fontFamily: "var(--font-sans)",
          }}>
            <span>{timeAgo(best?.created_at)}</span>
            {existing.length > 1 && (
              <span>+{existing.length - 1} older result{existing.length > 2 ? "s" : ""}</span>
            )}
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={() => onViewExisting(best?.id)}
            style={{
              flex: 1,
              padding: "11px 16px",
              background: "linear-gradient(135deg, #60a5fa, #818cf8)",
              border: "none",
              borderRadius: "var(--radius)",
              color: "#fff",
              fontSize: 13, fontWeight: 600,
              fontFamily: "var(--font-sans)",
              cursor: "pointer",
              boxShadow: "0 2px 8px rgba(96,165,250,0.3)",
            }}
          >
            View Existing Report
          </button>
          <button
            onClick={onRunNew}
            style={{
              flex: 1,
              padding: "11px 16px",
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--text-dim)",
              fontSize: 13, fontWeight: 600,
              fontFamily: "var(--font-sans)",
              cursor: "pointer",
            }}
          >
            Run New Investigation
          </button>
        </div>

        <button
          onClick={onClose}
          style={{
            position: "absolute", top: 14, right: 14,
            background: "none", border: "none",
            color: "var(--text-muted)", cursor: "pointer",
            fontSize: 18, padding: "2px 6px",
            borderRadius: 4,
          }}
        >
          ×
        </button>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function HomePage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [recent, setRecent] = useState<any[]>([]);
  const [stats, setStats] = useState<Stats>({ total: 0, threats: 0, suspicious: 0 });

  // Duplicate-check modal state
  const [duplicates, setDuplicates] = useState<any[] | null>(null);
  const [pendingArgs, setPendingArgs] = useState<SubmitArgs | null>(null);

  useEffect(() => {
    listInvestigations({ limit: 10 })
      .then((data) => setRecent(data.items))
      .catch(() => {});

    getDashboardStats()
      .then((data: any) => {
        const breakdown = data.classification_breakdown || {};
        setStats({
          total:      data.total_investigations || 0,
          threats:    breakdown.malicious || 0,
          suspicious: breakdown.suspicious || 0,
        });
      })
      .catch(() => {});
  }, []);

  const doCreate = useCallback(async (args: SubmitArgs) => {
    setLoading(true);
    setDuplicates(null);
    setPendingArgs(null);
    try {
      let investigationId: string;

      if (args.observableType === "file" && args.fileToUpload) {
        // File upload goes through a dedicated multipart endpoint
        const result = await uploadFileInvestigation(args.fileToUpload, args.context);
        investigationId = result.investigation_id;
      } else {
        const result = await createInvestigation({
          domain:               args.domain,
          observable_type:      args.observableType,
          context:              args.context,
          client_domain:        args.clientDomain,
          investigated_url:     args.investigatedUrl,
          client_url:           args.clientUrl,
          requested_collectors: args.requestedCollectors,
        });
        investigationId = result.investigation_id;
      }

      router.push(`/investigations/${investigationId}`);
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
      setLoading(false);
    }
  }, [router]);

  const handleSubmit = useCallback(
    async (
      domain: string,
      context?: string,
      clientDomain?: string,
      investigatedUrl?: string,
      clientUrl?: string,
      requestedCollectors?: string[],
      observableType?: ObservableType,
      fileToUpload?: File,
    ) => {
      const args: SubmitArgs = {
        domain, context, clientDomain, investigatedUrl, clientUrl,
        requestedCollectors, observableType, fileToUpload,
      };

      // Duplicate check for all observable types
      try {
        const effectiveType = observableType || "domain";
        const data = await listInvestigations({
          search: domain, limit: 10, state: "concluded",
          observable_type: effectiveType,
        });
        const exact = (data.items || []).filter(
          (inv: any) =>
            inv.domain.toLowerCase() === domain.toLowerCase() &&
            (inv.observable_type || "domain") === effectiveType,
        );
        if (exact.length > 0) {
          setPendingArgs(args);
          setDuplicates(exact);
          return; // wait for user choice in modal
        }
      } catch {
        // if check fails, proceed normally
      }

      await doCreate(args);
    },
    [doCreate],
  );

  const totalHighRisk = stats.threats + stats.suspicious;

  return (
    <div style={{ paddingBottom: 56 }}>

      {/* ── Duplicate modal ── */}
      {duplicates && pendingArgs && (
        <DuplicateModal
          existing={duplicates}
          observableType={pendingArgs.observableType}
          onViewExisting={(id) => router.push(`/investigations/${id}`)}
          onRunNew={() => doCreate(pendingArgs)}
          onClose={() => { setDuplicates(null); setPendingArgs(null); }}
        />
      )}

      {/* ── Hero ── */}
      <div style={{
        textAlign: "center",
        paddingTop: 40,
        paddingBottom: 8,
      }} className="animate-in">

        <div style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "4px 12px",
          background: "rgba(96,165,250,0.08)",
          border: "1px solid rgba(96,165,250,0.2)",
          borderRadius: 20,
          marginBottom: 16,
        }}>
          <span style={{
            width: 6, height: 6, borderRadius: "50%",
            background: "#60a5fa",
            display: "inline-block",
            animation: "pulse 2s ease-in-out infinite",
          }} />
          <span style={{
            fontSize: 11, fontWeight: 600, color: "#60a5fa",
            fontFamily: "var(--font-sans)", letterSpacing: "0.04em",
          }}>
            AI-Powered · Evidence-Based · MITRE ATT&CK Mapped
          </span>
        </div>

        <h1 style={{
          fontSize: 32,
          fontWeight: 800,
          fontFamily: "var(--font-mono)",
          color: "var(--text)",
          letterSpacing: "0.01em",
          lineHeight: 1.2,
          marginBottom: 10,
        }}>
          Domain Threat Investigation
        </h1>

        <p style={{
          fontSize: 14,
          color: "var(--text-dim)",
          fontFamily: "var(--font-sans)",
          maxWidth: 480,
          margin: "0 auto 24px",
          lineHeight: 1.6,
        }}>
          Submit a domain and get a full analyst-grade report in under 90 seconds —
          classification, IOCs, findings, and actionable SOC steps.
        </p>

        {/* Stats row — only shown if data exists */}
        {stats.total > 0 && (
          <div style={{
            display: "inline-flex",
            gap: 10,
            justifyContent: "center",
            flexWrap: "wrap",
          }}>
            <StatCard value={stats.total}      label="Investigated" />
            <StatCard value={stats.threats}    label="Threats Found"  accent="#f87171" />
            <StatCard value={totalHighRisk}    label="High Risk"      accent="#fbbf24" />
          </div>
        )}
      </div>

      {/* ── Collector strip ── */}
      <CollectorStrip />

      {/* ── How it works ── */}
      <HowItWorks />

      {/* ── Investigation form ── */}
      <InvestigationInput onSubmit={handleSubmit} loading={loading} />

      {/* ── Recent investigations ── */}
      <RecentInvestigations
        items={recent}
        onOpen={(id) => router.push(`/investigations/${id}`)}
      />

    </div>
  );
}
