"use client";

import React from "react";
import { ThreatFeedEvidence } from "@/lib/types";

interface Props {
  threatFeeds: ThreatFeedEvidence;
}

export default function ThreatFeedsSection({ threatFeeds }: Props) {
  const abuseipdb = threatFeeds.abuseipdb;
  const phishtank = threatFeeds.phishtank;
  const threatfox = threatFeeds.threatfox_matches || [];
  const openphish = threatFeeds.openphish_listed;
  const gsb = threatFeeds.google_safe_browsing;
  const otx = threatFeeds.otx;

  const abuseScore = abuseipdb?.abuse_confidence_score ?? 0;
  const hasAnyHit =
    abuseScore >= 25 ||
    phishtank?.in_database ||
    threatfox.length > 0 ||
    openphish ||
    !!gsb?.listed ||
    !!otx?.found;

  return (
    <div>
      {/* Status Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(6, 1fr)",
        gap: 8,
        marginBottom: 16,
      }}>
        <FeedStatusBox
          label="AbuseIPDB"
          status={
            abuseipdb
              ? abuseScore >= 75
                ? "danger"
                : abuseScore >= 25
                ? "warning"
                : "clean"
              : "skipped"
          }
          detail={
            abuseipdb
              ? `${abuseScore}% confidence`
              : "Not checked"
          }
        />
        <FeedStatusBox
          label="PhishTank"
          status={
            phishtank
              ? phishtank.in_database && phishtank.verified
                ? "danger"
                : phishtank.in_database
                ? "warning"
                : "clean"
              : "skipped"
          }
          detail={
            phishtank
              ? phishtank.in_database
                ? phishtank.verified
                  ? "Verified phish"
                  : "Listed (unverified)"
                : "Not in database"
              : "Not checked"
          }
        />
        <FeedStatusBox
          label="ThreatFox"
          status={
            threatFeeds.feeds_checked.includes("threatfox")
              ? threatfox.length > 0
                ? "danger"
                : "clean"
              : "skipped"
          }
          detail={
            threatFeeds.feeds_checked.includes("threatfox")
              ? threatfox.length > 0
                ? `${threatfox.length} IOC match${threatfox.length > 1 ? "es" : ""}`
                : "No IOC matches"
              : "Not checked"
          }
        />
        <FeedStatusBox
          label="OpenPhish"
          status={
            threatFeeds.feeds_checked.includes("openphish")
              ? openphish
                ? "danger"
                : "clean"
              : "skipped"
          }
          detail={
            threatFeeds.feeds_checked.includes("openphish")
              ? openphish
                ? "Listed in feed"
                : "Not in feed"
              : "Not checked"
          }
        />
        <FeedStatusBox
          label="Google Safe Browsing"
          status={
            threatFeeds.feeds_checked.includes("google_safe_browsing")
              ? gsb?.listed
                ? "danger"
                : "clean"
              : "skipped"
          }
          detail={
            threatFeeds.feeds_checked.includes("google_safe_browsing")
              ? gsb?.listed
                ? `Matched (${gsb?.matches_count || 0})`
                : "No match"
              : "Not checked"
          }
        />
        <FeedStatusBox
          label="AlienVault OTX"
          status={
            threatFeeds.feeds_checked.includes("otx")
              ? otx?.found
                ? (otx.pulse_count || 0) >= 3 ? "danger" : "warning"
                : "clean"
              : "skipped"
          }
          detail={
            threatFeeds.feeds_checked.includes("otx")
              ? otx?.found
                ? `${otx.pulse_count} pulse${otx.pulse_count === 1 ? "" : "s"}`
                : "No pulses"
              : "Not checked"
          }
        />
      </div>

      {/* AbuseIPDB Details */}
      {abuseipdb && abuseScore > 0 && (
        <div style={{ marginBottom: 14 }}>
          <SectionLabel color={abuseScore >= 75 ? "var(--red)" : "var(--yellow)"}>
            AbuseIPDB — {abuseipdb.ip}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <DetailRow label="Abuse Score" value={`${abuseScore}%`} highlight={abuseScore >= 75} />
            <DetailRow label="Total Reports" value={String(abuseipdb.total_reports)} />
            {abuseipdb.isp && <DetailRow label="ISP" value={abuseipdb.isp} />}
            {abuseipdb.usage_type && <DetailRow label="Usage Type" value={abuseipdb.usage_type} />}
            {abuseipdb.country_code && <DetailRow label="Country" value={abuseipdb.country_code} />}
            {abuseipdb.last_reported_at && (
              <DetailRow
                label="Last Reported"
                value={new Date(abuseipdb.last_reported_at).toLocaleDateString("en-US", {
                  year: "numeric", month: "short", day: "numeric",
                })}
              />
            )}
          </div>
        </div>
      )}

      {/* PhishTank Details */}
      {phishtank?.in_database && (
        <div style={{ marginBottom: 14 }}>
          <SectionLabel color={phishtank.verified ? "var(--red)" : "var(--yellow)"}>
            PhishTank — {phishtank.verified ? "Verified Phishing URL" : "Listed (Pending Verification)"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {phishtank.phish_id && <DetailRow label="Phish ID" value={phishtank.phish_id} />}
            <DetailRow label="Verified" value={phishtank.verified ? "Yes" : "No"} highlight={!!phishtank.verified} />
            {phishtank.verified_at && (
              <DetailRow label="Verified At" value={phishtank.verified_at} />
            )}
            {phishtank.target_brand && (
              <DetailRow label="Target Brand" value={phishtank.target_brand} />
            )}
          </div>
        </div>
      )}

      {/* ThreatFox IOC Matches */}
      {threatfox.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <SectionLabel color="var(--red)">
            ThreatFox — {threatfox.length} IOC Match{threatfox.length > 1 ? "es" : ""}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {threatfox.map((ioc, i) => (
              <div
                key={i}
                style={{
                  padding: "10px 14px",
                  background: "rgba(248,113,113,0.06)",
                  borderLeft: "3px solid var(--red)",
                  borderRadius: "var(--radius-sm)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span style={{
                    padding: "2px 8px", fontSize: 10, fontWeight: 700,
                    background: "rgba(248,113,113,0.15)", color: "var(--red)",
                    borderRadius: 3, letterSpacing: "0.05em",
                  }}>
                    {ioc.threat_type.toUpperCase()}
                  </span>
                  {ioc.malware && (
                    <span style={{
                      padding: "2px 8px", fontSize: 10, fontWeight: 600,
                      background: "rgba(251,191,36,0.12)", color: "var(--yellow)",
                      borderRadius: 3,
                    }}>
                      {ioc.malware}
                    </span>
                  )}
                  {ioc.confidence_level != null && (
                    <span style={{ fontSize: 10, color: "var(--text-muted)", marginLeft: "auto" }}>
                      Confidence: {ioc.confidence_level}%
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                  {ioc.ioc_value}
                </div>
                {ioc.tags.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                    {ioc.tags.map((tag, j) => (
                      <span key={j} style={{
                        padding: "1px 7px", fontSize: 10,
                        background: "var(--bg-input)", color: "var(--text-muted)",
                        borderRadius: 3, border: "1px solid var(--border-dim)",
                      }}>
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* OpenPhish */}
      {openphish && (
        <div style={{ marginBottom: 14 }}>
          <div style={{
            padding: "10px 14px",
            background: "rgba(248,113,113,0.06)",
            borderLeft: "3px solid var(--red)",
            borderRadius: "var(--radius-sm)",
            fontSize: 12, color: "var(--red)",
            fontWeight: 500,
          }}>
            Domain found in OpenPhish active phishing feed
          </div>
        </div>
      )}

      {/* Google Safe Browsing */}
      {threatFeeds.feeds_checked.includes("google_safe_browsing") && (
        <div style={{ marginBottom: 14 }}>
          <SectionLabel color={gsb?.listed ? "var(--red)" : "var(--green)"}>
            Google Safe Browsing — {gsb?.listed ? "Matched threat list" : "No matches"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <DetailRow label="Checked" value={gsb?.checked ? "Yes" : "No"} />
            <DetailRow label="Listed" value={gsb?.listed ? "Yes" : "No"} highlight={!!gsb?.listed} />
            <DetailRow label="Matches" value={String(gsb?.matches_count ?? 0)} />
            {gsb?.threat_types?.length ? <DetailRow label="Threat Types" value={gsb.threat_types.join(", ")} /> : null}
            {gsb?.platform_types?.length ? <DetailRow label="Platform Types" value={gsb.platform_types.join(", ")} /> : null}
            {gsb?.cache_durations?.length ? <DetailRow label="Cache Durations" value={gsb.cache_durations.join(", ")} /> : null}
            {gsb?.error ? <DetailRow label="Error" value={gsb.error} /> : null}
          </div>
        </div>
      )}

      {/* AlienVault OTX */}
      {threatFeeds.feeds_checked.includes("otx") && (
        <div style={{ marginBottom: 14 }}>
          <SectionLabel color={otx?.found ? "var(--yellow)" : "var(--green)"}>
            AlienVault OTX — {otx?.found ? `${otx.pulse_count} Pulse Match${otx.pulse_count === 1 ? "" : "es"}` : "No pulses"}
          </SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <DetailRow label="Checked" value={otx?.checked ? "Yes" : "No"} />
            <DetailRow label="Indicator Type" value={otx?.type_title || otx?.indicator_type || "-"} />
            <DetailRow label="Pulse Count" value={String(otx?.pulse_count ?? 0)} highlight={!!otx?.found} />
            {otx?.geo?.asn ? <DetailRow label="ASN" value={String(otx.geo.asn)} /> : null}
            {otx?.geo?.country_name ? <DetailRow label="Location" value={String(otx.geo.country_name)} /> : null}
            {otx?.ip_addresses?.length ? <DetailRow label="IP Addresses" value={otx.ip_addresses.slice(0, 4).join(", ")} /> : null}
            {otx?.nameservers?.length ? <DetailRow label="Nameservers" value={otx.nameservers.slice(0, 4).join(", ")} /> : null}
            {otx?.subdomains?.length ? <DetailRow label="Subdomains" value={String(otx.subdomains.length)} /> : null}
            {otx?.passive_dns_count ? <DetailRow label="Passive DNS Records" value={String(otx.passive_dns_count)} /> : null}
            {otx?.url_count ? <DetailRow label="Observed URLs" value={String(otx.url_count)} highlight /> : null}
            {otx?.malware_count ? <DetailRow label="Malware Samples" value={String(otx.malware_count)} highlight /> : null}
            {otx?.http_scans_count ? <DetailRow label="HTTP Scans" value={String(otx.http_scans_count)} /> : null}
            {otx?.malware_families?.length ? <DetailRow label="Malware Families" value={otx.malware_families.join(", ")} /> : null}
            {otx?.adversaries?.length ? <DetailRow label="Adversaries" value={otx.adversaries.join(", ")} /> : null}
            {otx?.tags?.length ? <DetailRow label="Tags" value={otx.tags.slice(0, 8).join(", ")} /> : null}
            {otx?.error ? <DetailRow label="Error" value={otx.error} /> : null}
          </div>
          {otx?.indicator_facts?.length ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
              {otx.indicator_facts.slice(0, 10).map((fact, i) => (
                <span key={`${fact}-${i}`} style={{
                  padding: "3px 8px", fontSize: 10, fontWeight: 700,
                  background: "rgba(251,191,36,0.12)", color: "var(--yellow)",
                  borderRadius: 3, border: "1px solid rgba(251,191,36,0.22)",
                }}>
                  {fact}
                </span>
              ))}
            </div>
          ) : null}
          {otx?.external_resources && Object.keys(otx.external_resources).length ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
              {Object.entries(otx.external_resources).slice(0, 8).map(([label, url]) => (
                <a
                  key={label}
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    padding: "3px 8px", fontSize: 10, fontWeight: 700,
                    background: "var(--bg-input)", color: "var(--blue)",
                    borderRadius: 3, border: "1px solid var(--border-dim)",
                    textDecoration: "none",
                  }}
                >
                  {label}
                </a>
              ))}
            </div>
          ) : null}
          {otx?.passive_dns?.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 8 }}>
              <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 700, letterSpacing: "0.05em" }}>
                PASSIVE DNS
              </div>
              {otx.passive_dns.slice(0, 8).map((record, i) => (
                <div
                  key={`${record.hostname || "-"}-${record.address || "-"}-${i}`}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "64px minmax(160px, 1fr) minmax(180px, 1fr) minmax(120px, 0.8fr)",
                    gap: 8,
                    alignItems: "center",
                    padding: "6px 10px",
                    background: "var(--bg-input)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 11,
                  }}
                >
                  <span style={{ color: "var(--yellow)", fontWeight: 700 }}>{record.record_type || "-"}</span>
                  <span style={{ color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{record.hostname || "-"}</span>
                  <span style={{ color: "var(--text-secondary)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{record.address || "-"}</span>
                  <span style={{ color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {record.asn || record.country || "-"}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
          {otx?.pulses?.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
              {otx.pulses.slice(0, 6).map((pulse, i) => (
                <div
                  key={`${pulse.id || pulse.name}-${i}`}
                  style={{
                    padding: "10px 14px",
                    background: "rgba(251,191,36,0.06)",
                    borderLeft: "3px solid var(--yellow)",
                    borderRadius: "var(--radius-sm)",
                  }}
                >
                  <div style={{ fontSize: 12, color: "var(--text)", fontWeight: 700 }}>
                    {pulse.name || "Unnamed pulse"}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
                    {pulse.author_name || "Unknown author"}{pulse.modified ? ` - modified ${new Date(pulse.modified).toLocaleDateString()}` : ""}{pulse.tlp ? ` - TLP:${pulse.tlp}` : ""}{pulse.subscriber_count != null ? ` - ${pulse.subscriber_count} subscribers` : ""}
                  </div>
                  {pulse.description ? (
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 6 }}>
                      {pulse.description}
                    </div>
                  ) : null}
                  {pulse.related_indicator_is_active === false ? (
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 5, fontWeight: 700 }}>
                      Indicator inactive
                    </div>
                  ) : null}
                  {pulse.tags?.length ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                      {pulse.tags.slice(0, 8).map((tag, j) => (
                        <span key={j} style={{
                          padding: "1px 7px", fontSize: 10,
                          background: "var(--bg-input)", color: "var(--text-muted)",
                          borderRadius: 3, border: "1px solid var(--border-dim)",
                        }}>
                          {tag}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      )}

      {/* No hits */}
      {!hasAnyHit && threatFeeds.feeds_checked.length > 0 && (
        <div style={{
          padding: "10px 14px", fontSize: 12, color: "var(--green)",
          background: "rgba(52,211,153,0.06)", borderRadius: "var(--radius-sm)",
          borderLeft: "3px solid var(--green)", marginBottom: 12,
        }}>
          No hits across {threatFeeds.feeds_checked.length} threat feed{threatFeeds.feeds_checked.length > 1 ? "s" : ""}
        </div>
      )}

      {/* Skipped feeds */}
      {threatFeeds.feeds_skipped.length > 0 && (
        <div style={{ fontSize: 10, color: "var(--text-muted)", fontStyle: "italic" }}>
          Skipped: {threatFeeds.feeds_skipped.join(", ")}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───

type FeedStatus = "clean" | "warning" | "danger" | "skipped";

const statusColors: Record<FeedStatus, { bg: string; border: string; text: string; dot: string }> = {
  clean:   { bg: "rgba(52,211,153,0.06)",  border: "rgba(52,211,153,0.2)",  text: "var(--green)",         dot: "var(--green)" },
  warning: { bg: "rgba(251,191,36,0.08)",  border: "rgba(251,191,36,0.2)",  text: "var(--yellow)",        dot: "var(--yellow)" },
  danger:  { bg: "rgba(248,113,113,0.08)", border: "rgba(248,113,113,0.2)", text: "var(--red)",           dot: "var(--red)" },
  skipped: { bg: "var(--bg-input)",        border: "var(--border-dim)",     text: "var(--text-muted)",    dot: "var(--text-muted)" },
};

function FeedStatusBox({ label, status, detail }: { label: string; status: FeedStatus; detail: string }) {
  const c = statusColors[status];
  return (
    <div style={{
      padding: "12px 14px",
      background: c.bg,
      border: `1px solid ${c.border}`,
      borderRadius: "var(--radius)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
        <span style={{
          width: 7, height: 7, borderRadius: "50%",
          background: c.dot, flexShrink: 0,
        }} />
        <span style={{ fontSize: 10, fontWeight: 700, color: c.text, letterSpacing: "0.05em" }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
        {detail}
      </div>
    </div>
  );
}

function SectionLabel({ children, color }: { children: React.ReactNode; color: string }) {
  return (
    <div style={{
      fontSize: 12, fontWeight: 600, color,
      letterSpacing: "0.01em", marginBottom: 8,
      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
      fontFamily: "var(--font-sans)",
    }}>
      {children}
    </div>
  );
}

function DetailRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "5px 10px",
      background: "var(--bg-input)",
      borderRadius: "var(--radius-sm)",
      fontSize: 12,
    }}>
      <span style={{ color: "var(--text-muted)", fontWeight: 500 }}>{label}</span>
      <span style={{
        color: highlight ? "var(--red)" : "var(--text-secondary)",
        fontFamily: "var(--font-mono)", fontWeight: highlight ? 600 : 400,
      }}>
        {value}
      </span>
    </div>
  );
}
