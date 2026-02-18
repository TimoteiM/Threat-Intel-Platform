"use client";

import React from "react";
import { CollectedEvidence } from "@/lib/types";
import { getArtifactUrl } from "@/lib/api";
import EvidenceTable from "@/components/evidence/EvidenceTable";
import VisualComparisonSection from "@/components/report/VisualComparisonSection";

interface Props {
  evidence: CollectedEvidence;
}

export default function TechnicalEvidenceTab({ evidence }: Props) {
  const dns = evidence?.dns || ({} as any);
  const tls = evidence?.tls || ({} as any);
  const http = evidence?.http || ({} as any);
  const whois = evidence?.whois || ({} as any);
  const hosting = evidence?.hosting || ({} as any);
  const intel = evidence?.intel || ({} as any);
  const vt = evidence?.vt || ({} as any);

  return (
    <div>
      {/* DNS */}
      <Section title="DNS Records">
        {(() => {
          const hasLiveDns = arr(dns.a).length > 0 || arr(dns.aaaa).length > 0;
          const vtDns = arr(vt.vt_dns_records);
          const vtA = vtDns.filter((r: any) => r?.type === "A").map((r: any) => r?.value).filter(Boolean);
          const vtAAAA = vtDns.filter((r: any) => r?.type === "AAAA").map((r: any) => r?.value).filter(Boolean);
          const hasVtDns = vtA.length > 0 || vtAAAA.length > 0;

          if (hasLiveDns) {
            return (
              <EvidenceTable
                title="A / AAAA Records"
                data={[
                  ...arr(dns.a).map((ip: string) => ({ field: "A", value: ip })),
                  ...arr(dns.aaaa).map((ip: string) => ({ field: "AAAA", value: ip })),
                ]}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
            );
          }

          if (hasVtDns) {
            return (
              <>
                <EmptyNote>No live A/AAAA records found — showing VT passive DNS (historical)</EmptyNote>
                <EvidenceTable
                  title="A / AAAA Records (VT Passive DNS)"
                  data={[
                    ...vtA.map((ip: string) => ({ field: "A", value: ip, source: "VT" })),
                    ...vtAAAA.map((ip: string) => ({ field: "AAAA", value: ip, source: "VT" })),
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }, { key: "source" }]}
                />
              </>
            );
          }

          return <EmptyNote>No A/AAAA records found</EmptyNote>;
        })()}

        {(() => {
          const liveCnames = arr(dns.cname);
          const vtDns = arr(vt.vt_dns_records);
          const vtCNAME = vtDns.filter((r: any) => r?.type === "CNAME").map((r: any) => r?.value).filter(Boolean);

          if (liveCnames.length > 0) {
            return (
              <EvidenceTable
                title="CNAME"
                data={liveCnames.map((c: string) => ({ field: "CNAME", value: c }))}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
            );
          }

          if (vtCNAME.length > 0) {
            return (
              <EvidenceTable
                title="CNAME (VT Passive DNS)"
                data={vtCNAME.map((c: string) => ({ field: "CNAME", value: c, source: "VT" }))}
                columns={[{ key: "field" }, { key: "value", wrap: true }, { key: "source" }]}
              />
            );
          }

          return null;
        })()}

        {arr(dns.ns).length > 0 && (
          <EvidenceTable
            title="Name Servers"
            data={arr(dns.ns).map((ns: string) => ({ field: "NS", value: ns }))}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
        )}

        <EvidenceTable
          title="Mail & Policy"
          data={[
            { field: "MX", value: arr(dns.mx).join(", ") || "None" },
            { field: "SPF", value: dns.spf || "None" },
            { field: "DMARC", value: dns.dmarc || "Not configured" },
          ]}
          columns={[{ key: "field" }, { key: "value", wrap: true }]}
        />
      </Section>

      {/* TLS */}
      <Section title="TLS Certificate">
        {tls.present === false ? (
          <EmptyNote>No TLS certificate present</EmptyNote>
        ) : (
          <EvidenceTable
            data={[
              { field: "Present", value: tls.present ?? "Unknown" },
              { field: "Issuer", value: tls.issuer_org || tls.issuer || "—" },
              { field: "Subject", value: tls.subject || "—" },
              { field: "SANs", value: arr(tls.sans).join(", ") || "—" },
              { field: "Valid From", value: fmtDate(tls.valid_from) },
              { field: "Valid To", value: fmtDate(tls.valid_to) },
              { field: "Days Remaining", value: tls.valid_days_remaining ?? "—" },
              { field: "Self-Signed", value: tls.is_self_signed },
              { field: "Wildcard", value: tls.is_wildcard },
              { field: "SHA-256", value: tls.cert_sha256 || "—" },
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
        )}
      </Section>

      {/* HTTP */}
      <Section title="HTTP Response">
        {http.reachable === false && !http.final_url ? (
          <EmptyNote>Domain not reachable over HTTP/HTTPS</EmptyNote>
        ) : (
          <>
            <EvidenceTable
              title="Connection"
              data={[
                { field: "Reachable", value: http.reachable ?? "Unknown" },
                { field: "Final URL", value: http.final_url || "—" },
                { field: "Status Code", value: http.final_status_code ?? "—" },
                { field: "Server", value: http.server || "—" },
                { field: "Title", value: http.title || "—" },
                { field: "Login Form", value: http.has_login_form ? "⚠ Yes" : "No" },
                { field: "Redirects", value: arr(http.redirect_chain).length },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />

            {arr(http.redirect_chain).length > 0 && (
              <EvidenceTable
                title="Redirect Chain"
                data={arr(http.redirect_chain).map((r: any, i: number) => ({
                  step: `${i + 1}`,
                  url: r?.url || r?.location || "—",
                  status: r?.status_code === 0 ? "JS/Meta" : (r?.status_code ?? "—"),
                }))}
                columns={[{ key: "step" }, { key: "url", wrap: true }, { key: "status" }]}
              />
            )}

            {http.security_headers && Object.keys(http.security_headers).length > 0 && (
              <EvidenceTable
                title="Security Headers"
                data={Object.entries(http.security_headers).map(([k, v]) => ({
                  header: k,
                  value: String(v ?? ""),
                }))}
                columns={[{ key: "header" }, { key: "value", wrap: true }]}
              />
            )}

            {arr(http.technologies_detected).length > 0 && (
              <EvidenceTable
                title="Technologies"
                data={arr(http.technologies_detected).map((t: string) => ({
                  field: "Detected",
                  value: t,
                }))}
                columns={[{ key: "field" }, { key: "value" }]}
              />
            )}
          </>
        )}
      </Section>

      {/* CONTENT ANALYSIS */}
      {(arr(http.phishing_indicators).length > 0 ||
        arr(http.brand_indicators).length > 0 ||
        arr(http.external_resources).length > 0 ||
        http.favicon_hash) && (
        <Section title="Content Analysis">
          {/* Phishing indicators */}
          {arr(http.phishing_indicators).length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 12, fontWeight: 600, color: "var(--red)",
                letterSpacing: "0.01em", marginBottom: 8,
                padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                fontFamily: "var(--font-sans)",
              }}>
                Phishing Kit Indicators ({arr(http.phishing_indicators).length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {arr(http.phishing_indicators).map((indicator: string, i: number) => (
                  <div key={i} style={{
                    padding: "8px 12px",
                    background: "rgba(248,113,113,0.06)",
                    borderLeft: "3px solid var(--red)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 12, color: "var(--text-secondary)",
                    fontFamily: "var(--font-mono)",
                  }}>
                    {indicator}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Brand impersonation */}
          {arr(http.brand_indicators).length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 12, fontWeight: 600, color: "var(--yellow)",
                letterSpacing: "0.01em", marginBottom: 8,
                padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                fontFamily: "var(--font-sans)",
              }}>
                Brand Impersonation Phrases ({arr(http.brand_indicators).length})
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {arr(http.brand_indicators).map((phrase: string, i: number) => (
                  <span key={i} style={{
                    padding: "4px 10px", fontSize: 11, fontWeight: 500,
                    background: "rgba(251,191,36,0.10)", color: "var(--yellow)",
                    borderRadius: "var(--radius-sm)", border: "1px solid rgba(251,191,36,0.2)",
                    fontFamily: "var(--font-mono)",
                  }}>
                    {phrase}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Favicon hash */}
          {http.favicon_hash && (
            <div style={{ marginBottom: 16 }}>
              <EvidenceTable
                title="Favicon"
                data={[
                  { field: "Favicon Hash", value: http.favicon_hash },
                  { field: "Compatibility", value: "Shodan (MurmurHash3)" },
                ]}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
            </div>
          )}

          {/* External resources */}
          {arr(http.external_resources).length > 0 && (
            <div>
              <div style={{
                fontSize: 12, fontWeight: 600, color: "var(--text-secondary)",
                letterSpacing: "0.01em", marginBottom: 8,
                padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                fontFamily: "var(--font-sans)",
              }}>
                External Resource Domains ({arr(http.external_resources).length})
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {arr(http.external_resources).map((domain: string, i: number) => (
                  <span key={i} style={{
                    padding: "4px 10px", fontSize: 11, fontWeight: 500,
                    background: "var(--bg-input)", color: "var(--text-dim)",
                    borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
                    fontFamily: "var(--font-mono)",
                  }}>
                    {domain}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Section>
      )}

      {/* WHOIS */}
      <Section title="WHOIS Registration">
        {whois.meta?.status === "failed" ? (
          <EmptyNote>WHOIS lookup failed: {whois.meta?.error || "unknown error"}</EmptyNote>
        ) : (
          <EvidenceTable
            data={[
              { field: "Registrar", value: whois.registrar || "—" },
              { field: "Created", value: fmtDate(whois.created_date) },
              { field: "Updated", value: fmtDate(whois.updated_date) },
              { field: "Expires", value: fmtDate(whois.expiry_date) },
              { field: "Domain Age", value: whois.domain_age_days != null ? `${whois.domain_age_days} days` : "—" },
              { field: "Privacy", value: whois.privacy_protected == null ? "—" : whois.privacy_protected ? "⚠ Yes" : "No" },
              { field: "Registrant Org", value: whois.registrant_org || "—" },
              { field: "Country", value: whois.registrant_country || "Redacted" },
              ...(arr(whois.name_servers).length > 0
                ? [{ field: "Name Servers", value: arr(whois.name_servers).join(", ") }]
                : []),
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
        )}
      </Section>

      {/* Hosting */}
      <Section title="Hosting / ASN">
        {hosting.meta?.status === "failed" ? (
          <EmptyNote>ASN lookup failed: {hosting.meta?.error || "unknown error"}</EmptyNote>
        ) : (
          <EvidenceTable
            data={[
              { field: "IP", value: hosting.ip || "—" },
              { field: "ASN", value: hosting.asn ? `AS${hosting.asn}` : "—" },
              { field: "Organization", value: hosting.asn_org || "—" },
              { field: "ISP", value: hosting.asn_description || "—" },
              { field: "Country", value: hosting.country || "—" },
              { field: "City", value: hosting.city || "—" },
              { field: "CDN", value: hosting.is_cdn },
              { field: "Cloud", value: hosting.is_cloud },
              { field: "Hosting", value: hosting.is_hosting },
              ...(hosting.reverse_dns ? [{ field: "Reverse DNS", value: hosting.reverse_dns }] : []),
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
        )}
      </Section>

      {/* VISUAL COMPARISON (only shown when client_domain was provided) */}
      {evidence?.visual_comparison && (
        <Section title="Visual Comparison">
          <VisualComparisonSection visual={evidence.visual_comparison} />
        </Section>
      )}

      {/* DOMAIN SCREENSHOT (always captured) */}
      {evidence?.screenshot && (
        <Section title="Domain Screenshot">
          {evidence.screenshot.capture_error ? (
            <EmptyNote>Screenshot capture failed: {evidence.screenshot.capture_error}</EmptyNote>
          ) : evidence.screenshot.artifact_id ? (
            <div>
              <div style={{
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
                overflow: "hidden",
                marginBottom: 8,
              }}>
                <img
                  src={getArtifactUrl(evidence.screenshot.artifact_id)}
                  alt={`Screenshot of ${evidence.domain}`}
                  style={{
                    width: "100%",
                    height: "auto",
                    display: "block",
                  }}
                />
              </div>
              {evidence.screenshot.final_url && (
                <div style={{
                  fontSize: 11, color: "var(--text-muted)",
                  fontFamily: "var(--font-mono)",
                }}>
                  Final URL: {evidence.screenshot.final_url}
                </div>
              )}
            </div>
          ) : (
            <EmptyNote>No screenshot available</EmptyNote>
          )}
        </Section>
      )}

      {/* SUBDOMAIN ENUMERATION */}
      {evidence?.subdomains && evidence.subdomains.discovered_count > 0 && (
        <Section title="Subdomain Enumeration">
          {/* Stats row */}
          <div style={{
            display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8,
            marginBottom: 16,
          }}>
            <SubStatBox label="Discovered" value={evidence.subdomains.discovered_count} color="var(--accent)" />
            <SubStatBox label="Resolved" value={evidence.subdomains.resolved.length} color="var(--green)" />
            <SubStatBox label="Unresolved" value={evidence.subdomains.unresolved.length} color="var(--text-muted)" />
            <SubStatBox label="Interesting" value={evidence.subdomains.interesting_subdomains.length} color="var(--yellow)" />
          </div>

          {/* Interesting subdomains */}
          {evidence.subdomains.interesting_subdomains.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 12, fontWeight: 600, color: "var(--yellow)",
                letterSpacing: "0.01em", marginBottom: 8,
                padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                fontFamily: "var(--font-sans)",
              }}>
                Interesting Subdomains ({evidence.subdomains.interesting_subdomains.length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {evidence.subdomains.interesting_subdomains.map((entry, i) => (
                  <div key={i} style={{
                    padding: "8px 12px",
                    background: "rgba(251,191,36,0.06)",
                    borderLeft: "3px solid var(--yellow)",
                    borderRadius: "var(--radius-sm)",
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                  }}>
                    <span style={{
                      fontSize: 12, fontWeight: 600, color: "var(--text)",
                      fontFamily: "var(--font-mono)",
                    }}>
                      {entry.subdomain}
                    </span>
                    <span style={{
                      fontSize: 10, color: "var(--text-dim)",
                      fontFamily: "var(--font-mono)",
                    }}>
                      {entry.ips.join(", ")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IP groups */}
          {Object.keys(evidence.subdomains.ip_groups).length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 12, fontWeight: 600, color: "var(--text-secondary)",
                letterSpacing: "0.01em", marginBottom: 8,
                padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                fontFamily: "var(--font-sans)",
              }}>
                IP Groupings ({Object.keys(evidence.subdomains.ip_groups).length} IPs)
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {Object.entries(evidence.subdomains.ip_groups).slice(0, 20).map(([ip, subs]) => (
                  <div key={ip} style={{
                    padding: "6px 12px",
                    background: "var(--bg-input)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: 11,
                    display: "flex", gap: 8, alignItems: "baseline",
                  }}>
                    <span style={{
                      fontWeight: 700, color: "var(--text)",
                      fontFamily: "var(--font-mono)", minWidth: 110,
                    }}>
                      {ip}
                    </span>
                    <span style={{ color: "var(--accent)", fontWeight: 600, minWidth: 20 }}>
                      {(subs as string[]).length}
                    </span>
                    <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                      {(subs as string[]).slice(0, 3).join(", ")}
                      {(subs as string[]).length > 3 ? ` +${(subs as string[]).length - 3} more` : ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Resolved list */}
          {evidence.subdomains.resolved.length > 0 && (
            <EvidenceTable
              title={`All Resolved (${evidence.subdomains.resolved.length})`}
              data={evidence.subdomains.resolved.slice(0, 50).map((entry) => ({
                subdomain: entry.subdomain,
                ips: entry.ips.join(", "),
                flag: entry.is_interesting ? "★" : "",
              }))}
              columns={[
                { key: "subdomain", wrap: true },
                { key: "ips", wrap: true },
                { key: "flag" },
              ]}
            />
          )}
        </Section>
      )}

      {/* VIRUSTOTAL */}
      <Section title="VirusTotal Reputation">
        {vt.meta?.status === "failed" ? (
          <EmptyNote>VirusTotal lookup failed: {vt.meta?.error || "unknown error"}</EmptyNote>
        ) : !vt.found && vt.meta?.status !== "completed" ? (
          <EmptyNote>VirusTotal data not available (API key not configured or collector not run)</EmptyNote>
        ) : !vt.found ? (
          <EmptyNote>Domain not found in VirusTotal database</EmptyNote>
        ) : (
          <>
            {/* Detection summary bar */}
            <div style={{
              display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8,
              marginBottom: 16,
            }}>
              <VTStatBox
                label="Malicious"
                count={vt.malicious_count || 0}
                total={vt.total_vendors || 0}
                color="var(--red)"
                highlight={vt.malicious_count > 0}
              />
              <VTStatBox
                label="Suspicious"
                count={vt.suspicious_count || 0}
                total={vt.total_vendors || 0}
                color="var(--yellow)"
                highlight={vt.suspicious_count > 0}
              />
              <VTStatBox
                label="Harmless"
                count={vt.harmless_count || 0}
                total={vt.total_vendors || 0}
                color="var(--green)"
                highlight={false}
              />
              <VTStatBox
                label="Undetected"
                count={vt.undetected_count || 0}
                total={vt.total_vendors || 0}
                color="var(--text-dim)"
                highlight={false}
              />
            </div>

            {/* Flagging vendors — most critical info */}
            {arr(vt.flagged_malicious_by).length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: "var(--red)",
                  letterSpacing: "0.01em", marginBottom: 8,
                  padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                  fontFamily: "var(--font-sans)",
                }}>
                  Flagged Malicious ({arr(vt.flagged_malicious_by).length} vendors)
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {arr(vt.flagged_malicious_by).map((vendor: string, i: number) => (
                    <span key={i} style={{
                      padding: "4px 10px", fontSize: 11, fontWeight: 500,
                      background: "rgba(248,113,113,0.10)", color: "var(--red)",
                      borderRadius: "var(--radius-sm)", border: "1px solid rgba(248,113,113,0.2)",
                      fontFamily: "var(--font-mono)",
                    }}>
                      {vendor}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {arr(vt.flagged_suspicious_by).length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: "var(--yellow)",
                  letterSpacing: "0.01em", marginBottom: 8,
                  fontFamily: "var(--font-sans)",
                }}>
                  Flagged Suspicious ({arr(vt.flagged_suspicious_by).length} vendors)
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {arr(vt.flagged_suspicious_by).map((vendor: string, i: number) => (
                    <span key={i} style={{
                      padding: "4px 10px", fontSize: 11, fontWeight: 500,
                      background: "rgba(251,191,36,0.10)", color: "var(--yellow)",
                      borderRadius: "var(--radius-sm)", border: "1px solid rgba(251,191,36,0.2)",
                      fontFamily: "var(--font-mono)",
                    }}>
                      {vendor}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Categories */}
            {vt.categories && Object.keys(vt.categories).length > 0 && (
              <EvidenceTable
                title="Domain Categories (per service)"
                data={Object.entries(vt.categories).map(([service, cat]) => ({
                  field: service, value: String(cat),
                }))}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
            )}

            {/* Metadata */}
            <EvidenceTable
              title="VT Metadata"
              data={[
                { field: "Community Reputation", value: vt.reputation_score ?? "—" },
                { field: "Last Analysis", value: fmtDate(vt.last_analysis_date) },
                { field: "VT Registrar", value: vt.vt_registrar || "—" },
                { field: "VT Cert Issuer", value: vt.vt_cert_issuer || "—" },
                ...(arr(vt.tags).length > 0
                  ? [{ field: "Tags", value: arr(vt.tags).join(", ") }]
                  : []),
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />

            {/* VT DNS records */}
            {arr(vt.vt_dns_records).length > 0 && (
              <EvidenceTable
                title={`VT Passive DNS (${arr(vt.vt_dns_records).length} records)`}
                data={arr(vt.vt_dns_records).slice(0, 20).map((r: any) => ({
                  type: r?.type || "?",
                  value: r?.value || "—",
                  ttl: r?.ttl ?? "—",
                }))}
                columns={[{ key: "type" }, { key: "value", wrap: true }, { key: "ttl" }]}
              />
            )}

            {/* Popularity ranks */}
            {vt.popularity_ranks && Object.keys(vt.popularity_ranks).length > 0 && (
              <EvidenceTable
                title="Popularity Ranks"
                data={Object.entries(vt.popularity_ranks).map(([service, rank]) => ({
                  field: service, value: `#${rank}`,
                }))}
                columns={[{ key: "field" }, { key: "value" }]}
              />
            )}
          </>
        )}
      </Section>

      {/* INTEL / REPUTATION */}
      <Section title="Threat Intelligence">
        {intel.meta?.status === "failed" ? (
          <EmptyNote>Intel lookup failed: {intel.meta?.error || "unknown error"}</EmptyNote>
        ) : (
          <>
            {arr(intel.blocklist_hits).length > 0 ? (
              <div style={{ marginBottom: 16 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: "var(--red)",
                  letterSpacing: "0.01em", marginBottom: 8,
                  padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                  fontFamily: "var(--font-sans)",
                }}>
                  Blocklist Hits ({arr(intel.blocklist_hits).length})
                </div>
                {arr(intel.blocklist_hits).map((hit: any, i: number) => (
                  <div key={i} style={{
                    padding: "8px 12px",
                    background: "rgba(248,113,113,0.06)",
                    borderLeft: "3px solid var(--red)",
                    borderRadius: "var(--radius-sm)",
                    marginBottom: 4,
                    fontSize: 12,
                  }}>
                    <span style={{ color: "var(--red)", fontWeight: 600 }}>{hit?.source || "Unknown"}</span>
                    <span style={{ color: "var(--text-dim)", margin: "0 8px" }}>-</span>
                    <span style={{ color: "var(--text-secondary)" }}>{hit?.details || hit?.category || ""}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{
                padding: "10px 14px", fontSize: 12, color: "var(--green)",
                background: "rgba(52,211,153,0.06)", borderRadius: "var(--radius-sm)",
                borderLeft: "3px solid var(--green)", marginBottom: 16,
              }}>
                No blocklist hits detected
              </div>
            )}

            {arr(intel.related_subdomains).length > 0 && (
              <EvidenceTable
                title={`Subdomains (crt.sh) — ${arr(intel.related_subdomains).length} found`}
                data={arr(intel.related_subdomains).slice(0, 30).map((s: string) => ({
                  field: "subdomain", value: s,
                }))}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
            )}

            {arr(intel.related_certs).length > 0 && (
              <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                Related certificates in CT logs: {arr(intel.related_certs).length}
              </div>
            )}

            {arr(intel.notes).length > 0 && (
              <div style={{ marginTop: 12 }}>
                {arr(intel.notes).map((note: string, i: number) => (
                  <div key={i} style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                    ℹ {note}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </Section>

      {/* Collector Metadata */}
      <Section title="Collector Metadata">
        <EvidenceTable
          data={[
            metaRow("DNS", dns.meta),
            metaRow("TLS", tls.meta),
            metaRow("HTTP", http.meta),
            metaRow("WHOIS", whois.meta),
            metaRow("ASN", hosting.meta),
            metaRow("INTEL", intel.meta),
            metaRow("VT", vt.meta),
          ].filter(Boolean) as any[]}
          columns={[
            { key: "collector" },
            { key: "status" },
            { key: "duration" },
            { key: "error", wrap: true },
          ]}
        />
      </Section>
    </div>
  );
}

// ─── Helpers ───

/** Safely coerce anything to an array */
function arr(val: any): any[] {
  if (Array.isArray(val)) return val;
  return [];
}

/** Format a date string, return "—" if missing */
function fmtDate(val: string | null | undefined): string {
  if (!val) return "—";
  try {
    return new Date(val).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return String(val);
  }
}

/** Build a metadata summary row */
function metaRow(name: string, meta: any) {
  if (!meta) return null;
  return {
    collector: name,
    status: meta.status || "—",
    duration: meta.duration_ms != null ? `${meta.duration_ms}ms` : "—",
    error: meta.error || "—",
  };
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

function SubStatBox({ label, value, color }: {
  label: string; value: number; color: string;
}) {
  return (
    <div style={{
      padding: "14px 16px",
      background: value > 0 ? `${color}0a` : "var(--bg-input)",
      border: `1px solid ${value > 0 ? `${color}33` : "var(--border)"}`,
      borderRadius: "var(--radius)",
      textAlign: "center",
    }}>
      <div style={{
        fontSize: 24, fontWeight: 800, color: value > 0 ? color : "var(--text-dim)",
        fontFamily: "var(--font-mono)",
      }}>
        {value}
      </div>
      <div style={{
        fontSize: 11, fontWeight: 600, color: value > 0 ? color : "var(--text-muted)",
        letterSpacing: "0.01em", marginTop: 4,
        fontFamily: "var(--font-sans)",
      }}>
        {label}
      </div>
    </div>
  );
}

function VTStatBox({ label, count, total, color, highlight }: {
  label: string; count: number; total: number; color: string; highlight: boolean;
}) {
  return (
    <div style={{
      padding: "14px 16px",
      background: highlight ? `${color}0a` : "var(--bg-input)",
      border: `1px solid ${highlight ? `${color}33` : "var(--border)"}`,
      borderRadius: "var(--radius)",
      textAlign: "center",
    }}>
      <div style={{
        fontSize: 24, fontWeight: 800, color: highlight ? color : "var(--text-dim)",
        fontFamily: "var(--font-mono)",
      }}>
        {count}
      </div>
      <div style={{
        fontSize: 11, fontWeight: 600, color: highlight ? color : "var(--text-muted)",
        letterSpacing: "0.01em", marginTop: 4,
        fontFamily: "var(--font-sans)",
      }}>
        {label}
      </div>
      <div style={{ fontSize: 9, color: "var(--text-muted)", marginTop: 2 }}>
        / {total} vendors
      </div>
    </div>
  );
}
