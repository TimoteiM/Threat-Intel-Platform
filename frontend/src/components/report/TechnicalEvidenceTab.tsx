"use client";

import React from "react";
import { CollectedEvidence } from "@/lib/types";
import { getArtifactUrl } from "@/lib/api";
import EvidenceTable from "@/components/evidence/EvidenceTable";
import VisualComparisonSection from "@/components/report/VisualComparisonSection";
import WHOISHistorySection from "@/components/report/WHOISHistorySection";
import ThreatFeedsSection from "@/components/report/ThreatFeedsSection";
import FaviconIntelSection from "@/components/report/FaviconIntelSection";
import CertTimelineSection from "@/components/report/CertTimelineSection";
import AnyRunInteractiveEvidence from "@/components/report/AnyRunInteractiveEvidence";

interface Props {
  evidence: CollectedEvidence;
  domain?: string;
  observableType?: string;
}

const EvidenceSplitContext = React.createContext<{ activeTitle: string | null } | null>(null);

export default function TechnicalEvidenceTab({ evidence, domain, observableType }: Props) {
  const dns = evidence?.dns || ({} as any);
  const tls = evidence?.tls || ({} as any);
  const http = evidence?.http || ({} as any);
  const whois = evidence?.whois || ({} as any);
  const hosting = evidence?.hosting || ({} as any);
  const intel = evidence?.intel || ({} as any);
  const vt = evidence?.vt || ({} as any);
  const braveOsint = evidence?.brave_osint || ({} as any);
  const urlscan = evidence?.urlscan || ({} as any);
  const urlLexical = evidence?.url_lexical_ml || ({} as any);
  const urlMlScore = evidence?.ml_url_score || ({} as any);
  const urlBehavior = evidence?.url_behavior || ({} as any);
  const contentMl = evidence?.content_ml || ({} as any);
  const attachmentAnalysis = evidence?.attachment_analysis || ({} as any);
  const hybridAnalysis = evidence?.hybrid_analysis || ({} as any);
  const finalRisk = evidence?.final_risk || ({} as any);
  const redirectDestinationIntel =
    evidence?.redirect_destination_intel ||
    (evidence as any)?.redirect_destination_intelligence ||
    (evidence as any)?.redirect_destination ||
    ({} as any);
  const hasRedirectDestinationIntel = !!(
    redirectDestinationIntel &&
    typeof redirectDestinationIntel === "object" &&
    Object.keys(redirectDestinationIntel).length > 0
  );
  const [jsDetailView, setJsDetailView] = React.useState<string | null>(null);
  const [isNarrow, setIsNarrow] = React.useState(false);

  const type = observableType || (evidence as any)?.observable_type || "domain";
  const isFileHash = type === "file" || type === "hash";
  const sectionDefs = React.useMemo(
    () => [
      {
        title: "DNS Records",
        visible: !isFileHash,
        hasData: arr(dns.a).length > 0 || arr(dns.aaaa).length > 0 || arr(dns.ns).length > 0 || arr(dns.mx).length > 0 || !!dns.spf || !!dns.dmarc,
      },
      {
        title: "Email Security",
        visible: !isFileHash && !!evidence?.email_security,
        hasData: !!(evidence?.email_security && (
          evidence.email_security.email_security_score != null ||
          evidence.email_security.dmarc_record ||
          evidence.email_security.spf_record
        )),
      },
      {
        title: "TLS Certificate",
        visible: !isFileHash,
        hasData: !!(tls && (tls.present || tls.issuer || tls.subject || arr(tls.sans).length)),
      },
      {
        title: "HTTP Response",
        visible: !isFileHash,
        hasData: !!(http && (http.reachable || http.final_url || http.final_status_code)),
      },
      {
        title: "Redirect Analysis",
        visible: !isFileHash && !!evidence?.redirect_analysis,
        hasData: !!(evidence?.redirect_analysis && arr(evidence.redirect_analysis.probes).length > 0),
      },
      { title: "Content Analysis", visible: !isFileHash && !!(
        arr(http.phishing_indicators).length > 0 ||
        arr(http.external_resources).length > 0 ||
        http.favicon_hash
      ), hasData: true },
      {
        title: "JavaScript Analysis",
        visible: !isFileHash && !!evidence?.js_analysis,
        hasData: !!(evidence?.js_analysis && (
          arr(evidence.js_analysis.captured_requests).length ||
          arr(evidence.js_analysis.suspicious_scripts).length ||
          arr(evidence.js_analysis.request_domains).length
        )),
      },
      {
        title: "WHOIS Registration",
        visible: !isFileHash,
        hasData: !!(whois && (whois.registrar || whois.created_date || whois.domain_age_days != null)),
      },
      {
        title: "Hosting / ASN",
        visible: !isFileHash,
        hasData: !!(hosting && (hosting.ip || hosting.asn || hosting.asn_org)),
      },
      {
        title: "Visual Comparison",
        visible: !isFileHash && !!evidence?.visual_comparison,
        hasData: !!(evidence?.visual_comparison && evidence.visual_comparison.overall_visual_similarity != null),
      },
      {
        title: "Domain Screenshot",
        visible: !isFileHash && !!evidence?.screenshot,
        hasData: !!(evidence?.screenshot && (evidence.screenshot.artifact_id || evidence.screenshot.final_url || evidence.screenshot.capture_error)),
      },
      {
        title: "Subdomain Enumeration",
        visible: !isFileHash && !!(evidence?.subdomains && evidence.subdomains.discovered_count > 0),
        hasData: !!(evidence?.subdomains && evidence.subdomains.discovered_count > 0),
      },
      {
        title: "VirusTotal Reputation",
        visible: true,
        hasData: !!(vt && (vt.found || vt.total_vendors || vt.meta?.status === "completed")),
      },
      {
        title: "Brave OSINT",
        visible: !!evidence?.brave_osint,
        hasData: !!(evidence?.brave_osint && (
          arr(evidence.brave_osint.top_hits).length ||
          arr(evidence.brave_osint.all_results).length ||
          evidence.brave_osint.summary ||
          evidence.brave_osint.meta?.status === "completed"
        )),
      },
      {
        title: "URLScan Reputation",
        visible: true,
        hasData: !!(urlscan && (urlscan.scan_id || urlscan.page_url || urlscan.meta?.status === "completed")),
      },
      {
        title: "URL Lexical ML",
        visible: (type === "url" || type === "domain"),
        hasData: !!(urlLexical && Object.keys(urlLexical).length > 0),
      },
      {
        title: "Content ML Signals",
        visible: true,
        hasData: !!(contentMl && Object.keys(contentMl).length > 0),
      },
      {
        title: "Attachment Static Analysis",
        visible: true,
        hasData: !!(attachmentAnalysis?.items?.length),
      },
      {
        title: "URL Behavior Analysis",
        visible: (type === "url" || type === "domain"),
        hasData: !!(urlBehavior && Object.keys(urlBehavior).length > 0),
      },
      {
        title: "AnyRun Analysis",
        visible: true,
        hasData: !!(hybridAnalysis?.items?.length) || !!hybridAnalysis?.meta?.status,
      },
      {
        title: "Final Risk Aggregation",
        visible: true,
        hasData: !!(finalRisk && Object.keys(finalRisk).length > 0),
      },
      {
        title: "Redirect Destination Intelligence",
        visible: (type === "url" || type === "domain"),
        hasData: hasRedirectDestinationIntel,
      },
      {
        title: "Threat Intelligence",
        visible: true,
        hasData: !!(intel && (
          arr(intel.blocklist_hits).length ||
          arr(intel.related_subdomains).length ||
          arr(intel.notes).length
        )),
      },
      {
        title: "Threat Feed Intelligence",
        visible: !!evidence?.threat_feeds,
        hasData: !!(evidence?.threat_feeds && Object.keys(evidence.threat_feeds).length > 0),
      },
      {
        title: "Favicon Hash Intelligence",
        visible: !isFileHash && !!evidence?.favicon_intel,
        hasData: !!(evidence?.favicon_intel && Object.keys(evidence.favicon_intel).length > 0),
      },
      {
        title: "Certificate Transparency Timeline",
        visible: !isFileHash && !!(evidence?.cert_timeline && evidence.cert_timeline.total_certs > 0),
        hasData: !!(evidence?.cert_timeline && evidence.cert_timeline.total_certs > 0),
      },
      {
        title: "Collector Metadata",
        visible: true,
        hasData: true,
      },
    ],
    [isFileHash, evidence, dns, http, tls, whois, hosting, vt, braveOsint, urlscan, urlLexical, contentMl, attachmentAnalysis, urlBehavior, hybridAnalysis, finalRisk, hasRedirectDestinationIntel, intel, type],
  );
  const availableSections = React.useMemo(
    () => sectionDefs.filter((s) => s.visible),
    [sectionDefs],
  );
  const [activeSectionTitle, setActiveSectionTitle] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!availableSections.length) {
      setActiveSectionTitle(null);
      return;
    }
    if (!activeSectionTitle || !availableSections.some((s) => s.title === activeSectionTitle)) {
      setActiveSectionTitle(availableSections[0].title);
    }
  }, [availableSections, activeSectionTitle]);

  React.useEffect(() => {
    const update = () => setIsNarrow(typeof window !== "undefined" && window.innerWidth < 1100);
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: isNarrow ? "1fr" : "250px minmax(0,1fr)",
        gap: 18,
        alignItems: "start",
      }}
    >
      <div
        style={{
          position: isNarrow ? "static" : "sticky",
          top: 82,
          alignSelf: "start",
          background: "var(--bg-card)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          padding: 10,
          maxHeight: isNarrow ? "none" : "72vh",
          overflowY: "auto",
        }}
      >
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8, letterSpacing: "0.03em" }}>
          TECHNICAL EVIDENCE
        </div>
        <div style={{ display: "grid", gap: 6 }}>
          {availableSections.map(({ title, hasData }) => (
            <button
              key={title}
              type="button"
              onClick={() => setActiveSectionTitle(title)}
              style={{
                textAlign: "left",
                fontSize: 12,
                padding: "8px 10px",
                borderRadius: "var(--radius-sm)",
                border: activeSectionTitle === title
                  ? "1px solid rgba(96,165,250,0.45)"
                  : hasData
                  ? "1px solid rgba(52,211,153,0.25)"
                  : "1px solid var(--border)",
                background: activeSectionTitle === title
                  ? "rgba(96,165,250,0.12)"
                  : hasData
                  ? "rgba(52,211,153,0.08)"
                  : "var(--bg-elevated)",
                color: activeSectionTitle === title ? "var(--accent)" : hasData ? "var(--green)" : "var(--text-secondary)",
                cursor: "pointer",
                fontWeight: activeSectionTitle === title ? 700 : 500,
              }}
            >
              <span style={{ marginRight: 6, color: hasData ? "var(--green)" : "var(--text-muted)" }}>
                {hasData ? "●" : "○"}
              </span>
              {title}
            </button>
          ))}
        </div>
      </div>

      <div>
      <EvidenceSplitContext.Provider value={{ activeTitle: activeSectionTitle }}>

      {/* —— DOMAIN/URL/IP sections — hidden for file/hash investigations —— */}
      {!isFileHash && <>

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

      {/* EMAIL SECURITY */}
      {evidence?.email_security && (
        <Section title="Email Security">
          {(() => {
            const es = evidence.email_security!;
            const score = es.email_security_score;
            const spoofability = es.spoofability_score;
            const dkimCount = arr(es.dkim_selectors_found).length;
            const mxCount = arr(es.mx_records).length;

            const spoofColor =
              spoofability === "high" ? "var(--red)" :
              spoofability === "medium" ? "var(--yellow)" :
              spoofability === "low" ? "var(--accent)" :
              "var(--green)";

            const scoreColor =
              (score ?? 0) >= 80 ? "var(--green)" :
              (score ?? 0) >= 50 ? "var(--yellow)" :
              "var(--red)";

            return (
              <>
                {/* Summary stat boxes */}
                <div style={{
                  display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8,
                  marginBottom: 16,
                }}>
                  <div style={{
                    padding: "14px 16px",
                    background: `${scoreColor}0a`,
                    border: `1px solid ${scoreColor}33`,
                    borderRadius: "var(--radius)",
                    textAlign: "center",
                  }}>
                    <div style={{
                      fontSize: 24, fontWeight: 800, color: scoreColor,
                      fontFamily: "var(--font-mono)",
                    }}>
                      {score ?? "—"}
                    </div>
                    <div style={{
                      fontSize: 11, fontWeight: 600, color: scoreColor,
                      letterSpacing: "0.01em", marginTop: 4,
                      fontFamily: "var(--font-sans)",
                    }}>
                      Security Score
                    </div>
                  </div>
                  <div style={{
                    padding: "14px 16px",
                    background: `${spoofColor}0a`,
                    border: `1px solid ${spoofColor}33`,
                    borderRadius: "var(--radius)",
                    textAlign: "center",
                  }}>
                    <div style={{
                      fontSize: 18, fontWeight: 800, color: spoofColor,
                      fontFamily: "var(--font-mono)", textTransform: "uppercase",
                    }}>
                      {spoofability || "—"}
                    </div>
                    <div style={{
                      fontSize: 11, fontWeight: 600, color: spoofColor,
                      letterSpacing: "0.01em", marginTop: 4,
                      fontFamily: "var(--font-sans)",
                    }}>
                      Spoofability
                    </div>
                  </div>
                  <SubStatBox label="DKIM Selectors" value={dkimCount} color="var(--accent)" />
                  <SubStatBox label="MX Records" value={mxCount} color="var(--accent)" />
                </div>

                {/* DMARC details */}
                <EvidenceTable
                  title="DMARC"
                  data={[
                    { field: "Record", value: es.dmarc_record || "Not configured" },
                    { field: "Policy", value: es.dmarc_policy || "none" },
                    { field: "Subdomain Policy", value: es.dmarc_subdomain_policy || "—" },
                    { field: "Percentage", value: es.dmarc_pct != null ? `${es.dmarc_pct}%` : "—" },
                    { field: "DKIM Alignment", value: es.dmarc_alignment_dkim === "s" ? "strict" : es.dmarc_alignment_dkim === "r" ? "relaxed" : "—" },
                    { field: "SPF Alignment", value: es.dmarc_alignment_spf === "s" ? "strict" : es.dmarc_alignment_spf === "r" ? "relaxed" : "—" },
                    ...(arr(es.dmarc_rua).length > 0 ? [{ field: "Aggregate Reports", value: arr(es.dmarc_rua).join(", ") }] : []),
                    ...(arr(es.dmarc_ruf).length > 0 ? [{ field: "Forensic Reports", value: arr(es.dmarc_ruf).join(", ") }] : []),
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }]}
                />

                {/* SPF details */}
                <EvidenceTable
                  title="SPF"
                  data={[
                    { field: "Record", value: es.spf_record || "Not configured" },
                    { field: "All Qualifier", value: es.spf_all_qualifier || "—" },
                    { field: "IP Count", value: es.spf_ip_count ?? "—" },
                    ...(arr(es.spf_includes).length > 0 ? [{ field: "Includes", value: arr(es.spf_includes).join(", ") }] : []),
                    ...(arr(es.spf_mechanisms).length > 0 ? [{ field: "Mechanisms", value: arr(es.spf_mechanisms).join(" ") }] : []),
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }]}
                />

                {/* DKIM selectors */}
                {arr(es.dkim_records).length > 0 && (
                  <EvidenceTable
                    title={`DKIM Selectors (${arr(es.dkim_records).length} found)`}
                    data={arr(es.dkim_records).map((r: any) => ({
                      selector: r.selector,
                      key_present: r.public_key_present ? "Yes" : "No",
                      key_type: r.key_type || "—",
                      notes: r.notes || "—",
                    }))}
                    columns={[
                      { key: "selector" },
                      { key: "key_present" },
                      { key: "key_type" },
                      { key: "notes" },
                    ]}
                  />
                )}

                {dkimCount === 0 && (
                  <div style={{
                    padding: "10px 14px", fontSize: 12, color: "var(--yellow)",
                    background: "rgba(251,191,36,0.06)", borderRadius: "var(--radius-sm)",
                    borderLeft: "3px solid var(--yellow)", marginBottom: 16,
                  }}>
                    No DKIM selectors found (checked 10 common selectors)
                  </div>
                )}

                {/* MX records */}
                {arr(es.mx_records).length > 0 && (
                  <EvidenceTable
                    title={`MX Records (${arr(es.mx_records).length})`}
                    data={arr(es.mx_records).map((mx: any) => ({
                      priority: mx.priority,
                      hostname: mx.hostname,
                      ips: arr(mx.ips).join(", ") || "—",
                      blocklist: arr(mx.blocklist_hits).length > 0
                        ? arr(mx.blocklist_hits).join("; ")
                        : "Clean",
                    }))}
                    columns={[
                      { key: "priority" },
                      { key: "hostname", wrap: true },
                      { key: "ips", wrap: true },
                      { key: "blocklist", wrap: true },
                    ]}
                  />
                )}

                {/* Spoofability reasons */}
                {arr(es.spoofability_reasons).length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: spoofColor,
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Spoofability Assessment
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {arr(es.spoofability_reasons).map((reason: string, i: number) => (
                        <div key={i} style={{
                          padding: "8px 12px",
                          background: `${spoofColor}08`,
                          borderLeft: `3px solid ${spoofColor}`,
                          borderRadius: "var(--radius-sm)",
                          fontSize: 12, color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {reason}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            );
          })()}
        </Section>
      )}

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
                {
                  field: "Redirect Destination Intel",
                  value: hasRedirectDestinationIntel
                    ? (
                        redirectDestinationIntel?.comparison?.source_vs_destination_root
                        || (
                          redirectDestinationIntel?.investigated_root &&
                          redirectDestinationIntel?.destination_root
                            ? `${redirectDestinationIntel.investigated_root} -> ${redirectDestinationIntel.destination_root}`
                            : "Available"
                        )
                      )
                    : "Not available",
                },
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

      {/* REDIRECT ANALYSIS */}
      {evidence?.redirect_analysis && (
        <Section title="Redirect Analysis">
          {(() => {
            const ra = evidence.redirect_analysis!;
            const cloaking = ra.cloaking_detected;

            return (
              <>
                {/* Cloaking alert banner */}
                <div style={{
                  padding: "12px 16px", fontSize: 12, marginBottom: 16,
                  borderRadius: "var(--radius-sm)",
                  borderLeft: `3px solid ${cloaking ? "var(--red)" : "var(--green)"}`,
                  background: cloaking ? "rgba(248,113,113,0.06)" : "rgba(52,211,153,0.06)",
                  color: cloaking ? "var(--red)" : "var(--green)",
                  fontWeight: 600,
                }}>
                  {cloaking
                    ? "UA-based cloaking detected — different URLs or status codes across User-Agents"
                    : "No cloaking detected — consistent URLs and status codes across User-Agents"}
                </div>

                {/* Cloaking details */}
                {arr(ra.cloaking_details).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    {arr(ra.cloaking_details).map((detail: string, i: number) => (
                      <div key={i} style={{
                        padding: "8px 12px", marginBottom: 4,
                        background: "rgba(248,113,113,0.06)",
                        borderLeft: "3px solid var(--red)",
                        borderRadius: "var(--radius-sm)",
                        fontSize: 12, color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}>
                        {detail}
                      </div>
                    ))}
                  </div>
                )}

                {/* Probe comparison table */}
                {arr(ra.probes).length > 0 && (
                  <EvidenceTable
                    title="User-Agent Probe Comparison"
                    data={arr(ra.probes).map((p: any) => ({
                      ua_type: p.user_agent_type,
                      status: p.status_code || "Failed",
                      final_url: p.final_url || "—",
                      redirects: p.redirect_count,
                      title: p.title || "—",
                      content_hash: p.content_hash ? `${p.content_hash.substring(0, 12)}...` : "—",
                    }))}
                    columns={[
                      { key: "ua_type" },
                      { key: "status" },
                      { key: "final_url", wrap: true },
                      { key: "redirects" },
                      { key: "title", wrap: true },
                      { key: "content_hash" },
                    ]}
                  />
                )}

                {/* Evasion techniques */}
                {arr(ra.evasion_techniques).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--yellow)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Evasion Techniques ({arr(ra.evasion_techniques).length})
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {arr(ra.evasion_techniques).map((tech: string, i: number) => (
                        <div key={i} style={{
                          padding: "8px 12px",
                          background: "rgba(251,191,36,0.06)",
                          borderLeft: "3px solid var(--yellow)",
                          borderRadius: "var(--radius-sm)",
                          fontSize: 12, color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {tech}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Intermediate domains */}
                {arr(ra.intermediate_domains).length > 0 && (
                  <EvidenceTable
                    title={`Intermediate Domains (${arr(ra.intermediate_domains).length})`}
                    data={arr(ra.intermediate_domains).map((d: any) => ({
                      domain: d.domain,
                      hop: d.hop_number,
                      tracker: d.is_known_tracker ? "Yes" : "—",
                      redirector: d.is_known_redirector ? "Yes" : "—",
                    }))}
                    columns={[
                      { key: "domain", wrap: true },
                      { key: "hop" },
                      { key: "tracker" },
                      { key: "redirector" },
                    ]}
                  />
                )}
              </>
            );
          })()}
        </Section>
      )}

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

      {/* JAVASCRIPT ANALYSIS */}
      {evidence?.js_analysis && (
        <Section title="JavaScript Analysis">
          {(() => {
            const ja = evidence.js_analysis!;
            const credPosts = arr(ja.post_endpoints).filter((p: any) => p.is_credential_form);

            return (
              <>
                {ja.error && (
                  <EmptyNote>JavaScript analysis failed: {ja.error}</EmptyNote>
                )}
                {/* Summary stat boxes — clickable to expand details */}
                <div style={{
                  display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8,
                  marginBottom: 16,
                }}>
                  <ClickableStatBox label="Total Requests" value={ja.total_requests} color="var(--accent)" active={jsDetailView === "total"} onClick={() => setJsDetailView(jsDetailView === "total" ? null : "total")} />
                  <ClickableStatBox label="External" value={ja.external_requests} color="var(--yellow)" active={jsDetailView === "external"} onClick={() => setJsDetailView(jsDetailView === "external" ? null : "external")} />
                  <ClickableStatBox label="POST Endpoints" value={arr(ja.post_endpoints).length} color={credPosts.length > 0 ? "var(--red)" : "var(--accent)"} active={jsDetailView === "post"} onClick={() => setJsDetailView(jsDetailView === "post" ? null : "post")} />
                  <ClickableStatBox label="Unique Domains" value={arr(ja.request_domains).length} color="var(--accent)" active={jsDetailView === "domains"} onClick={() => setJsDetailView(jsDetailView === "domains" ? null : "domains")} />
                </div>

                {/* Expandable detail panel */}
                {jsDetailView && (
                  <div style={{
                    marginBottom: 16, padding: "14px 16px",
                    background: "var(--bg-input)", borderRadius: "var(--radius)",
                    border: "1px solid var(--border)",
                  }}>
                    {jsDetailView === "total" && (
                      <>
                        <div style={{
                          fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 10,
                          paddingBottom: 8, borderBottom: "1px solid var(--border-dim)",
                        }}>
                          All Captured Requests ({ja.total_requests})
                        </div>
                        {arr(ja.captured_requests).length > 0 ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 400, overflowY: "auto" }}>
                            {arr(ja.captured_requests).map((req: any, i: number) => (
                              <div key={i} style={{
                                padding: "5px 10px", fontSize: 11,
                                background: req.is_external ? "rgba(251,191,36,0.04)" : "rgba(52,211,153,0.04)",
                                borderLeft: `3px solid ${req.is_external ? "var(--yellow)" : "var(--green)"}`,
                                borderRadius: "var(--radius-sm)",
                                color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
                                display: "flex", alignItems: "center", gap: 8,
                              }}>
                                <span style={{
                                  padding: "1px 5px", fontSize: 9, fontWeight: 700,
                                  background: req.method === "POST" ? "rgba(248,113,113,0.15)" : "rgba(96,165,250,0.12)",
                                  color: req.method === "POST" ? "var(--red)" : "var(--accent)",
                                  borderRadius: 3, minWidth: 32, textAlign: "center",
                                }}>
                                  {req.method}
                                </span>
                                <span style={{
                                  padding: "1px 5px", fontSize: 9, fontWeight: 600,
                                  background: "rgba(148,163,184,0.10)", color: "var(--text-muted)",
                                  borderRadius: 3, minWidth: 48, textAlign: "center",
                                }}>
                                  {req.resource_type}
                                </span>
                                <span style={{ flex: 1, wordBreak: "break-all" }}>
                                  {req.url}
                                </span>
                              </div>
                            ))}
                            {ja.total_requests > arr(ja.captured_requests).length && (
                              <div style={{ fontSize: 10, color: "var(--text-muted)", padding: "6px 10px", fontStyle: "italic" }}>
                                Showing {arr(ja.captured_requests).length} of {ja.total_requests} requests
                              </div>
                            )}
                          </div>
                        ) : arr(ja.request_domains).length > 0 ? (
                          <div>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
                              Individual requests not available for this investigation. Showing domains:
                            </div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                              {arr(ja.request_domains).map((domain: string, i: number) => {
                                const isExt = domain !== evidence.domain && !domain.endsWith(`.${evidence.domain}`);
                                return (
                                  <span key={i} style={{
                                    padding: "4px 10px", fontSize: 11, fontWeight: 500,
                                    background: isExt ? "rgba(251,191,36,0.10)" : "rgba(52,211,153,0.10)",
                                    color: isExt ? "var(--yellow)" : "var(--green)",
                                    borderRadius: "var(--radius-sm)",
                                    border: `1px solid ${isExt ? "rgba(251,191,36,0.2)" : "rgba(52,211,153,0.2)"}`,
                                    fontFamily: "var(--font-mono)",
                                  }}>
                                    {domain}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        ) : (
                          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No requests captured</div>
                        )}
                      </>
                    )}

                    {jsDetailView === "external" && (() => {
                      const extReqs = arr(ja.captured_requests).filter((r: any) => r.is_external);
                      const externalDomains = arr(ja.request_domains).filter(
                        (d: string) => d !== evidence.domain && !d.endsWith(`.${evidence.domain}`)
                      );
                      return (
                        <>
                          <div style={{
                            fontSize: 12, fontWeight: 600, color: "var(--yellow)", marginBottom: 10,
                            paddingBottom: 8, borderBottom: "1px solid var(--border-dim)",
                          }}>
                            External Requests ({extReqs.length > 0 ? `${extReqs.length} requests to ${externalDomains.length} domains` : `${externalDomains.length} domains`})
                          </div>
                          {extReqs.length > 0 ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 400, overflowY: "auto" }}>
                              {extReqs.map((req: any, i: number) => (
                                <div key={i} style={{
                                  padding: "5px 10px", fontSize: 11,
                                  background: "rgba(251,191,36,0.04)",
                                  borderLeft: "3px solid var(--yellow)",
                                  borderRadius: "var(--radius-sm)",
                                  color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
                                  display: "flex", alignItems: "center", gap: 8,
                                }}>
                                  <span style={{
                                    padding: "1px 5px", fontSize: 9, fontWeight: 700,
                                    background: req.method === "POST" ? "rgba(248,113,113,0.15)" : "rgba(96,165,250,0.12)",
                                    color: req.method === "POST" ? "var(--red)" : "var(--accent)",
                                    borderRadius: 3, minWidth: 32, textAlign: "center",
                                  }}>
                                    {req.method}
                                  </span>
                                  <span style={{
                                    padding: "1px 5px", fontSize: 9, fontWeight: 600,
                                    background: "rgba(148,163,184,0.10)", color: "var(--text-muted)",
                                    borderRadius: 3, minWidth: 48, textAlign: "center",
                                  }}>
                                    {req.resource_type}
                                  </span>
                                  <span style={{ flex: 1, wordBreak: "break-all" }}>
                                    {req.url}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : externalDomains.length > 0 ? (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                              {externalDomains.map((domain: string, i: number) => (
                                <span key={i} style={{
                                  padding: "4px 10px", fontSize: 11, fontWeight: 500,
                                  background: "rgba(251,191,36,0.10)", color: "var(--yellow)",
                                  borderRadius: "var(--radius-sm)", border: "1px solid rgba(251,191,36,0.2)",
                                  fontFamily: "var(--font-mono)",
                                }}>
                                  {domain}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No external requests detected</div>
                          )}
                        </>
                      );
                    })()}

                    {jsDetailView === "post" && (
                      <>
                        <div style={{
                          fontSize: 12, fontWeight: 600,
                          color: credPosts.length > 0 ? "var(--red)" : "var(--text-secondary)",
                          marginBottom: 10, paddingBottom: 8, borderBottom: "1px solid var(--border-dim)",
                        }}>
                          POST Endpoints ({arr(ja.post_endpoints).length})
                        </div>
                        {arr(ja.post_endpoints).length > 0 ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            {arr(ja.post_endpoints).map((p: any, i: number) => (
                              <div key={i} style={{
                                padding: "8px 12px",
                                background: p.is_credential_form ? "rgba(248,113,113,0.06)" : "rgba(96,165,250,0.04)",
                                borderLeft: `3px solid ${p.is_credential_form ? "var(--red)" : p.is_external ? "var(--yellow)" : "var(--border)"}`,
                                borderRadius: "var(--radius-sm)",
                                fontSize: 12, color: "var(--text-secondary)",
                                fontFamily: "var(--font-mono)", wordBreak: "break-all",
                                display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8,
                              }}>
                                <span style={{ flex: 1 }}>{p.url}</span>
                                <span style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                                  {p.is_external && (
                                    <span style={{
                                      padding: "2px 6px", fontSize: 9, fontWeight: 600,
                                      background: "rgba(251,191,36,0.15)", color: "var(--yellow)", borderRadius: 3,
                                    }}>EXTERNAL</span>
                                  )}
                                  {p.is_credential_form && (
                                    <span style={{
                                      padding: "2px 6px", fontSize: 9, fontWeight: 600,
                                      background: "rgba(248,113,113,0.15)", color: "var(--red)", borderRadius: 3,
                                    }}>CREDENTIAL</span>
                                  )}
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No POST endpoints detected</div>
                        )}
                      </>
                    )}

                    {jsDetailView === "domains" && (
                      <>
                        <div style={{
                          fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 10,
                          paddingBottom: 8, borderBottom: "1px solid var(--border-dim)",
                        }}>
                          All Unique Domains ({arr(ja.request_domains).length})
                        </div>
                        {arr(ja.request_domains).length > 0 ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                            {arr(ja.request_domains).map((domain: string, i: number) => {
                              const isExt = domain !== evidence.domain && !domain.endsWith(`.${evidence.domain}`);
                              return (
                                <div key={i} style={{
                                  padding: "6px 12px", fontSize: 11,
                                  background: isExt ? "rgba(251,191,36,0.04)" : "rgba(52,211,153,0.04)",
                                  borderLeft: `3px solid ${isExt ? "var(--yellow)" : "var(--green)"}`,
                                  borderRadius: "var(--radius-sm)",
                                  color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
                                  display: "flex", justifyContent: "space-between", alignItems: "center",
                                }}>
                                  <span>{domain}</span>
                                  <span style={{
                                    padding: "1px 5px", fontSize: 9, fontWeight: 600,
                                    background: isExt ? "rgba(251,191,36,0.12)" : "rgba(52,211,153,0.12)",
                                    color: isExt ? "var(--yellow)" : "var(--green)", borderRadius: 3,
                                  }}>
                                    {isExt ? "EXTERNAL" : "INTERNAL"}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No domains detected</div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {/* Credential harvesting alerts */}
                {credPosts.length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--red)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Credential Harvesting ({credPosts.length} external POST to auth endpoints)
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {credPosts.map((p: any, i: number) => (
                        <div key={i} style={{
                          padding: "8px 12px",
                          background: "rgba(248,113,113,0.06)",
                          borderLeft: "3px solid var(--red)",
                          borderRadius: "var(--radius-sm)",
                          fontSize: 12, color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                          wordBreak: "break-all",
                        }}>
                          {p.url}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Data exfiltration indicators */}
                {arr(ja.data_exfil_indicators).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    {arr(ja.data_exfil_indicators).map((ind: string, i: number) => (
                      <div key={i} style={{
                        padding: "8px 12px", marginBottom: 4,
                        background: "rgba(248,113,113,0.06)",
                        borderLeft: "3px solid var(--red)",
                        borderRadius: "var(--radius-sm)",
                        fontSize: 12, color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                      }}>
                        {ind}
                      </div>
                    ))}
                  </div>
                )}

                {/* Fingerprinting APIs */}
                {arr(ja.fingerprinting_apis).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--yellow)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Fingerprinting APIs ({arr(ja.fingerprinting_apis).length})
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {arr(ja.fingerprinting_apis).map((api: string, i: number) => (
                        <span key={i} style={{
                          padding: "4px 10px", fontSize: 11, fontWeight: 500,
                          background: "rgba(251,191,36,0.10)", color: "var(--yellow)",
                          borderRadius: "var(--radius-sm)", border: "1px solid rgba(251,191,36,0.2)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {api}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tracking pixels */}
                {arr(ja.tracking_pixels).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--text-secondary)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Tracking Pixels ({arr(ja.tracking_pixels).length} domains)
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {arr(ja.tracking_pixels).map((domain: string, i: number) => (
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

                {/* Suspicious scripts */}
                {arr(ja.suspicious_scripts).length > 0 && (
                  <EvidenceTable
                    title={`External Scripts (${arr(ja.suspicious_scripts).length})`}
                    data={arr(ja.suspicious_scripts).slice(0, 15).map((s: any) => ({
                      domain: s.domain,
                      reason: s.reason,
                      url: s.url ? `${s.url.substring(0, 60)}...` : "—",
                    }))}
                    columns={[
                      { key: "domain", wrap: true },
                      { key: "reason", wrap: true },
                      { key: "url", wrap: true },
                    ]}
                  />
                )}

                {/* WebSocket connections */}
                {arr(ja.websocket_connections).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--text-secondary)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      WebSocket Connections ({arr(ja.websocket_connections).length})
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {arr(ja.websocket_connections).map((url: string, i: number) => (
                        <div key={i} style={{
                          padding: "6px 12px", fontSize: 11,
                          background: "var(--bg-input)",
                          borderRadius: "var(--radius-sm)",
                          color: "var(--text-secondary)",
                          fontFamily: "var(--font-mono)",
                          wordBreak: "break-all",
                        }}>
                          {url}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Console errors (first 5) */}
                {arr(ja.console_errors).length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--text-muted)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Console Errors ({arr(ja.console_errors).length})
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {arr(ja.console_errors).slice(0, 5).map((err: string, i: number) => (
                        <div key={i} style={{
                          padding: "6px 12px", fontSize: 10,
                          background: "var(--bg-input)",
                          borderRadius: "var(--radius-sm)",
                          color: "var(--text-dim)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {err}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            );
          })()}
        </Section>
      )}

      {/* WHOIS */}
      <Section title="WHOIS Registration">
        {/* For URL type, show which domain was queried */}
        {type === "url" && domain && (() => {
          let queried = domain;
          try { queried = new URL(domain).hostname; } catch {}
          return (
            <div style={{
              fontSize: 11, color: "var(--text-muted)", marginBottom: 10,
              fontFamily: "var(--font-mono)",
            }}>
              Queried domain: <span style={{ color: "var(--accent)" }}>{queried}</span>
            </div>
          );
        })()}
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
        {whois.meta?.status !== "failed" && domain && (() => {
          let historyDomain = domain;
          if (type === "url") {
            try { historyDomain = new URL(domain).hostname; } catch {}
          }
          return <WHOISHistorySection domain={historyDomain} />;
        })()}
      </Section>

      {/* WHOIS History — for URL type use extracted hostname, not full URL */}
      

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
                flag: entry.is_interesting ? "â˜…" : "",
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

      </>}

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
            {/* File identity — only shown for hash/file investigations */}
            {isFileHash && (vt.file_name || arr(vt.file_names).length > 0) && (
              <div style={{ marginBottom: 16 }}>
                {vt.file_name && (
                  <EvidenceTable
                    title="File Identity"
                    data={[
                      { field: "File Name", value: vt.file_name },
                      ...(vt.vt_registrar ? [{ field: "File Type", value: vt.vt_registrar }] : []),
                    ]}
                    columns={[{ key: "field" }, { key: "value", wrap: true }]}
                  />
                )}
                {arr(vt.file_names).length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{
                      fontSize: 12, fontWeight: 600, color: "var(--text-secondary)",
                      letterSpacing: "0.01em", marginBottom: 8,
                      padding: "6px 0", borderBottom: "1px solid var(--border-dim)",
                      fontFamily: "var(--font-sans)",
                    }}>
                      Known File Names ({arr(vt.file_names).length})
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {arr(vt.file_names).map((name: string, i: number) => (
                        <span key={i} style={{
                          padding: "4px 10px", fontSize: 11, fontWeight: 500,
                          background: "var(--bg-input)", color: "var(--text-dim)",
                          borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
                          fontFamily: "var(--font-mono)",
                        }}>
                          {name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

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
                ...(isFileHash
                  ? (vt.vt_registrar ? [{ field: "File Type", value: vt.vt_registrar }] : [])
                  : [{ field: "VT Registrar", value: vt.vt_registrar || "—" }]),
                ...(!isFileHash ? [{ field: "VT Cert Issuer", value: vt.vt_cert_issuer || "—" }] : []),
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

      {/* URLSCAN */}
      <Section title="URLScan Reputation">
        {!urlscan || Object.keys(urlscan).length === 0 ? (
          <EmptyNote>URLScan data not available (collector not run)</EmptyNote>
        ) : urlscan?.meta?.status === "failed" ? (
          <EmptyNote>URLScan lookup failed: {urlscan?.meta?.error || "unknown error"}</EmptyNote>
        ) : (
          <>
            <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 8, fontFamily: "var(--font-mono)" }}>
              UI build marker: URLSCAN-TECH-EVIDENCE-2026-03-09
            </div>
            <EvidenceTable
              title="URLScan Summary"
              data={[
                { field: "Verdict", value: String(urlscan?.verdict || "unknown").toUpperCase() },
                { field: "Score", value: urlscan?.score ?? "—" },
                { field: "Page URL", value: urlscan?.page_url || "—" },
                { field: "Page IP", value: urlscan?.page_ip || "—" },
                { field: "Page Title", value: urlscan?.page_title || "—" },
                { field: "Country", value: urlscan?.page_country || "—" },
                { field: "Server", value: urlscan?.page_server || "—" },
                { field: "Requests", value: urlscan?.requests_count ?? "—" },
                { field: "Scan ID", value: urlscan?.scan_id || "—" },
                { field: "Tags", value: arr(urlscan?.tags).join(", ") || "—" },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />

            {arr(urlscan?.notes).length > 0 && (
              <EvidenceTable
                title="URLScan Notes"
                data={arr(urlscan.notes).map((n: string) => ({ note: n }))}
                columns={[{ key: "note", wrap: true }]}
              />
            )}

            {urlscan?.screenshot_artifact_id && (
              <div style={{ marginTop: 10, fontSize: 12 }}>
                Screenshot artifact:{" "}
                <a
                  href={getArtifactUrl(urlscan.screenshot_artifact_id)}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: "var(--accent)" }}
                >
                  {urlscan.screenshot_artifact_id}
                </a>
              </div>
            )}
          </>
        )}
      </Section>

      {/* URL LEXICAL ML */}
      {(type === "url" || type === "domain") && (
        <Section title="URL Lexical ML">
          {!urlLexical || Object.keys(urlLexical).length === 0 ? (
            <EmptyNote>URL lexical ML data not available (collector not run)</EmptyNote>
          ) : (
            <EvidenceTable
              title="Lexical Risk Summary"
              data={[
                { field: "Model Source", value: urlLexical?.model_source || "built_in" },
                {
                  field: "Phishing Probability",
                  value: typeof urlMlScore?.phishing_probability === "number"
                    ? urlMlScore.phishing_probability.toFixed(4)
                    : typeof urlLexical?.score === "number"
                      ? urlLexical.score.toFixed(4)
                      : "—",
                },
                { field: "Risk Label", value: String(urlMlScore?.risk_level || urlLexical?.label || "unknown").toUpperCase() },
                { field: "Model Version", value: urlMlScore?.model_version || "—" },
                { field: "Thresholds", value: "<0.3 low | 0.3-0.65 medium | >0.65 high" },
                {
                  field: "Top Features",
                  value: arr(urlLexical?.top_features).length
                    ? arr(urlLexical?.top_features).slice(0, 5).join(", ")
                    : "—",
                },
                { field: "Error", value: urlLexical?.error || "—" },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />
          )}
        </Section>
      )}

      <Section title="Content ML Signals">
        {!contentMl || Object.keys(contentMl).length === 0 ? (
          <EmptyNote>Content ML data not available</EmptyNote>
        ) : (
          <EvidenceTable
            title="Header/Metadata Risk Signals"
            data={[
              { field: "Social Engineering", value: typeof contentMl?.social_engineering_probability === "number" ? contentMl.social_engineering_probability.toFixed(4) : "—" },
              { field: "Urgency", value: typeof contentMl?.urgency_probability === "number" ? contentMl.urgency_probability.toFixed(4) : "—" },
              { field: "Impersonation", value: typeof contentMl?.impersonation_probability === "number" ? contentMl.impersonation_probability.toFixed(4) : "—" },
              { field: "BEC", value: typeof contentMl?.bec_probability === "number" ? contentMl.bec_probability.toFixed(4) : "—" },
              { field: "Top Terms", value: arr(contentMl?.top_content_terms).join(", ") || "—" },
              { field: "Model Source", value: contentMl?.model_source || "—" },
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
        )}
      </Section>

      <Section title="Attachment Static Analysis">
        {!attachmentAnalysis?.items?.length ? (
          <EmptyNote>No attachment static analysis available</EmptyNote>
        ) : (
          <EvidenceTable
            title="Attachment Risk"
            data={arr(attachmentAnalysis.items).map((item: any, idx: number) => ({
              index: idx + 1,
              filename: item?.filename || "—",
              hash: item?.hash ? (
                <span
                  title={String(item.hash)}
                  style={{
                    display: "inline-block",
                    maxWidth: 360,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    verticalAlign: "bottom",
                  }}
                >
                  {String(item.hash)}
                </span>
              ) : "-",
              risk: `Risk: ${String(item?.risk_level || "unknown").toUpperCase()}`,
              score: `Static score: ${typeof item?.static_risk_score === "number" ? item.static_risk_score.toFixed(4) : "-"}`,
              macro: `Macro: ${item?.macro_detected ? "Yes" : "No"}`,
              entropy: `Entropy: ${typeof item?.entropy === "number" ? item.entropy.toFixed(4) : "-"}`,
            }))}
            columns={[
              { key: "index", label: "#" },
              { key: "filename", label: "Filename" },
              { key: "hash", label: "SHA256 Hash" },
              { key: "risk", label: "Risk Level" },
              { key: "score", label: "Static Risk Score (0-1)" },
              { key: "macro", label: "Macro Detected" },
              { key: "entropy", label: "Entropy (0-1)" },
            ]}
            showHeader
          />
        )}
      </Section>

      {(type === "url" || type === "domain") && (
        <Section title="URL Behavior Analysis">
          {!urlBehavior || Object.keys(urlBehavior).length === 0 ? (
            <EmptyNote>URL behavior data not available</EmptyNote>
          ) : (
            <EvidenceTable
              title="Behavior Summary"
              data={[
                { field: "Redirect Count", value: urlBehavior?.redirect_count ?? 0 },
                { field: "UA Cloaking", value: urlBehavior?.ua_cloaking_detected ? "Yes" : "No" },
                { field: "Credential Form", value: urlBehavior?.credential_form_present ? "Yes" : "No" },
                { field: "Multiple Domain Hops", value: urlBehavior?.multiple_domain_hops ? "Yes" : "No" },
                { field: "Behavior Score", value: typeof urlBehavior?.behavior_score === "number" ? urlBehavior.behavior_score.toFixed(4) : "—" },
                { field: "Final URL", value: urlBehavior?.final_url || "—" },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />
          )}
        </Section>
      )}

      <Section title="AnyRun Analysis">
        <AnyRunInteractiveEvidence hybridAnalysis={hybridAnalysis} />
      </Section>

      <Section title="Final Risk Aggregation">
        {!finalRisk || Object.keys(finalRisk).length === 0 ? (
          <EmptyNote>Final risk data not available</EmptyNote>
        ) : (
          <>
            <EvidenceTable
              title="Risk Summary"
              data={[
                { field: "Risk Score", value: finalRisk?.risk_score ?? "—" },
                { field: "Risk Level", value: String(finalRisk?.risk_level || "unknown").toUpperCase() },
                { field: "Confidence", value: String(finalRisk?.confidence || "unknown").toUpperCase() },
              ]}
              columns={[{ key: "field" }, { key: "value", wrap: true }]}
            />
            {arr(finalRisk?.rationale).length > 0 && (
              <EvidenceTable
                title="Rationale"
                data={arr(finalRisk.rationale).map((r: string) => ({ rationale: r }))}
                columns={[{ key: "rationale", wrap: true }]}
              />
            )}
          </>
        )}
      </Section>

      {/* REDIRECT DESTINATION INTELLIGENCE */}
      {(type === "url" || type === "domain") && (
        <Section title="Redirect Destination Intelligence">
          {!hasRedirectDestinationIntel ? (
            <EmptyNote>No cross-domain redirect destination intel available</EmptyNote>
          ) : (
            <>
              <EvidenceTable
                title="Redirect Comparison"
                data={[
                  {
                    field: "Source vs Destination Root",
                    value: redirectDestinationIntel?.comparison?.source_vs_destination_root || "—",
                  },
                  { field: "Final URL", value: redirectDestinationIntel?.final_url || "—" },
                  { field: "Source Host", value: redirectDestinationIntel?.investigated_host || "—" },
                  { field: "Destination Host", value: redirectDestinationIntel?.destination_host || "—" },
                  {
                    field: "Source Domain Age (days)",
                    value: redirectDestinationIntel?.comparison?.source_age_days ?? "—",
                  },
                  {
                    field: "Destination Domain Age (days)",
                    value: redirectDestinationIntel?.comparison?.destination_age_days ?? "—",
                  },
                ]}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />

              {redirectDestinationIntel?.whois && (
                <EvidenceTable
                  title="Destination WHOIS"
                  data={[
                    { field: "Collector Status", value: redirectDestinationIntel.whois.status || "—" },
                    { field: "Registrar", value: redirectDestinationIntel.whois.registrar || "—" },
                    { field: "Domain Age (days)", value: redirectDestinationIntel.whois.domain_age_days ?? "—" },
                    { field: "Created Date", value: fmtDate(redirectDestinationIntel.whois.created_date) },
                    { field: "Expiry Date", value: fmtDate(redirectDestinationIntel.whois.expiry_date) },
                    {
                      field: "Registrant",
                      value: redirectDestinationIntel.whois.registrant_org || redirectDestinationIntel.whois.registrant_country || "—",
                    },
                    {
                      field: "Name Servers",
                      value: arr(redirectDestinationIntel.whois.name_servers).join(", ") || "—",
                    },
                    { field: "Error", value: redirectDestinationIntel.whois.error || "—" },
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }]}
                />
              )}

              {redirectDestinationIntel?.vt && (
                <EvidenceTable
                  title="Destination VirusTotal"
                  data={[
                    { field: "Collector Status", value: redirectDestinationIntel.vt.status || "—" },
                    { field: "Found in VT", value: redirectDestinationIntel.vt.found ? "Yes" : "No" },
                    { field: "Malicious", value: redirectDestinationIntel.vt.malicious_count ?? 0 },
                    { field: "Suspicious", value: redirectDestinationIntel.vt.suspicious_count ?? 0 },
                    { field: "Total Vendors", value: redirectDestinationIntel.vt.total_vendors ?? 0 },
                    { field: "Reputation Score", value: redirectDestinationIntel.vt.reputation_score ?? "—" },
                    {
                      field: "Categories",
                      value: redirectDestinationIntel.vt.categories
                        ? Object.entries(redirectDestinationIntel.vt.categories)
                            .map(([k, v]) => `${k}:${v}`)
                            .join(", ") || "—"
                        : "—",
                    },
                    { field: "Error", value: redirectDestinationIntel.vt.error || "—" },
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }]}
                />
              )}

              {(redirectDestinationIntel?.dns || redirectDestinationIntel?.hosting) && (
                <EvidenceTable
                  title="Destination Infrastructure"
                  data={[
                    { field: "DNS Status", value: redirectDestinationIntel?.dns?.status || "—" },
                    { field: "A / AAAA", value: [...arr(redirectDestinationIntel?.dns?.a), ...arr(redirectDestinationIntel?.dns?.aaaa)].join(", ") || "—" },
                    { field: "MX", value: arr(redirectDestinationIntel?.dns?.mx).join(", ") || "—" },
                    { field: "NS", value: arr(redirectDestinationIntel?.dns?.ns).join(", ") || "—" },
                    { field: "Hosting Status", value: redirectDestinationIntel?.hosting?.status || "—" },
                    { field: "IP", value: redirectDestinationIntel?.hosting?.ip || "—" },
                    { field: "ASN", value: redirectDestinationIntel?.hosting?.asn ?? "—" },
                    { field: "ASN Org", value: redirectDestinationIntel?.hosting?.asn_org || "—" },
                    { field: "Country", value: redirectDestinationIntel?.hosting?.country || "—" },
                    { field: "CDN / Cloud", value: `${redirectDestinationIntel?.hosting?.is_cdn ? "CDN" : "no CDN"} | ${redirectDestinationIntel?.hosting?.is_cloud ? "cloud" : "non-cloud"}` },
                  ]}
                  columns={[{ key: "field" }, { key: "value", wrap: true }]}
                />
              )}
            </>
          )}
        </Section>
      )}

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
                    â„¹ {note}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </Section>

      {/* THREAT FEEDS */}
      {evidence?.brave_osint && (
        <Section title="Brave OSINT">
          {braveOsint?.meta?.status === "failed" ? (
            <EmptyNote>Brave OSINT lookup failed: {braveOsint?.meta?.error || braveOsint?.error || "unknown error"}</EmptyNote>
          ) : !braveOsint?.checked ? (
            <EmptyNote>Brave OSINT data not available (collector not run)</EmptyNote>
          ) : (
            <>
              <EvidenceTable
                title="Brave OSINT Summary"
                data={[
                  { field: "Risk Score", value: braveOsint?.score ?? "—" },
                  { field: "Risk Level", value: String(braveOsint?.risk_level || "unknown").toUpperCase() },
                  { field: "Queries Run", value: arr(braveOsint?.queries).length || 0 },
                  { field: "Relevant Hits", value: arr(braveOsint?.top_hits).length || 0 },
                  { field: "All Results", value: arr(braveOsint?.all_results).length || 0 },
                  {
                    field: "Sources",
                    value: braveOsint?.source_counts
                      ? Object.entries(braveOsint.source_counts).map(([k, v]) => `${k} (${v})`).join(", ") || "—"
                      : "—",
                  },
                ]}
                columns={[{ key: "field" }, { key: "value", wrap: true }]}
              />
              {braveOsint?.summary && (
                <div style={{ marginTop: 12, fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>
                  {braveOsint.summary}
                </div>
              )}
              {arr(braveOsint?.queries).length > 0 && (
                <EvidenceTable
                  title="Generated Queries"
                  data={arr(braveOsint.queries).map((query: string) => ({ query }))}
                  columns={[{ key: "query", wrap: true }]}
                />
              )}
              {arr(braveOsint?.top_hits).length > 0 && (
                <EvidenceTable
                  title="Top Relevant Hits"
                  data={arr(braveOsint.top_hits).map((hit: any, index: number) => ({
                    index: index + 1,
                    source: hit?.source || "unknown",
                    score: hit?.score ?? "—",
                    title: hit?.title || "—",
                    keywords: arr(hit?.matched_keywords).join(", ") || "—",
                    url: hit?.url || "—",
                  }))}
                  columns={[
                    { key: "index", label: "#" },
                    { key: "source", label: "Source" },
                    { key: "score", label: "Score" },
                    { key: "title", label: "Title", wrap: true },
                    { key: "keywords", label: "Matched Keywords", wrap: true },
                    { key: "url", label: "URL", wrap: true },
                  ]}
                  showHeader
                />
              )}
              {arr(braveOsint?.all_results).length > 0 && (
                <EvidenceTable
                  title="All Brave Search Results"
                  data={arr(braveOsint.all_results).map((hit: any, index: number) => ({
                    index: index + 1,
                    source: hit?.source || "unknown",
                    title: hit?.title || "—",
                    description: hit?.description || "—",
                    url: hit?.url || "—",
                  }))}
                  columns={[
                    { key: "index", label: "#" },
                    { key: "source", label: "Source" },
                    { key: "title", label: "Title", wrap: true },
                    { key: "description", label: "Description", wrap: true },
                    { key: "url", label: "URL", wrap: true },
                  ]}
                  showHeader
                />
              )}
              {arr(braveOsint?.notes).length > 0 && (
                <EvidenceTable
                  title="Collector Notes"
                  data={arr(braveOsint.notes).map((note: string) => ({ note }))}
                  columns={[{ key: "note", wrap: true }]}
                />
              )}
            </>
          )}
        </Section>
      )}

      {/* THREAT FEEDS */}
      {evidence?.threat_feeds && (
        <Section title="Threat Feed Intelligence">
          <ThreatFeedsSection threatFeeds={evidence.threat_feeds} />
        </Section>
      )}

      {/* FAVICON HASH INTELLIGENCE — domain-specific */}
      {!isFileHash && evidence?.favicon_intel && (
        <Section title="Favicon Hash Intelligence">
          <FaviconIntelSection faviconIntel={evidence.favicon_intel} />
        </Section>
      )}

      {/* CERTIFICATE TRANSPARENCY TIMELINE — domain-specific */}
      {!isFileHash && evidence?.cert_timeline && evidence.cert_timeline.total_certs > 0 && (
        <Section title="Certificate Transparency Timeline">
          <CertTimelineSection certTimeline={evidence.cert_timeline} />
        </Section>
      )}

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
            ...(evidence?.brave_osint ? [metaRow("BRAVE OSINT", evidence.brave_osint.meta)] : []),
            metaRow("URLSCAN", urlscan.meta),
            ...(evidence?.hybrid_analysis ? [metaRow("SANDBOX (ANY.RUN/HYBRID)", (evidence as any).hybrid_analysis?.meta)] : []),
            ...(evidence?.threat_feeds ? [metaRow("THREAT FEEDS", evidence.threat_feeds.meta)] : []),
          ].filter(Boolean) as any[]}
          columns={[
            { key: "collector" },
            { key: "status" },
            { key: "duration" },
            { key: "error", wrap: true },
          ]}
        />
      </Section>
      </EvidenceSplitContext.Provider>
      </div>
    </div>
  );
}

// --- Helpers ---

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
  const split = React.useContext(EvidenceSplitContext);
  if (split?.activeTitle && split.activeTitle !== title) return null;
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

function ClickableStatBox({ label, value, color, active, onClick }: {
  label: string; value: number; color: string; active: boolean; onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      style={{
        padding: "14px 16px",
        background: active ? `${color}18` : value > 0 ? `${color}0a` : "var(--bg-input)",
        border: `1px solid ${active ? color : value > 0 ? `${color}33` : "var(--border)"}`,
        borderRadius: "var(--radius)",
        textAlign: "center",
        cursor: "pointer",
        transition: "all 0.15s ease",
        outline: active ? `2px solid ${color}` : "none",
        outlineOffset: -1,
      }}
    >
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
        textDecoration: active ? "underline" : "none",
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







