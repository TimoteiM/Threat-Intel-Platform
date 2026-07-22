"use client";

import React from "react";
import EvidenceTable from "@/components/evidence/EvidenceTable";

interface Props {
  intelligence: any;
  redirectChain?: any[];
}

type RedirectStep = {
  host: string;
  url?: string;
  role: "source" | "redirect" | "destination";
  status?: number | string;
};

export default function RedirectDestinationGraph({ intelligence, redirectChain = [] }: Props) {
  const whois = intelligence?.whois;
  const vt = intelligence?.vt;
  const dns = intelligence?.dns;
  const hosting = intelligence?.hosting;
  const sourceHost = intelligence?.investigated_host || hostFromUrl(redirectChain[0]?.url) || "Unknown source";
  const destinationHost = intelligence?.destination_host || hostFromUrl(intelligence?.final_url) || "Unknown destination";
  const steps = buildSteps(sourceHost, destinationHost, intelligence?.final_url, redirectChain);
  const malicious = numberOrZero(vt?.malicious_count);
  const suspicious = numberOrZero(vt?.suspicious_count);
  const totalVendors = numberOrZero(vt?.total_vendors);
  const verdict = !vt ? "Reputation unavailable" : !vt.found ? "Not found in VirusTotal" : malicious > 0 ? "Malicious detections" : suspicious > 0 ? "Suspicious detections" : "No detections";
  const verdictColor = !vt || !vt.found ? "var(--text-muted)" : malicious > 0 ? "var(--red)" : suspicious > 0 ? "var(--yellow)" : "var(--green)";
  const isCrossDomain = sourceHost !== destinationHost;
  const resolvedIps = [...asArray(dns?.a), ...asArray(dns?.aaaa)];

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div style={{
        border: "1px solid var(--border)", borderRadius: 10, overflow: "hidden",
        background: "linear-gradient(145deg, rgba(20,34,55,.98), rgba(10,22,39,.98))",
      }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12,
          flexWrap: "wrap", padding: "13px 16px", borderBottom: "1px solid var(--border)",
          background: "rgba(255,255,255,.018)",
        }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>Redirect path</div>
            <div style={{ marginTop: 3, fontSize: 10, color: "var(--text-muted)" }}>
              {steps.length - 1} transition{steps.length - 1 === 1 ? "" : "s"} observed
            </div>
          </div>
          <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
            <Badge color={isCrossDomain ? "var(--yellow)" : "var(--green)"}>
              {isCrossDomain ? "Cross-domain" : "Same domain"}
            </Badge>
            <Badge color={verdictColor}>{verdict}</Badge>
          </div>
        </div>

        <div style={{
          overflowX: "auto", padding: "28px 22px 30px",
          backgroundImage: "linear-gradient(rgba(100,140,190,.055) 1px, transparent 1px), linear-gradient(90deg, rgba(100,140,190,.055) 1px, transparent 1px)",
          backgroundSize: "22px 22px",
        }}>
          <div style={{ display: "flex", alignItems: "center", minWidth: "max-content" }}>
            {steps.map((step, index) => (
              <React.Fragment key={`${step.role}-${step.host}-${index}`}>
                {index > 0 && <GraphEdge status={step.status} />}
                <GraphNode step={step} destinationColor={verdictColor} />
              </React.Fragment>
            ))}
          </div>
        </div>

        <div style={{ padding: "11px 16px", borderTop: "1px solid var(--border)", display: "grid", gap: 4 }}>
          <span style={{ color: "var(--text-muted)", fontSize: 9, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase" }}>
            Final URL
          </span>
          <span title={intelligence?.final_url || ""} style={{
            fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)",
            overflowWrap: "anywhere", lineHeight: 1.5,
          }}>
            {intelligence?.final_url || "—"}
          </span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 250px), 1fr))", gap: 10 }}>
        {whois && (
          <IntelCard eyebrow="Identity" title="Registration" status={whois.status} accent="#60a5fa">
            <Fact label="Registrar" value={whois.registrar} />
            <Fact label="Domain age" value={formatAge(whois.domain_age_days)} />
            <Fact label="Created" value={formatDate(whois.created_date)} />
            <Fact label="Expires" value={formatDate(whois.expiry_date)} />
            <Fact label="Registrant" value={whois.registrant_org || whois.registrant_country} />
          </IntelCard>
        )}

        {vt && (
          <IntelCard eyebrow="Reputation" title="VirusTotal" status={vt.status} accent={verdictColor}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 7, marginBottom: 11 }}>
              <span style={{ fontSize: 28, lineHeight: 1, fontWeight: 750, color: verdictColor }}>{malicious + suspicious}</span>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>/ {totalVendors || "—"} engines flagged</span>
            </div>
            <div style={{ height: 4, borderRadius: 99, overflow: "hidden", background: "rgba(148,163,184,.15)", marginBottom: 12 }}>
              <div style={{ width: `${totalVendors ? Math.max(2, ((malicious + suspicious) / totalVendors) * 100) : 0}%`, height: "100%", background: verdictColor }} />
            </div>
            <Fact label="Malicious" value={malicious} valueColor={malicious ? "var(--red)" : undefined} />
            <Fact label="Suspicious" value={suspicious} valueColor={suspicious ? "var(--yellow)" : undefined} />
            <Fact label="Reputation" value={vt.reputation_score} />
            {!!vt?.categories && (
              <ChipList values={Object.entries(vt.categories).map(([vendor, category]) => `${vendor}: ${category}`)} />
            )}
          </IntelCard>
        )}

        {(dns || hosting) && (
          <IntelCard eyebrow="Infrastructure" title="Network context" status={hosting?.status || dns?.status} accent="#a78bfa">
            <Fact label="IP address" value={hosting?.ip || resolvedIps[0]} mono />
            <Fact label="ASN" value={hosting?.asn ? `AS${hosting.asn}` : undefined} />
            <Fact label="Network" value={hosting?.asn_org} />
            <Fact label="Country" value={hosting?.country} />
            <ChipList values={[
              hosting?.is_cdn ? "CDN" : "",
              hosting?.is_cloud ? "Cloud" : "",
              ...resolvedIps.slice(hosting?.ip ? 0 : 1, 4),
            ].filter(Boolean)} />
          </IntelCard>
        )}
      </div>

      <details style={{ border: "1px solid var(--border)", borderRadius: 8, background: "var(--bg-card)", overflow: "hidden" }}>
        <summary style={{ padding: "11px 14px", cursor: "pointer", fontSize: 11, fontWeight: 650, color: "var(--text-secondary)" }}>
          Raw collector evidence
        </summary>
        <div style={{ padding: "2px 12px 12px" }}>
          <EvidenceTable
            title="Redirect comparison"
            data={[
              { field: "Source vs Destination Root", value: intelligence?.comparison?.source_vs_destination_root || "—" },
              { field: "Final URL", value: intelligence?.final_url || "—" },
              { field: "Source Host", value: sourceHost },
              { field: "Destination Host", value: destinationHost },
              { field: "Source Domain Age (days)", value: intelligence?.comparison?.source_age_days ?? "—" },
              { field: "Destination Domain Age (days)", value: intelligence?.comparison?.destination_age_days ?? "—" },
            ]}
            columns={[{ key: "field" }, { key: "value", wrap: true }]}
          />
          {whois && <EvidenceTable title="Destination WHOIS" data={[
            { field: "Collector Status", value: whois.status || "—" }, { field: "Registrar", value: whois.registrar || "—" },
            { field: "Domain Age (days)", value: whois.domain_age_days ?? "—" }, { field: "Created Date", value: formatDate(whois.created_date) },
            { field: "Expiry Date", value: formatDate(whois.expiry_date) }, { field: "Registrant", value: whois.registrant_org || whois.registrant_country || "—" },
            { field: "Name Servers", value: asArray(whois.name_servers).join(", ") || "—" }, { field: "Error", value: whois.error || "—" },
          ]} columns={[{ key: "field" }, { key: "value", wrap: true }]} />}
          {vt && <EvidenceTable title="Destination VirusTotal" data={[
            { field: "Collector Status", value: vt.status || "—" }, { field: "Found in VT", value: vt.found ? "Yes" : "No" },
            { field: "Malicious", value: malicious }, { field: "Suspicious", value: suspicious }, { field: "Total Vendors", value: totalVendors },
            { field: "Reputation Score", value: vt.reputation_score ?? "—" },
            { field: "Categories", value: vt.categories ? Object.entries(vt.categories).map(([k, v]) => `${k}:${v}`).join(", ") || "—" : "—" },
            { field: "Error", value: vt.error || "—" },
          ]} columns={[{ key: "field" }, { key: "value", wrap: true }]} />}
          {(dns || hosting) && <EvidenceTable title="Destination Infrastructure" data={[
            { field: "DNS Status", value: dns?.status || "—" }, { field: "A / AAAA", value: resolvedIps.join(", ") || "—" },
            { field: "MX", value: asArray(dns?.mx).join(", ") || "—" }, { field: "NS", value: asArray(dns?.ns).join(", ") || "—" },
            { field: "Hosting Status", value: hosting?.status || "—" }, { field: "IP", value: hosting?.ip || "—" },
            { field: "ASN", value: hosting?.asn ?? "—" }, { field: "ASN Org", value: hosting?.asn_org || "—" },
            { field: "Country", value: hosting?.country || "—" },
            { field: "CDN / Cloud", value: `${hosting?.is_cdn ? "CDN" : "no CDN"} | ${hosting?.is_cloud ? "cloud" : "non-cloud"}` },
          ]} columns={[{ key: "field" }, { key: "value", wrap: true }]} />}
        </div>
      </details>
    </div>
  );
}

function GraphNode({ step, destinationColor }: { step: RedirectStep; destinationColor: string }) {
  const accent = step.role === "source" ? "#60a5fa" : step.role === "destination" ? destinationColor : "#a78bfa";
  const label = step.role === "source" ? "Investigated host" : step.role === "destination" ? "Final destination" : "Redirect hop";
  return (
    <div style={{ width: 190, border: `1px solid color-mix(in srgb, ${accent} 48%, transparent)`, borderRadius: 8, background: "rgba(11,24,42,.96)", boxShadow: `0 8px 24px rgba(0,0,0,.22), inset 3px 0 0 ${accent}` }}>
      <div style={{ padding: "11px 12px 10px 15px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 7, color: accent, fontSize: 9, fontWeight: 750, letterSpacing: ".08em", textTransform: "uppercase" }}>
          <span style={{ width: 7, height: 7, borderRadius: 99, background: accent, boxShadow: `0 0 8px ${accent}` }} />
          {label}
        </div>
        <div title={step.host} style={{ marginTop: 8, color: "var(--text-primary)", fontSize: 12, fontWeight: 700, fontFamily: "var(--font-mono)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {step.host}
        </div>
        {step.url && <div title={step.url} style={{ marginTop: 4, fontSize: 9, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{pathFromUrl(step.url)}</div>}
      </div>
    </div>
  );
}

function GraphEdge({ status }: { status?: number | string }) {
  return (
    <div style={{ width: 72, position: "relative", height: 30, flex: "0 0 72px" }}>
      <div style={{ position: "absolute", left: 0, right: 8, top: 15, height: 1, background: "#4b759f", boxShadow: "0 0 6px rgba(96,165,250,.3)" }} />
      <div style={{ position: "absolute", right: 3, top: 11, width: 8, height: 8, borderTop: "1px solid #6ea1d3", borderRight: "1px solid #6ea1d3", transform: "rotate(45deg)" }} />
      {status != null && <span style={{ position: "absolute", top: -1, left: "50%", transform: "translateX(-50%)", padding: "1px 5px", borderRadius: 8, background: "#142b45", border: "1px solid #294969", color: "#8fb8df", fontSize: 8, fontFamily: "var(--font-mono)" }}>{status}</span>}
    </div>
  );
}

function IntelCard({ eyebrow, title, status, accent, children }: { eyebrow: string; title: string; status?: string; accent: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: 14, border: "1px solid var(--border)", borderRadius: 9, background: "linear-gradient(160deg, var(--bg-card), rgba(15,28,47,.82))", minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, marginBottom: 13 }}>
        <div>
          <div style={{ color: accent, fontSize: 8, fontWeight: 750, letterSpacing: ".1em", textTransform: "uppercase" }}>{eyebrow}</div>
          <div style={{ color: "var(--text-primary)", fontSize: 12, fontWeight: 700, marginTop: 3 }}>{title}</div>
        </div>
        {status && <span style={{ color: status === "completed" ? "var(--green)" : "var(--text-muted)", fontSize: 8, textTransform: "uppercase", letterSpacing: ".06em" }}>{status}</span>}
      </div>
      {children}
    </div>
  );
}

function Fact({ label, value, mono = false, valueColor }: { label: string; value: any; mono?: boolean; valueColor?: string }) {
  if (value == null || value === "") return null;
  return <div style={{ display: "grid", gridTemplateColumns: "88px minmax(0,1fr)", gap: 8, padding: "5px 0", borderTop: "1px solid rgba(148,163,184,.08)", fontSize: 10 }}>
    <span style={{ color: "var(--text-muted)" }}>{label}</span>
    <span title={String(value)} style={{ color: valueColor || "var(--text-secondary)", fontWeight: 600, fontFamily: mono ? "var(--font-mono)" : undefined, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(value)}</span>
  </div>;
}

function ChipList({ values }: { values: string[] }) {
  if (!values.length) return null;
  return <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 10 }}>{values.map((value, i) => <span key={`${value}-${i}`} title={value} style={{ maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", padding: "3px 7px", borderRadius: 99, border: "1px solid rgba(148,163,184,.16)", background: "rgba(148,163,184,.07)", color: "var(--text-muted)", fontSize: 8 }}>{value}</span>)}</div>;
}

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ padding: "4px 8px", borderRadius: 99, border: `1px solid color-mix(in srgb, ${color} 35%, transparent)`, background: `color-mix(in srgb, ${color} 8%, transparent)`, color, fontSize: 9, fontWeight: 700 }}>{children}</span>;
}

function buildSteps(source: string, destination: string, finalUrl: string | undefined, chain: any[]): RedirectStep[] {
  const steps: RedirectStep[] = [{ host: source, role: "source" }];
  const hops = asArray(chain);
  for (let index = 0; index < hops.length; index += 1) {
    const hop = hops[index];
    const host = hostFromUrl(hop?.url);
    if (!host || host === steps[steps.length - 1]?.host || host === destination) continue;
    steps.push({ host, url: hop.url, role: "redirect", status: chain[Math.max(0, index - 1)]?.status_code });
  }
  if (destination === source && steps.length === 1) {
    steps[0].url = finalUrl;
  } else {
    steps.push({ host: destination, url: finalUrl, role: "destination", status: chain[Math.max(0, chain.length - 2)]?.status_code });
  }
  return steps;
}

function hostFromUrl(value?: string): string {
  if (!value) return "";
  try { return new URL(value).hostname; } catch { return ""; }
}

function pathFromUrl(value: string): string {
  try { const parsed = new URL(value); return `${parsed.pathname}${parsed.search}` || "/"; } catch { return value; }
}

function asArray(value: any): any[] { return Array.isArray(value) ? value : []; }
function numberOrZero(value: any): number { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : 0; }
function formatAge(value: any): string { const days = Number(value); return Number.isFinite(days) ? `${days.toLocaleString()} days · ${(days / 365.25).toFixed(1)} years` : "—"; }
function formatDate(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}
