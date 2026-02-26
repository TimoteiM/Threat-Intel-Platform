"use client";

import React, { useState, useRef } from "react";
import { uploadReferenceImage } from "@/lib/api";
import type { ObservableType } from "@/lib/types";

interface Props {
  onSubmit: (
    domain: string,
    context?: string,
    clientDomain?: string,
    investigatedUrl?: string,
    clientUrl?: string,
    requestedCollectors?: string[],
    observableType?: ObservableType,
    fileToUpload?: File,
    deepScan?: boolean,
  ) => void;
  loading: boolean;
}

const OBSERVABLE_TYPES: { id: ObservableType; label: string; placeholder: string }[] = [
  { id: "domain", label: "Domain",  placeholder: "suspicious-site.com" },
  { id: "url",    label: "URL",     placeholder: "https://phishing.com/login" },
  { id: "hash",   label: "Hash",    placeholder: "sha256:abc123... or md5:..." },
  { id: "file",   label: "File",    placeholder: "Upload a file sample" },
];

const COLLECTOR_DESCRIPTORS: { id: string; label: string; desc: string }[] = [
  { id: "dns",              label: "DNS",              desc: "Records, nameservers, MX" },
  { id: "http",             label: "HTTP",             desc: "Headers, title, tech stack" },
  { id: "tls",              label: "TLS",              desc: "Certificate & cipher analysis" },
  { id: "whois",            label: "WHOIS",            desc: "Registrar & registrant info" },
  { id: "asn",              label: "ASN",              desc: "AS number, BGP prefix, ISP" },
  { id: "intel",            label: "Intel",            desc: "crt.sh, URLScan, DNSBL" },
  { id: "vt",           label: "VirusTotal",   desc: "Multi-engine AV scan" },
  { id: "threat_feeds", label: "Threat Feeds", desc: "AbuseIPDB, PhishTank, ThreatFox" },
  { id: "urlscan",      label: "URLScan",      desc: "Full page scan, screenshot, network map" },
];

// Which collectors support each observable type
const COLLECTORS_PER_TYPE: Record<ObservableType, string[]> = {
  domain: ["dns", "http", "tls", "whois", "asn", "intel", "vt", "threat_feeds", "urlscan"],
  ip:     ["asn", "vt", "threat_feeds", "urlscan"],
  url:    ["dns", "http", "tls", "whois", "asn", "intel", "vt", "threat_feeds", "urlscan"],
  hash:   ["vt", "threat_feeds"],
  file:   ["vt"],
};

export default function InvestigationInput({ onSubmit, loading }: Props) {
  const [observableType, setObservableType] = useState<ObservableType>("domain");
  const [domain, setDomain] = useState("");
  const [fileToUpload, setFileToUpload] = useState<File | null>(null);
  const [context, setContext] = useState("");
  const [deepScan, setDeepScan] = useState(false);
  const [clientDomain, setClientDomain] = useState("");
  const [showContext, setShowContext] = useState(false);
  const [showClientDomain, setShowClientDomain] = useState(false);
  const [showAnalyzers, setShowAnalyzers] = useState(false);
  const [selectedCollectors, setSelectedCollectors] = useState<string[]>(COLLECTORS_PER_TYPE["domain"]);
  const [investigatedUrl, setInvestigatedUrl] = useState("");
  const [clientUrl, setClientUrl] = useState("");
  const [referenceFile, setReferenceFile] = useState<File | null>(null);
  const [uploadingRef, setUploadingRef] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const sampleFileRef = useRef<HTMLInputElement>(null);

  const supportedCollectors = COLLECTORS_PER_TYPE[observableType];
  const canSubmit = (observableType === "file" ? !!fileToUpload : domain.trim().length > 0) && !loading;

  const handleTypeChange = (type: ObservableType) => {
    setObservableType(type);
    setSelectedCollectors(COLLECTORS_PER_TYPE[type]); // auto-select all applicable
    setDomain("");
    setFileToUpload(null);
    if (type !== "file") setDeepScan(false);
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;

    // Upload reference image if provided
    if (referenceFile && clientDomain.trim()) {
      try {
        setUploadingRef(true);
        await uploadReferenceImage(clientDomain.trim(), referenceFile);
      } catch (e: any) {
        alert(`Failed to upload reference image: ${e.message}`);
        setUploadingRef(false);
        return;
      }
      setUploadingRef(false);
    }

    onSubmit(
      domain.trim(),
      context.trim() || undefined,
      clientDomain.trim() || undefined,
      investigatedUrl.trim() || undefined,
      clientUrl.trim() || undefined,
      selectedCollectors.length > 0 ? selectedCollectors : undefined,
      observableType,
      fileToUpload || undefined,
      observableType === "file" ? deepScan : undefined,
    );
  };

  const inputBase: React.CSSProperties = {
    width: "100%",
    padding: "12px 16px",
    background: "var(--bg-input)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius)",
    color: "var(--text)",
    fontSize: 14,
    fontFamily: "var(--font-mono)",
    outline: "none",
    transition: "border-color 0.2s, box-shadow 0.2s",
    boxSizing: "border-box" as const,
  };

  const toggleStyle: React.CSSProperties = {
    background: "none",
    border: "none",
    color: "var(--text-dim)",
    fontSize: 11,
    cursor: "pointer",
    marginTop: 14,
    fontFamily: "var(--font-sans)",
    padding: "4px 0",
    fontWeight: 500,
  };

  const placeholder = OBSERVABLE_TYPES.find((t) => t.id === observableType)?.placeholder ?? "";

  return (
    <div
      style={{
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        padding: 28,
        marginTop: 20,
        boxShadow: "var(--shadow-md)",
      }}
      className="animate-in"
    >
      <div style={{
        fontSize: 13,
        color: "var(--text-dim)",
        letterSpacing: "0.02em",
        marginBottom: 16,
        fontWeight: 600,
        fontFamily: "var(--font-sans)",
      }}>
        New Investigation
      </div>

      {/* ── Observable type selector ── */}
      <div style={{
        display: "flex",
        gap: 6,
        marginBottom: 14,
        flexWrap: "wrap",
      }}>
        {OBSERVABLE_TYPES.map((t) => {
          const active = t.id === observableType;
          return (
            <button
              key={t.id}
              onClick={() => handleTypeChange(t.id)}
              style={{
                padding: "6px 14px",
                borderRadius: "var(--radius-sm)",
                border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                background: active ? "rgba(96,165,250,0.12)" : "var(--bg-elevated)",
                color: active ? "var(--accent)" : "var(--text-dim)",
                fontSize: 11,
                fontWeight: active ? 700 : 500,
                fontFamily: "var(--font-mono)",
                cursor: "pointer",
                transition: "all 0.15s",
                letterSpacing: "0.03em",
              }}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* ── Main input or file drop ── */}
      <div style={{ display: "flex", gap: 12 }}>
        <div style={{ flex: 1 }}>
          {observableType === "file" ? (
            <div
              onClick={() => sampleFileRef.current?.click()}
              style={{
                ...inputBase,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 10,
                borderStyle: "dashed",
                color: fileToUpload ? "var(--text)" : "var(--text-muted)",
              }}
            >
              <span style={{ fontSize: 16 }}>📎</span>
              <span>
                {fileToUpload
                  ? `${fileToUpload.name} (${(fileToUpload.size / 1024).toFixed(1)} KB)`
                  : "Click to upload file sample..."}
              </span>
              <input
                ref={sampleFileRef}
                type="file"
                style={{ display: "none" }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) setFileToUpload(f);
                }}
              />
            </div>
          ) : (
            <input
              type="text"
              placeholder={`Enter ${OBSERVABLE_TYPES.find((t) => t.id === observableType)?.label.toLowerCase()} — e.g. ${placeholder}`}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              style={inputBase}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
              onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
            />
          )}
        </div>

        <button
          onClick={handleSubmit}
          disabled={!canSubmit}
          style={{
            padding: "12px 28px",
            background: canSubmit
              ? "linear-gradient(135deg, #60a5fa, #818cf8)"
              : "var(--bg-elevated)",
            border: "none",
            borderRadius: "var(--radius)",
            color: canSubmit ? "#fff" : "var(--text-muted)",
            fontSize: 13,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            cursor: canSubmit ? "pointer" : "not-allowed",
            transition: "all 0.2s",
            boxShadow: canSubmit ? "0 2px 8px rgba(96, 165, 250, 0.3)" : "none",
            whiteSpace: "nowrap",
          }}
        >
          {uploadingRef ? "Uploading..." : loading ? "Investigating..." : "Investigate"}
        </button>
      </div>

      {/* ── URL input (domain + url types only) ── */}
      {observableType === "domain" && (
        <div style={{ marginTop: 10 }}>
          <input
            type="text"
            placeholder="Specific page URL (optional) — e.g. https://suspicious-site.com/login"
            value={investigatedUrl}
            onChange={(e) => setInvestigatedUrl(e.target.value)}
            style={{
              ...inputBase,
              fontSize: 12,
              padding: "10px 16px",
              borderStyle: investigatedUrl.trim() ? "solid" : "dashed",
              borderColor: investigatedUrl.trim() ? "var(--accent)" : "var(--border)",
            }}
            onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
            onBlur={(e) =>
              (e.target.style.borderColor = investigatedUrl.trim()
                ? "var(--accent)"
                : "var(--border)")
            }
          />
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
            If provided, this URL will be screenshotted for visual comparison instead of the domain homepage
          </div>
        </div>
      )}

      {observableType === "file" && (
        <div style={{
          marginTop: 10,
          padding: "10px 12px",
          borderRadius: "var(--radius)",
          border: "1px solid var(--border)",
          background: "var(--bg-elevated)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
        }}>
          <div style={{ minWidth: 0 }}>
            <div style={{
              fontSize: 12,
              fontWeight: 600,
              color: "var(--text)",
              fontFamily: "var(--font-sans)",
            }}>
              Deep scan mode
            </div>
            <div style={{
              fontSize: 10,
              color: "var(--text-muted)",
              marginTop: 2,
              fontFamily: "var(--font-sans)",
            }}>
              Off gives the fastest hash-based response. On uses file mode for richer evidence.
            </div>
          </div>
          <label style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            cursor: "pointer",
            flexShrink: 0,
          }}>
            <input
              type="checkbox"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
              style={{ accentColor: "var(--accent)" }}
            />
            <span style={{
              fontSize: 11,
              color: deepScan ? "var(--accent)" : "var(--text-dim)",
              fontWeight: 600,
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.03em",
            }}>
              {deepScan ? "DEEP" : "FAST"}
            </span>
          </label>
        </div>
      )}

      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        {/* Client domain comparison only for domain type */}
        {observableType === "domain" && (
          <button onClick={() => setShowClientDomain(!showClientDomain)} style={toggleStyle}>
            {showClientDomain
              ? "▾ Hide client domain comparison"
              : "▸ Compare with client domain (typosquatting)"}
          </button>
        )}

        <button onClick={() => setShowAnalyzers(!showAnalyzers)} style={toggleStyle}>
          {showAnalyzers
            ? `▾ Analyzers${selectedCollectors.length > 0 ? ` (${selectedCollectors.length} selected)` : " (all)"}`
            : `▸ Select analyzers${selectedCollectors.length > 0 ? ` (${selectedCollectors.length} selected)` : ""}`}
        </button>

        <button onClick={() => setShowContext(!showContext)} style={toggleStyle}>
          {showContext ? "▾ Hide context" : "▸ Add context (ticket, SOC notes, CTI)"}
        </button>
      </div>

      {/* ── Analyzer picker ── */}
      {showAnalyzers && (
        <div style={{
          marginTop: 12,
          padding: "14px 16px",
          background: "var(--bg-elevated)",
          borderRadius: "var(--radius)",
          border: "1px solid var(--border)",
        }}>
          <div style={{
            fontSize: 11,
            color: "var(--text-dim)",
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            marginBottom: 10,
            letterSpacing: "0.04em",
            textTransform: "uppercase" as const,
          }}>
            Analyzers — uncheck to skip specific collectors
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
            {COLLECTOR_DESCRIPTORS.map((c) => {
              const applicable = supportedCollectors.includes(c.id);
              const checked = selectedCollectors.includes(c.id);
              return (
                <label
                  key={c.id}
                  title={!applicable ? `Not applicable for ${observableType}` : undefined}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 8,
                    padding: "8px 10px",
                    background: !applicable
                      ? "var(--bg-input)"
                      : checked
                        ? "rgba(96,165,250,0.08)"
                        : "var(--bg-input)",
                    border: `1px solid ${checked && applicable ? "var(--accent)" : "var(--border)"}`,
                    borderRadius: "var(--radius-sm)",
                    cursor: applicable ? "pointer" : "not-allowed",
                    opacity: applicable ? 1 : 0.4,
                    transition: "all 0.15s",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={!applicable}
                    onChange={() => {
                      if (!applicable) return;
                      setSelectedCollectors((prev) =>
                        prev.includes(c.id) ? prev.filter((x) => x !== c.id) : [...prev, c.id],
                      );
                    }}
                    style={{ marginTop: 2, accentColor: "var(--accent)", cursor: applicable ? "pointer" : "not-allowed" }}
                  />
                  <div>
                    <div style={{
                      fontSize: 12,
                      fontWeight: 600,
                      color: !applicable ? "var(--text-muted)" : checked ? "var(--accent)" : "var(--text)",
                      fontFamily: "var(--font-mono)",
                    }}>
                      {c.label}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>
                      {applicable ? c.desc : `N/A for ${observableType}`}
                    </div>
                  </div>
                </label>
              );
            })}
          </div>
          {selectedCollectors.length > 0 && (
            <button
              onClick={() => setSelectedCollectors(COLLECTORS_PER_TYPE[observableType])}
              style={{ ...toggleStyle, marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}
            >
              Reset to all applicable
            </button>
          )}
        </div>
      )}

      {/* ── Client domain comparison ── */}
      {showClientDomain && observableType === "domain" && (
        <div style={{ marginTop: 12 }}>
          <div style={{
            fontSize: 12,
            color: "var(--text-dim)",
            letterSpacing: "0.01em",
            marginBottom: 6,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
          }}>
            Client Domain
          </div>
          <input
            type="text"
            placeholder="Enter your client's legitimate domain — e.g. company.com"
            value={clientDomain}
            onChange={(e) => setClientDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            style={{
              ...inputBase,
              borderColor: clientDomain.trim() ? "var(--accent)" : "var(--border)",
            }}
            onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
            onBlur={(e) =>
              (e.target.style.borderColor = clientDomain.trim() ? "var(--accent)" : "var(--border)")
            }
          />
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
            The investigated domain will be compared for typosquatting, homoglyphs, and visual similarity
          </div>

          <div style={{ marginTop: 10 }}>
            <input
              type="text"
              placeholder="Client page URL (optional) — e.g. https://company.com/login"
              value={clientUrl}
              onChange={(e) => setClientUrl(e.target.value)}
              style={{
                ...inputBase,
                fontSize: 12,
                padding: "10px 16px",
                borderStyle: clientUrl.trim() ? "solid" : "dashed",
                borderColor: clientUrl.trim() ? "var(--accent)" : "var(--border)",
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
              onBlur={(e) =>
                (e.target.style.borderColor = clientUrl.trim() ? "var(--accent)" : "var(--border)")
              }
            />
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
              Compare against a specific page on the client domain instead of the homepage
            </div>
          </div>

          {/* Reference image upload */}
          <div style={{
            marginTop: 12,
            padding: "12px 14px",
            background: "var(--bg-elevated)",
            borderRadius: "var(--radius)",
            border: "1px dashed var(--border)",
          }}>
            <div style={{
              fontSize: 12,
              color: "var(--text-dim)",
              letterSpacing: "0.01em",
              marginBottom: 8,
              fontWeight: 600,
              fontFamily: "var(--font-sans)",
            }}>
              Reference Screenshot (Optional)
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                style={{
                  padding: "8px 14px",
                  background: "var(--bg-input)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  color: "var(--text-secondary)",
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  cursor: "pointer",
                }}
              >
                {referenceFile ? "Change file" : "Upload screenshot"}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                style={{ display: "none" }}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) setReferenceFile(file);
                }}
              />
              {referenceFile && (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    {referenceFile.name}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setReferenceFile(null);
                      if (fileInputRef.current) fileInputRef.current.value = "";
                    }}
                    style={{
                      background: "none",
                      border: "none",
                      color: "var(--text-muted)",
                      cursor: "pointer",
                      fontSize: 14,
                      padding: "0 4px",
                    }}
                  >
                    ×
                  </button>
                </div>
              )}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6 }}>
              Upload a screenshot of the client&apos;s website to compare against. If not provided, a live screenshot will be captured automatically.
            </div>
          </div>
        </div>
      )}

      {showContext && (
        <textarea
          placeholder="Paste SOC ticket notes, OpenCTI observables, or any additional context..."
          value={context}
          onChange={(e) => setContext(e.target.value)}
          style={{
            ...inputBase,
            marginTop: 12,
            minHeight: 100,
            resize: "vertical" as const,
          }}
        />
      )}
    </div>
  );
}
