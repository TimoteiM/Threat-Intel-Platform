"use client";

import React, { useState, useRef } from "react";
import { uploadReferenceImage } from "@/lib/api";

interface Props {
  onSubmit: (
    domain: string,
    context?: string,
    clientDomain?: string,
    investigatedUrl?: string,
    clientUrl?: string,
  ) => void;
  loading: boolean;
}

export default function InvestigationInput({ onSubmit, loading }: Props) {
  const [domain, setDomain] = useState("");
  const [context, setContext] = useState("");
  const [clientDomain, setClientDomain] = useState("");
  const [showContext, setShowContext] = useState(false);
  const [showClientDomain, setShowClientDomain] = useState(false);
  const [investigatedUrl, setInvestigatedUrl] = useState("");
  const [clientUrl, setClientUrl] = useState("");
  const [referenceFile, setReferenceFile] = useState<File | null>(null);
  const [uploadingRef, setUploadingRef] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const canSubmit = domain.trim().length > 0 && !loading;

  const handleSubmit = async () => {
    if (!canSubmit) return;

    // Upload reference image first if one is selected
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

      <div style={{ display: "flex", gap: 12 }}>
        <div style={{ flex: 1 }}>
          <input
            type="text"
            placeholder="Enter domain — e.g. suspicious-site.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            style={inputBase}
            onFocus={(e) => (e.target.style.borderColor = "var(--accent)")}
            onBlur={(e) => (e.target.style.borderColor = "var(--border)")}
          />
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
          }}
        >
          {uploadingRef ? "Uploading..." : loading ? "Investigating..." : "Investigate"}
        </button>
      </div>

      {/* Optional: specific URL for investigated domain screenshot */}
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

      <div style={{ display: "flex", gap: 16 }}>
        <button onClick={() => setShowClientDomain(!showClientDomain)} style={toggleStyle}>
          {showClientDomain
            ? "▾ Hide client domain comparison"
            : "▸ Compare with client domain (typosquatting)"}
        </button>

        <button onClick={() => setShowContext(!showContext)} style={toggleStyle}>
          {showContext ? "▾ Hide context" : "▸ Add context (ticket, SOC notes, CTI)"}
        </button>
      </div>

      {showClientDomain && (
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
              (e.target.style.borderColor = clientDomain.trim()
                ? "var(--accent)"
                : "var(--border)")
            }
          />
          <div style={{
            fontSize: 10,
            color: "var(--text-muted)",
            marginTop: 4,
          }}>
            The investigated domain will be compared for typosquatting, homoglyphs, and visual similarity
          </div>

          {/* Client URL for specific page comparison */}
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
                (e.target.style.borderColor = clientUrl.trim()
                  ? "var(--accent)"
                  : "var(--border)")
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
                    x
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
