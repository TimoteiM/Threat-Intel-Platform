"use client";

import React, { useState } from "react";

interface Props {
  onSubmit: (domain: string, context?: string) => void;
  loading: boolean;
}

export default function InvestigationInput({ onSubmit, loading }: Props) {
  const [domain, setDomain] = useState("");
  const [context, setContext] = useState("");
  const [showContext, setShowContext] = useState(false);

  const canSubmit = domain.trim().length > 0 && !loading;

  const handleSubmit = () => {
    if (canSubmit) onSubmit(domain.trim(), context.trim() || undefined);
  };

  const inputBase: React.CSSProperties = {
    width: "100%",
    padding: "14px 16px",
    background: "var(--bg-input)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius)",
    color: "var(--text)",
    fontSize: 14,
    fontFamily: "var(--font-mono)",
    outline: "none",
    transition: "border-color 0.2s",
  };

  return (
    <div
      style={{
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        padding: 32,
        marginTop: 32,
      }}
      className="animate-in"
    >
      <div style={{
        fontSize: 11,
        color: "var(--text-dim)",
        letterSpacing: "0.08em",
        marginBottom: 16,
        fontWeight: 600,
      }}>
        NEW INVESTIGATION
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
            padding: "14px 28px",
            background: canSubmit
              ? "linear-gradient(135deg, #3b82f6, #2563eb)"
              : "var(--bg-elevated)",
            border: "none",
            borderRadius: "var(--radius)",
            color: canSubmit ? "#fff" : "var(--text-muted)",
            fontSize: 12,
            fontWeight: 700,
            fontFamily: "var(--font-mono)",
            cursor: canSubmit ? "pointer" : "not-allowed",
            letterSpacing: "0.06em",
            transition: "all 0.2s",
          }}
        >
          {loading ? "INVESTIGATING..." : "INVESTIGATE"}
        </button>
      </div>

      <button
        onClick={() => setShowContext(!showContext)}
        style={{
          background: "none",
          border: "none",
          color: "var(--text-dim)",
          fontSize: 10,
          cursor: "pointer",
          marginTop: 12,
          fontFamily: "var(--font-mono)",
          padding: 0,
          letterSpacing: "0.06em",
        }}
      >
        {showContext ? "▾ Hide context" : "▸ Add context (ticket, SOC notes, CTI)"}
      </button>

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
