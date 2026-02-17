"use client";

import React, { useState } from "react";

interface Props {
  onSubmit: (data: string) => void;
}

export default function EnrichmentPanel({ onSubmit }: Props) {
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);

  return (
    <div
      style={{
        background: "var(--bg-card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "16px 20px",
        marginBottom: 24,
      }}
    >
      <button
        onClick={() => setOpen(!open)}
        style={{
          background: "none",
          border: "none",
          color: "var(--purple)",
          fontSize: 12,
          fontWeight: 500,
          cursor: "pointer",
          fontFamily: "var(--font-sans)",
          padding: 0,
        }}
      >
        {open ? "▾" : "▸"} Add External Intelligence
      </button>

      {open && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 8 }}>
            Paste OpenCTI observables, Flare findings, or SOC ticket notes
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder='{"opencti_observables": [...], "soc_ticket_notes": "..."}'
            style={{
              width: "100%",
              minHeight: 100,
              padding: 14,
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--text)",
              fontSize: 11,
              fontFamily: "var(--font-mono)",
              resize: "vertical" as const,
              outline: "none",
            }}
          />
          <button
            onClick={() => {
              onSubmit(text);
              setText("");
            }}
            disabled={!text}
            style={{
              marginTop: 10,
              padding: "8px 20px",
              background: text ? "var(--purple)" : "var(--bg-elevated)",
              border: "none",
              borderRadius: "var(--radius-sm)",
              color: "#fff",
              fontSize: 12,
              fontWeight: 600,
              cursor: text ? "pointer" : "default",
              fontFamily: "var(--font-sans)",
            }}
          >
            Correlate with Evidence
          </button>
        </div>
      )}
    </div>
  );
}
