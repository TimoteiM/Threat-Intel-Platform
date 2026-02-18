"use client";

import React, { useState, useRef, useCallback } from "react";

interface Props {
  onUpload: (file: File, metadata: { name?: string; context?: string; client_domain?: string }) => Promise<void>;
  loading?: boolean;
}

export default function BatchUpload({ onUpload, loading }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [context, setContext] = useState("");
  const [clientDomain, setClientDomain] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f && (f.name.endsWith(".csv") || f.name.endsWith(".txt"))) {
      setFile(f);
    }
  }, []);

  const handleSubmit = async () => {
    if (!file) return;
    await onUpload(file, {
      name: name || undefined,
      context: context || undefined,
      client_domain: clientDomain || undefined,
    });
    setFile(null);
    setName("");
    setContext("");
    setClientDomain("");
  };

  return (
    <div style={{
      background: "var(--bg-card)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius-lg)",
      padding: 24,
      boxShadow: "var(--shadow-sm)",
    }}>
      <div style={{
        fontSize: 15, fontWeight: 700, color: "var(--text)",
        marginBottom: 16, fontFamily: "var(--font-sans)",
      }}>
        Bulk Domain Investigation
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        style={{
          padding: "32px 24px",
          border: `2px dashed ${dragOver ? "var(--accent)" : "var(--border)"}`,
          borderRadius: "var(--radius)",
          background: dragOver ? "var(--accent-glow)" : "var(--bg-input)",
          textAlign: "center",
          cursor: "pointer",
          transition: "all 0.15s",
          marginBottom: 16,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv,.txt"
          style={{ display: "none" }}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) setFile(f);
          }}
        />
        {file ? (
          <div>
            <div style={{
              fontSize: 13, fontWeight: 600, color: "var(--accent)",
              fontFamily: "var(--font-mono)", marginBottom: 4,
            }}>
              {file.name}
            </div>
            <div style={{
              fontSize: 11, color: "var(--text-muted)",
              fontFamily: "var(--font-sans)",
            }}>
              {(file.size / 1024).toFixed(1)} KB — Click to change
            </div>
          </div>
        ) : (
          <div>
            <div style={{
              fontSize: 13, fontWeight: 500, color: "var(--text-secondary)",
              fontFamily: "var(--font-sans)", marginBottom: 4,
            }}>
              Drop a CSV or TXT file here, or click to browse
            </div>
            <div style={{
              fontSize: 11, color: "var(--text-muted)",
              fontFamily: "var(--font-sans)",
            }}>
              CSV: expects a &quot;domain&quot; column. TXT: one domain per line.
            </div>
          </div>
        )}
      </div>

      {/* Optional fields */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <InputField
          label="Batch Name (optional)"
          value={name}
          onChange={setName}
          placeholder="e.g. Q1 Phishing Domains"
        />
        <InputField
          label="Client Domain (optional)"
          value={clientDomain}
          onChange={setClientDomain}
          placeholder="e.g. company.com"
        />
      </div>
      <InputField
        label="Context (optional)"
        value={context}
        onChange={setContext}
        placeholder="e.g. Domains from SOC ticket #1234"
      />

      {/* Submit */}
      <div style={{ marginTop: 16, display: "flex", justifyContent: "flex-end" }}>
        <button
          onClick={handleSubmit}
          disabled={!file || loading}
          style={{
            padding: "10px 24px",
            background: file && !loading ? "var(--accent)" : "var(--bg-elevated)",
            color: file && !loading ? "#fff" : "var(--text-muted)",
            border: "none",
            borderRadius: "var(--radius-sm)",
            fontSize: 13, fontWeight: 600,
            cursor: file && !loading ? "pointer" : "not-allowed",
            fontFamily: "var(--font-sans)",
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? "Uploading..." : "Start Batch Investigation"}
        </button>
      </div>
    </div>
  );
}

function InputField({
  label, value, onChange, placeholder,
}: {
  label: string; value: string; onChange: (v: string) => void; placeholder: string;
}) {
  return (
    <div>
      <div style={{
        fontSize: 11, fontWeight: 600, color: "var(--text-muted)",
        marginBottom: 6, fontFamily: "var(--font-sans)",
      }}>
        {label}
      </div>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", padding: "8px 12px",
          background: "var(--bg-input)", border: "1px solid var(--border)",
          borderRadius: "var(--radius-sm)", color: "var(--text)",
          fontSize: 12, fontFamily: "var(--font-mono)",
          outline: "none", boxSizing: "border-box",
        }}
      />
    </div>
  );
}
