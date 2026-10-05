"use client";

/**
 * What the submitted file actually says.
 *
 * This is the artefact itself, not a reading of it, so it is given its own
 * section and placed first among the file-related ones: for a `.js` or a
 * `.rar` it is the thing an analyst came to see, and it previously required
 * opening the file by hand and pasting it into the assistant.
 *
 * Source is shown as source — monospaced, wrapped, scrollable, with the
 * original line breaks — because reading obfuscated script in a reflowed
 * paragraph is how a payload hides in plain sight. It is collapsed by default
 * past the first file: an archive can hold twenty, and the page should not
 * open on a wall of code.
 */

import React, { useState } from "react";

type ExtractedFile = {
  path: string;
  kind?: string;
  size?: number;
  truncated?: boolean;
  depth?: number;
  text?: string;
};

type FileContent = {
  files?: ExtractedFile[];
  limitations?: string[];
  entries_seen?: number;
  bytes_read?: number;
  encrypted?: boolean;
  readable_files?: number;
};

const KIND_LABEL: Record<string, string> = {
  source: "script",
  text: "text",
  vba: "VBA macro",
  "pdf-js": "PDF JavaScript",
};

// A macro and a PDF's JavaScript are executable parts of a document that
// claims to be neither, which is worth seeing before the text is read.
const KIND_TONE: Record<string, string> = {
  vba: "var(--status-critical)",
  "pdf-js": "var(--status-critical)",
  source: "var(--status-warning)",
};

function bytes(n?: number): string {
  if (!n && n !== 0) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function FileContentSection({ content }: { content?: FileContent | null }) {
  const files = content?.files || [];
  const limitations = content?.limitations || [];

  if (!files.length && !limitations.length) {
    return (
      <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
        No readable content was extracted from the submitted file.
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "baseline" }}>
        <Fact label="Readable files" value={String(files.length)} />
        {content?.entries_seen ? (
          <Fact label="Archive entries" value={String(content.entries_seen)} />
        ) : null}
        <Fact label="Content read" value={bytes(content?.bytes_read)} />
        {content?.encrypted ? (
          <Fact label="Encrypted" value="yes — password needed" tone="var(--status-warning)" />
        ) : null}
      </div>

      {limitations.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 3 }}>
          {limitations.map((note, i) => (
            <li key={i} style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5 }}>
              {note}
            </li>
          ))}
        </ul>
      )}

      {files.map((file, index) => (
        <FileBlock key={`${file.path}:${index}`} file={file} openByDefault={index === 0} />
      ))}
    </div>
  );
}

function FileBlock({ file, openByDefault }: { file: ExtractedFile; openByDefault: boolean }) {
  const [open, setOpen] = useState(openByDefault);
  const kind = String(file.kind || "text");
  const tone = KIND_TONE[kind] || "var(--border)";
  const lines = String(file.text || "").split("\n").length;

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderLeft: `3px solid ${tone}`,
        borderRadius: 10,
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          display: "flex",
          width: "100%",
          gap: 10,
          alignItems: "baseline",
          flexWrap: "wrap",
          padding: "8px 11px",
          background: "transparent",
          border: "none",
          color: "var(--text)",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, fontWeight: 600 }}>
          {file.path}
        </span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: tone,
          }}
        >
          {KIND_LABEL[kind] || kind}
        </span>
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
          {bytes(file.size)} · {lines} line{lines === 1 ? "" : "s"}
          {file.truncated ? " · truncated" : ""}
        </span>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--accent)" }}>
          {open ? "hide" : "show"}
        </span>
      </button>

      {open && (
        <pre
          style={{
            margin: 0,
            padding: "10px 12px",
            maxHeight: 420,
            overflow: "auto",
            background: "var(--panel-card-bg, rgba(0,0,0,0.25))",
            borderTop: "1px solid var(--border)",
            fontFamily: "var(--font-mono)",
            fontSize: 11.5,
            lineHeight: 1.55,
            color: "var(--text-secondary, var(--text))",
            // Wrapped rather than cut: a one-line obfuscated dropper is the
            // normal case, and horizontal scrolling hides most of it.
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {file.text}
        </pre>
      )}
    </div>
  );
}

function Fact({ label, value, tone }: { label: string; value: string; tone?: string }) {
  if (!value) return null;
  return (
    <span style={{ display: "grid", gap: 1 }}>
      <span
        style={{
          fontSize: "var(--font-micro, 10px)",
          fontWeight: 700,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        {label}
      </span>
      <span style={{ fontSize: 12.5, color: tone || "var(--text)" }}>{value}</span>
    </span>
  );
}
