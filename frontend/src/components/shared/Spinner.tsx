"use client";

import React from "react";

export default function Spinner({ size = 40, message }: { size?: number; message?: string }) {
  return (
    <div style={{ textAlign: "center", padding: "80px 0" }}>
      <div
        style={{
          width: size,
          height: size,
          margin: "0 auto 20px",
          border: "3px solid var(--border)",
          borderTop: "3px solid var(--accent)",
          borderRadius: "50%",
        }}
        className="animate-spin"
      />
      {message && (
        <div style={{ fontSize: 13, color: "var(--accent)", fontFamily: "var(--font-mono)" }}>
          {message}
        </div>
      )}
    </div>
  );
}
