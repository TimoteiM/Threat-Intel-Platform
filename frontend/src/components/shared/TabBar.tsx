"use client";

import React from "react";

interface Tab {
  id: string;
  label: string;
}

interface TabBarProps {
  tabs: readonly Tab[];
  active: string;
  onChange: (id: string) => void;
}

export default function TabBar({ tabs, active, onChange }: TabBarProps) {
  return (
    <div style={{
      display: "flex",
      gap: 0,
      borderBottom: "1px solid var(--border)",
      marginBottom: 24,
      overflowX: "auto",
    }}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          style={{
            padding: "12px 20px",
            background: "none",
            border: "none",
            borderBottom: active === tab.id ? "2px solid var(--accent)" : "2px solid transparent",
            color: active === tab.id ? "var(--text)" : "var(--text-dim)",
            fontSize: 11,
            fontWeight: 600,
            cursor: "pointer",
            fontFamily: "var(--font-mono)",
            letterSpacing: "0.06em",
            transition: "all 0.15s",
            whiteSpace: "nowrap",
          }}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
