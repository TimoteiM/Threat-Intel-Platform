"use client";

import React from "react";
import { AnyRunGraph } from "@/components/report/AnyRunInteractiveEvidence";
import AnyRunSandboxIntelligence from "@/components/report/AnyRunSandboxIntelligence";
import { useSearchParams } from "next/navigation";

type Props = {
  evidence: any;
};

function arr(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

export default function AnyRunProcessGraphTab({ evidence }: Props) {
  const searchParams = useSearchParams();
  const hybrid = evidence?.hybrid_analysis || {};
  const items = arr(hybrid?.items);
  if (!items.length) {
    return (
      <EmptyNote>
        {hybrid?.meta?.status === "failed"
          ? `Sandbox collector failed: ${hybrid?.meta?.error || "unknown error"}`
          : "AnyRun process graph not available (collector not run)."}
      </EmptyNote>
    );
  }

  const prioritized = [...items].sort((a: any, b: any) => {
    const sa = String(a?.raw_summary?.source || "").toLowerCase() === "anyrun" ? 0 : 1;
    const sb = String(b?.raw_summary?.source || "").toLowerCase() === "anyrun" ? 0 : 1;
    return sa - sb;
  });
  const idxParam = Number(searchParams?.get("graph_index") ?? "");
  const selectedIndex = Number.isFinite(idxParam) && idxParam >= 0 ? idxParam : -1;
  const renderList = selectedIndex >= 0 && selectedIndex < prioritized.length
    ? [prioritized[selectedIndex]]
    : prioritized;

  return (
    <div>
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Dedicated process tree view (AnyRun source preferred). Use mouse wheel to zoom and drag to pan.
      </div>
      <AnyRunSandboxIntelligence hybridAnalysis={{ items: renderList }} />
      {renderList.map((item: any, idx: number) => {
        const raw = item?.raw_summary || {};
        const source = String(raw?.source || "hybrid").toUpperCase();
        const mode = String(raw?.mode || "lookup").toUpperCase();
        return (
          <div key={`pg-${idx}`} style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 8 }}>
              Graph #{idx + 1} · {source} · {mode}
            </div>
            <AnyRunGraph raw={raw} height={760} analysisContext={{ item, items }} />
          </div>
        );
      })}
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        padding: "12px 16px",
        fontSize: 12,
        color: "var(--text-dim)",
        background: "var(--bg-input)",
        borderRadius: "var(--radius-sm)",
        borderLeft: "3px solid var(--text-muted)",
        marginBottom: 8,
      }}
    >
      {children}
    </div>
  );
}
