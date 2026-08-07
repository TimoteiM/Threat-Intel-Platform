"use client";

import React from "react";
import { AnyRunGraph } from "@/components/report/AnyRunInteractiveEvidence";
import AnyRunSandboxIntelligence from "@/components/report/AnyRunSandboxIntelligence";
import { useSearchParams } from "next/navigation";

type Props = {
  evidence: any;
  graphOnly?: boolean;
  graphHeight?: number;
};

function arr(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

export default function AnyRunProcessGraphTab({ evidence, graphOnly = false, graphHeight = 760 }: Props) {
  const searchParams = useSearchParams();
  const hybrid = evidence?.hybrid_analysis || {};
  const items = arr(hybrid?.items);
  const anyRunSensitiveFormDetection = items
    .map((item: any) => item?.raw_summary?.sensitive_form_detection)
    .find((detection: any) => detection?.detected);
  const sensitiveFormDetection =
    evidence?.js_analysis?.sensitive_form_detection?.detected
      ? evidence.js_analysis.sensitive_form_detection
      : anyRunSensitiveFormDetection;
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
      {!graphOnly && (
        <>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Dedicated process tree view (AnyRun source preferred). Use mouse wheel to zoom and drag to pan.
          </div>
          <AnyRunSandboxIntelligence hybridAnalysis={{ items: renderList }} />
          {sensitiveFormDetection?.detected && (
            <div style={{
              margin: "10px 0",
              padding: "10px 12px",
              border: "1px solid rgba(245, 158, 11, 0.35)",
              borderLeft: "3px solid var(--yellow)",
              borderRadius: 6,
              background: "rgba(245, 158, 11, 0.08)",
              color: "var(--text-secondary)",
              fontSize: 12,
            }}>
              Browser-visible data-entry form detected; the form was not submitted, so a clean sandbox
              verdict has incomplete interaction coverage.
            </div>
          )}
        </>
      )}
      {renderList.map((item: any, idx: number) => {
        const raw = item?.raw_summary || {};
        const source = String(raw?.source || "hybrid").toUpperCase();
        const mode = String(raw?.mode || "lookup").toUpperCase();
        return (
          <div key={`pg-${idx}`} style={{ marginBottom: graphOnly ? 0 : 20 }}>
            {!graphOnly && (
              <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 8 }}>
                Graph #{idx + 1} - {source} - {mode}
              </div>
            )}
            <AnyRunGraph raw={raw} height={graphHeight} analysisContext={{ item, items }} />
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
