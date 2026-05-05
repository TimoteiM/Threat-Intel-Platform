"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Spinner from "@/components/shared/Spinner";
import AnyRunProcessGraphTab from "@/components/report/AnyRunProcessGraphTab";
import * as api from "@/lib/api";

export default function InvestigationProcessGraphPage() {
  const params = useParams();
  const investigationId = params?.id as string;
  const [evidence, setEvidence] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [graphHeight, setGraphHeight] = useState(760);

  useEffect(() => {
    let mounted = true;
    async function run() {
      setLoading(true);
      setError(null);
      try {
        const ev = await api.getEvidence(investigationId);
        if (!mounted) return;
        setEvidence(ev);
      } catch (e: any) {
        if (!mounted) return;
        setError(e?.message || "Failed to load graph evidence");
      } finally {
        if (mounted) setLoading(false);
      }
    }
    if (investigationId) run();
    return () => {
      mounted = false;
    };
  }, [investigationId]);

  useEffect(() => {
    function updateHeight() {
      setGraphHeight(Math.max(420, window.innerHeight - 16));
    }
    updateHeight();
    window.addEventListener("resize", updateHeight);
    return () => window.removeEventListener("resize", updateHeight);
  }, []);

  useEffect(() => {
    document.body.classList.add("process-graph-fullscreen");
    return () => document.body.classList.remove("process-graph-fullscreen");
  }, []);

  if (loading) {
    return (
      <div style={fullscreenShell}>
        <Spinner message="Loading process graph..." />
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ ...fullscreenShell, padding: 24, color: "var(--red)", fontSize: 12 }}>
        {error}
      </div>
    );
  }

  return (
    <div style={fullscreenShell}>
      <AnyRunProcessGraphTab evidence={evidence || {}} graphOnly graphHeight={graphHeight} />
    </div>
  );
}

const fullscreenShell: React.CSSProperties = {
  position: "fixed",
  inset: 0,
  zIndex: 2147483000,
  width: "100vw",
  minHeight: "100vh",
  padding: 8,
  boxSizing: "border-box",
  background: "#061724",
  overflow: "hidden",
};
