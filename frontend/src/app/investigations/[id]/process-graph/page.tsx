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

  if (loading) return <Spinner message="Loading process graph..." />;
  if (error) {
    return (
      <div style={{ paddingTop: 24, color: "var(--red)", fontSize: 12 }}>
        {error}
      </div>
    );
  }

  return (
    <div
      style={{
        width: "100vw",
        marginLeft: "calc(50% - 50vw)",
        padding: "8px 12px 18px 12px",
      }}
    >
      <AnyRunProcessGraphTab evidence={evidence || {}} />
    </div>
  );
}
