/**
 * useInvestigation — fetches investigation data, evidence, and report.
 */

import { useState, useCallback } from "react";
import * as api from "@/lib/api";
import { CollectedEvidence, AnalystReport, InvestigationDetail } from "@/lib/types";

interface InvestigationData {
  detail: InvestigationDetail | null;
  evidence: CollectedEvidence | null;
  report: AnalystReport | null;
  loading: boolean;
  error: string | null;
}

export function useInvestigation() {
  const [data, setData] = useState<InvestigationData>({
    detail: null,
    evidence: null,
    report: null,
    loading: false,
    error: null,
  });

  const fetch = useCallback(async (investigationId: string) => {
    setData((d) => ({ ...d, loading: true, error: null }));
    try {
      const [detail, evidence, report] = await Promise.all([
        api.getInvestigation(investigationId),
        api.getEvidence(investigationId).catch(() => null),
        api.getReport(investigationId).catch(() => null),
      ]);
      setData({
        detail,
        evidence,
        report,
        loading: false,
        error: null,
      });
    } catch (e: any) {
      setData((d) => ({
        ...d,
        loading: false,
        error: e.message || "Failed to load investigation",
      }));
    }
  }, []);

  return { ...data, fetch };
}
