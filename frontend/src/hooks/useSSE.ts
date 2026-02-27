/**
 * useSSE — connects to the SSE endpoint for live investigation progress.
 */

import { useEffect, useRef, useCallback, useState } from "react";
import { ProgressEvent, CollectorStatus, InvestigationState } from "@/lib/types";

interface SSEState {
  connected: boolean;
  collectors: Record<string, CollectorStatus>;
  collectorDurations: Record<string, number>;
  state?: InvestigationState;
  message: string;
  percent: number;
  totalElapsedMs?: number;
  done: boolean;
}

export function useSSE(investigationId: string | null) {
  const [state, setState] = useState<SSEState>({
    connected: false,
    collectors: {},
    collectorDurations: {},
    message: "",
    percent: 0,
    done: false,
  });
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!investigationId) return;

    const es = new EventSource(`/api/investigations/${investigationId}/status`);
    esRef.current = es;

    es.onopen = () => {
      setState((s) => ({ ...s, connected: true }));
    };

    es.onmessage = (e) => {
      try {
        const data: ProgressEvent = JSON.parse(e.data);

        setState((s) => ({
          ...s,
          collectors: { ...s.collectors, ...data.collectors, ...(data.collector ? { [data.collector]: data.collectors?.[data.collector] || "completed" as CollectorStatus } : {}) },
          collectorDurations: {
            ...s.collectorDurations,
            ...(data.collector && typeof data.duration_ms === "number" ? { [data.collector]: data.duration_ms } : {}),
          },
          state: data.state || s.state,
          message: data.message || s.message,
          percent: data.percent_complete ?? s.percent,
          totalElapsedMs: data.total_elapsed_ms ?? s.totalElapsedMs,
          done: data.done || data.state === "concluded" || data.state === "failed",
        }));

        if (data.done || data.state === "concluded" || data.state === "failed") {
          es.close();
        }
      } catch {
        // Ignore keepalives
      }
    };

    es.onerror = () => {
      setState((s) => ({ ...s, connected: false }));
      es.close();
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [investigationId]);

  return state;
}
