/**
 * useSSE — connects to the SSE endpoint for live investigation progress.
 */

import { useEffect, useRef, useCallback, useState } from "react";
import { ProgressEvent, CollectorStatus } from "@/lib/types";

interface SSEState {
  connected: boolean;
  collectors: Record<string, CollectorStatus>;
  message: string;
  percent: number;
  done: boolean;
}

export function useSSE(investigationId: string | null) {
  const [state, setState] = useState<SSEState>({
    connected: false,
    collectors: {},
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
          message: data.message || s.message,
          percent: data.percent_complete ?? s.percent,
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
