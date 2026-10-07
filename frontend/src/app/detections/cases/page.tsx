"use client";

/**
 * Cases — one session of activity on one device, for one account.
 *
 * Its own page under Security Threats. It was a tab on Detection quality,
 * which framed a live intrusion as a reporting view about rule performance.
 *
 * The detail page for a single case stays at /detections/cases/[caseKey], so
 * every link already written to a case keeps working.
 */

import React, { Suspense, useCallback, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import CasesList from "@/components/detections/CasesList";
import TimeWindow from "@/components/shared/TimeWindow";
import { Page, PageHeader } from "@/components/ui/Primitives";

export default function CasesPage() {
  // useSearchParams needs a Suspense boundary in the App Router.
  return (
    <Suspense fallback={null}>
      <CasesPageInner />
    </Suspense>
  );
}

function CasesPageInner() {
  // The window lives in the URL, not in component state.
  //
  // It was state, so opening a case and coming back dropped the analyst on a
  // list reset to 7 days — they re-picked the window every single time, and
  // on the wider ones that is a few seconds of waiting for a view they had
  // already chosen. In the URL it survives the round trip, the browser's own
  // Back button restores exactly what they were looking at, and the view is
  // a link somebody can send to a colleague.
  const router = useRouter();
  const params = useSearchParams();

  const hours = Number(params.get("hours")) || 168;
  const since = params.get("since") || "";
  const until = params.get("until") || "";

  const write = useCallback(
    (next: { hours?: number; since?: string; until?: string }) => {
      const query = new URLSearchParams(params.toString());
      const apply = (key: string, value: string | number | undefined) => {
        if (value === undefined) return;
        if (!value) query.delete(key);
        else query.set(key, String(value));
      };
      apply("hours", next.hours);
      apply("since", next.since);
      apply("until", next.until);
      // `replace`, not `push`: choosing a window is changing what you are
      // looking at, not navigating somewhere new, and `push` would make Back
      // step through every window the analyst tried.
      router.replace(`?${query.toString()}`, { scroll: false });
    },
    [params, router],
  );

  return (
    <Page>
      <PageHeader
        title="Cases"
        subtitle="Alerts on one device that share evidence — an indicator, an account, or the same detection — grouped into one case."
        actions={
          <TimeWindow
            value={{ hours, since, until }}
            onChange={(next) => write(next)}
          />
        }
      />
      <CasesList hours={hours} since={since} until={until} />
    </Page>
  );
}

