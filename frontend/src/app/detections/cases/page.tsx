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
import { Button, Page, PageHeader } from "@/components/ui/Primitives";

// Presets, plus "All". The list used to offer 48h/7d/30d and nothing else, so
// there was no way to ask for a case from six weeks ago — or for all of them.
const PRESETS = [
  { label: "48h", hours: 48 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
  { label: "90d", hours: 2160 },
  // Two years. Retention decides what this actually reaches; the point is that
  // nothing is hidden by the control.
  { label: "All", hours: 17520 },
] as const;

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

  const setHours = (value: number) => write({ hours: value, since: "", until: "" });
  const setSince = (value: string) => write({ since: value });
  const setUntil = (value: string) => write({ until: value });

  const custom = Boolean(since || until);

  return (
    <Page>
      <PageHeader
        title="Cases"
        subtitle="Alerts on one device that share evidence — an indicator, an account, or the same detection — grouped into one case."
        actions={
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <div className="ds-toolbar" role="group" aria-label="Time window">
              {PRESETS.map((preset) => (
                <Button
                  key={preset.label}
                  variant={!custom && hours === preset.hours ? "primary" : "secondary"}
                  aria-pressed={!custom && hours === preset.hours}
                  onClick={() => {
                    // Picking a preset clears the dates, so the two controls
                    // can never both claim to be in effect.
                    setSince("");
                    setUntil("");
                    setHours(preset.hours);
                  }}
                >
                  {preset.label}
                </Button>
              ))}
            </div>
            <label style={dateLabel}>
              <span style={dateCaption}>From</span>
              <input
                type="date"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                style={dateInput}
              />
            </label>
            <label style={dateLabel}>
              <span style={dateCaption}>To</span>
              <input
                type="date"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                style={dateInput}
              />
            </label>
            {custom && (
              <Button
                variant="secondary"
                onClick={() => {
                  setSince("");
                  setUntil("");
                }}
              >
                Clear dates
              </Button>
            )}
          </div>
        }
      />
      <CasesList hours={hours} since={since} until={until} />
    </Page>
  );
}

const dateLabel: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

const dateCaption: React.CSSProperties = {
  fontSize: "var(--font-micro, 10px)",
  fontWeight: 700,
  letterSpacing: "0.06em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
};

const dateInput: React.CSSProperties = {
  borderRadius: 10,
  border: "1px solid var(--panel-divider-strong, var(--border))",
  background: "var(--panel-card-bg, transparent)",
  color: "var(--text-strong, var(--text))",
  padding: "5px 8px",
  fontSize: 13,
};
