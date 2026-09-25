"use client";

/**
 * Cases — one session of activity on one device, for one account.
 *
 * Its own page under Security Threats. It was a tab on Detection quality,
 * which framed a live intrusion as a reporting view about rule performance;
 * an analyst opening it wants to know what is happening now, not how the
 * ruleset is doing.
 *
 * The detail page for a single case stays at /detections/cases/[caseKey], so
 * every link already written to a case keeps working.
 */

import React, { useState } from "react";
import CasesList, { CASE_WINDOWS } from "@/components/detections/CasesList";
import { Button, Page, PageHeader } from "@/components/ui/Primitives";

export default function CasesPage() {
  // 7 days. Long enough that a case which began before the shift started is
  // still on screen, short enough that the list is the current picture rather
  // than an archive.
  const [hours, setHours] = useState<number>(168);

  return (
    <Page>
      <PageHeader
        title="Cases"
        subtitle="Alerts that belong to the same activity on the same device, grouped into one case."
        actions={
          <div className="ds-toolbar" role="group" aria-label="Time window">
            {CASE_WINDOWS.map((value) => (
              <Button
                key={value}
                variant={hours === value ? "primary" : "secondary"}
                aria-pressed={hours === value}
                onClick={() => setHours(value)}
              >
                {value === 48 ? "48h" : `${value / 24}d`}
              </Button>
            ))}
          </div>
        }
      />
      <CasesList hours={hours} />
    </Page>
  );
}
