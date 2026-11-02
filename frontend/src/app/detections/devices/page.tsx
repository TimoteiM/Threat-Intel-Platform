"use client";

/**
 * Devices — the estate, one machine at a time.
 *
 * A real page, because the sidebar links to one. It was reachable only as a tab
 * on Detection quality, so /detections/devices — the address in the nav — was a
 * 404.
 */

import React, { useState } from "react";
import DevicesTab from "@/components/detections/DevicesTab";
import { Button, Page, PageHeader } from "@/components/ui/Primitives";

const WINDOWS = [7, 30, 90] as const;

export default function DevicesPage() {
  const [days, setDays] = useState<number>(30);

  return (
    <Page>
      <PageHeader
        title="Devices"
        subtitle="Every machine that has produced an alert, worst verdict first. Open one for its full history."
        actions={
          <div className="ds-toolbar" role="group" aria-label="Time window">
            {WINDOWS.map((value) => (
              <Button
                key={value}
                variant={days === value ? "primary" : "secondary"}
                aria-pressed={days === value}
                onClick={() => setDays(value)}
              >
                {value}d
              </Button>
            ))}
          </div>
        }
      />
      <DevicesTab days={days} />
    </Page>
  );
}
