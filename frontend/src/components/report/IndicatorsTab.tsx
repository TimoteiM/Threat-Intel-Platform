"use client";

import React from "react";
import { AnalystReport } from "@/lib/types";
import { IOC_TYPE_COLORS } from "@/lib/constants";
import Badge from "@/components/shared/Badge";

interface Props {
  report: AnalystReport;
}

export default function IndicatorsTab({ report }: Props) {
  const iocs = Array.isArray(report?.iocs) ? report.iocs : [];

  return (
    <div>
      <div style={{
        fontSize: 13, fontWeight: 600, color: "var(--accent)",
        letterSpacing: "0.01em", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-sans)",
      }}>
        Indicators of Compromise
      </div>

      {iocs.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--text-dim)", padding: 20 }}>
          No IOCs extracted.
        </div>
      ) : (
        <div>
          {iocs.map((ioc: any, i: number) => {
            const iocType = ioc?.type || "domain";
            const color = IOC_TYPE_COLORS[iocType] || "var(--text-dim)";
            return (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "10px 14px",
                  background: i % 2 === 0 ? "transparent" : "var(--bg-input)",
                  borderRadius: "var(--radius-sm)",
                }}
              >
                <Badge label={iocType} color={color} />
                <span style={{
                  fontSize: 13, fontWeight: 600, color: "var(--text)",
                  fontFamily: "var(--font-mono)",
                }}>
                  {ioc?.value || "—"}
                </span>
                <span style={{ fontSize: 11, color: "var(--text-dim)", marginLeft: "auto" }}>
                  {ioc?.context || ""}
                </span>
                <Badge label={ioc?.confidence || "low"} color="var(--text-dim)" size="sm" />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}