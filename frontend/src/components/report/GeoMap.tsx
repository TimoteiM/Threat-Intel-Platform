"use client";

import React, { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import * as api from "@/lib/api";

const GEO_TYPE_COLORS: Record<string, string> = {
  hosting: "#60a5fa",
  mx: "#34d399",
  redirect: "#fb923c",
  subdomain: "#a78bfa",
};

const GEO_TYPE_LABELS: Record<string, string> = {
  hosting: "Hosting / A Record",
  mx: "Mail Server",
  redirect: "Redirect Hop",
  subdomain: "Subdomain",
};

interface Props {
  investigationId: string;
}

// Dynamically import the map to avoid SSR issues with Leaflet
const MapContent = dynamic(() => import("./GeoMapContent"), { ssr: false });

export default function GeoMap({ investigationId }: Props) {
  const [points, setPoints] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    api.getGeoPoints(investigationId)
      .then(setPoints)
      .catch((e) => setError(e?.message || "Failed to load geo data"))
      .finally(() => setLoading(false));
  }, [investigationId]);

  if (loading) {
    return (
      <div style={{ padding: 16, fontSize: 12, color: "var(--text-dim)" }}>
        Loading geolocation data...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        padding: 12, fontSize: 12, color: "var(--text-dim)",
        background: "var(--bg-input)", borderRadius: "var(--radius-sm)",
      }}>
        Could not load geolocation data.
      </div>
    );
  }

  if (points.length === 0) {
    return (
      <div style={{
        padding: 12, fontSize: 12, color: "var(--text-dim)",
        background: "var(--bg-input)", borderRadius: "var(--radius-sm)",
        borderLeft: "3px solid var(--text-muted)",
      }}>
        No geolocatable IPs found in evidence.
      </div>
    );
  }

  return (
    <div>
      {/* Legend */}
      <div style={{ display: "flex", gap: 12, marginBottom: 8 }}>
        {Object.entries(GEO_TYPE_LABELS).map(([type, label]) => {
          const hasType = points.some((p) => p.type === type);
          if (!hasType) return null;
          return (
            <div key={type} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{
                width: 8, height: 8, borderRadius: "50%",
                background: GEO_TYPE_COLORS[type] || "#999",
              }} />
              <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-sans)" }}>
                {label}
              </span>
            </div>
          );
        })}
      </div>

      {/* Map */}
      <div style={{
        height: 400, borderRadius: "var(--radius)",
        overflow: "hidden", border: "1px solid var(--border)",
      }}>
        <MapContent points={points} typeColors={GEO_TYPE_COLORS} />
      </div>

      {/* Point list */}
      <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 2 }}>
        {points.map((p, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "4px 8px", fontSize: 11,
            fontFamily: "var(--font-mono)",
          }}>
            <div style={{
              width: 6, height: 6, borderRadius: "50%",
              background: GEO_TYPE_COLORS[p.type] || "#999",
              flexShrink: 0,
            }} />
            <span style={{ color: "var(--text)", fontWeight: 600 }}>{p.ip}</span>
            <span style={{ color: "var(--text-dim)" }}>
              {p.city && p.country ? `${p.city}, ${p.country}` : p.country || ""}
            </span>
            <span style={{ color: "var(--text-muted)", marginLeft: "auto", fontSize: 10 }}>
              {p.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
