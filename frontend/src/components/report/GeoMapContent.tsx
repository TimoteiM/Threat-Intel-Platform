"use client";

import React, { useEffect } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";

interface GeoPoint {
  lat: number;
  lon: number;
  label: string;
  type: string;
  country?: string;
  city?: string;
  ip: string;
}

interface Props {
  points: GeoPoint[];
  typeColors: Record<string, string>;
}

function FitBounds({ points }: { points: GeoPoint[] }) {
  const map = useMap();
  useEffect(() => {
    if (points.length === 0) return;
    const bounds = points.map((p) => [p.lat, p.lon] as [number, number]);
    map.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
  }, [map, points]);
  return null;
}

export default function GeoMapContent({ points, typeColors }: Props) {
  if (points.length === 0) return null;

  const center: [number, number] = [points[0].lat, points[0].lon];

  return (
    <MapContainer
      center={center}
      zoom={3}
      style={{ height: "100%", width: "100%", background: "#1a1a2e" }}
      scrollWheelZoom={true}
    >
      <TileLayer
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />
      <FitBounds points={points} />
      {points.map((point, i) => (
        <CircleMarker
          key={i}
          center={[point.lat, point.lon]}
          radius={8}
          pathOptions={{
            color: typeColors[point.type] || "#999",
            fillColor: typeColors[point.type] || "#999",
            fillOpacity: 0.7,
            weight: 2,
          }}
        >
          <Popup>
            <div style={{ fontFamily: "monospace", fontSize: 12, lineHeight: 1.6 }}>
              <strong>{point.ip}</strong><br />
              {point.city && point.country
                ? `${point.city}, ${point.country}`
                : point.country || "Unknown location"}<br />
              <span style={{ color: "#888", fontSize: 11 }}>{point.label}</span>
            </div>
          </Popup>
        </CircleMarker>
      ))}
    </MapContainer>
  );
}
