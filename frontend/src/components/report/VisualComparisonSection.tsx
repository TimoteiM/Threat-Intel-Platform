"use client";

import React from "react";
import { VisualComparisonEvidence } from "@/lib/types";
import { getArtifactUrl } from "@/lib/api";

interface Props {
  visual: VisualComparisonEvidence;
}

export default function VisualComparisonSection({ visual }: Props) {
  const overall = visual.overall_visual_similarity;
  const hasScreenshots =
    visual.investigated_screenshot_artifact_id || visual.client_screenshot_artifact_id;

  // Color based on similarity level
  const scoreColor = visual.is_visual_clone
    ? "#ef4444"
    : visual.is_partial_clone
    ? "#f59e0b"
    : "#10b981";

  const scoreLabel = visual.is_visual_clone
    ? "VISUAL CLONE"
    : visual.is_partial_clone
    ? "PARTIAL MATCH"
    : "DISTINCT";

  return (
    <div>
      {/* Summary badge */}
      {overall != null && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            padding: "16px 20px",
            background: `${scoreColor}08`,
            border: `1px solid ${scoreColor}33`,
            borderRadius: "var(--radius)",
            marginBottom: 20,
          }}
        >
          {/* Score circle */}
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: "50%",
              border: `3px solid ${scoreColor}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <span
              style={{
                fontSize: 18,
                fontWeight: 800,
                color: scoreColor,
                fontFamily: "var(--font-mono)",
              }}
            >
              {Math.round(overall * 100)}
            </span>
          </div>

          <div style={{ flex: 1 }}>
            <div
              style={{
                fontSize: 10,
                fontWeight: 700,
                color: scoreColor,
                letterSpacing: "0.1em",
                marginBottom: 4,
              }}
            >
              {scoreLabel}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              {visual.summary}
            </div>
            {visual.reference_image_used && (
              <div
                style={{
                  fontSize: 10,
                  color: "var(--text-muted)",
                  marginTop: 4,
                  fontStyle: "italic",
                }}
              >
                Compared against uploaded reference image
              </div>
            )}
          </div>
        </div>
      )}

      {/* Metrics row */}
      {overall != null && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: 8,
            marginBottom: 20,
          }}
        >
          <MetricBox
            label="OVERALL"
            value={overall}
            color={scoreColor}
            highlight
          />
          <MetricBox
            label="PERCEPTUAL"
            value={visual.phash_similarity}
            color="var(--text-dim)"
          />
          <MetricBox
            label="HISTOGRAM"
            value={visual.histogram_similarity}
            color="var(--text-dim)"
          />
        </div>
      )}

      {/* Side-by-side screenshots */}
      {hasScreenshots && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 16,
            marginBottom: 16,
          }}
        >
          <ScreenshotPanel
            label={`Investigated: ${visual.investigated_domain}`}
            artifactId={visual.investigated_screenshot_artifact_id}
            error={visual.investigated_capture_error}
          />
          <ScreenshotPanel
            label={`Client: ${visual.client_domain}${
              visual.reference_image_used ? " (reference)" : ""
            }`}
            artifactId={visual.client_screenshot_artifact_id}
            error={visual.client_capture_error}
          />
        </div>
      )}

      {/* Errors (when no screenshots at all) */}
      {!hasScreenshots && (visual.investigated_capture_error || visual.client_capture_error) && (
        <div
          style={{
            padding: "12px 16px",
            fontSize: 12,
            color: "var(--text-dim)",
            background: "var(--bg-input)",
            borderRadius: "var(--radius-sm)",
            borderLeft: "3px solid var(--text-muted)",
          }}
        >
          Screenshot comparison incomplete:
          {visual.investigated_capture_error && (
            <div style={{ marginTop: 4 }}>
              Investigated domain: {visual.investigated_capture_error}
            </div>
          )}
          {visual.client_capture_error && (
            <div style={{ marginTop: 4 }}>
              Client domain: {visual.client_capture_error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MetricBox({
  label,
  value,
  color,
  highlight,
}: {
  label: string;
  value?: number | null;
  color: string;
  highlight?: boolean;
}) {
  return (
    <div
      style={{
        padding: "12px 14px",
        background: highlight ? `${color}0a` : "var(--bg-input)",
        border: `1px solid ${highlight ? `${color}33` : "var(--border)"}`,
        borderRadius: "var(--radius)",
        textAlign: "center",
      }}
    >
      <div
        style={{
          fontSize: 20,
          fontWeight: 800,
          color: highlight ? color : "var(--text-dim)",
          fontFamily: "var(--font-mono)",
        }}
      >
        {value != null ? `${Math.round(value * 100)}%` : "--"}
      </div>
      <div
        style={{
          fontSize: 9,
          fontWeight: 700,
          color: highlight ? color : "var(--text-muted)",
          letterSpacing: "0.1em",
          marginTop: 4,
        }}
      >
        {label}
      </div>
    </div>
  );
}

function ScreenshotPanel({
  label,
  artifactId,
  error,
}: {
  label: string;
  artifactId?: string;
  error?: string;
}) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          color: "var(--text-dim)",
          letterSpacing: "0.06em",
          padding: "8px 12px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-elevated)",
        }}
      >
        {label}
      </div>
      {artifactId ? (
        <img
          src={getArtifactUrl(artifactId)}
          alt={label}
          style={{
            width: "100%",
            height: "auto",
            display: "block",
          }}
          loading="lazy"
        />
      ) : error ? (
        <div
          style={{
            padding: "32px 16px",
            textAlign: "center",
            fontSize: 11,
            color: "var(--text-muted)",
            background: "var(--bg-input)",
            minHeight: 120,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          Capture failed: {error}
        </div>
      ) : (
        <div
          style={{
            padding: "32px 16px",
            textAlign: "center",
            fontSize: 11,
            color: "var(--text-muted)",
            background: "var(--bg-input)",
            minHeight: 120,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          No screenshot available
        </div>
      )}
    </div>
  );
}
