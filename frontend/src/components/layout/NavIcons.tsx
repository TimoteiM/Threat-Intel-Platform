"use client";

/**
 * The sidebar's icon set.
 *
 * Hand-drawn on a 24px grid rather than pulled from an icon package: the app
 * needs thirteen glyphs, and a dependency for thirteen glyphs is a dependency
 * that also has to be themed, tree-shaken and kept in step with React. Every
 * path inherits `stroke: currentColor` from `.app-sidebar__icon`, so the
 * active, hover and rest states need no icon-specific colour rules.
 */

import React from "react";
import type { NavIcon } from "@/lib/constants";

const PATHS: Record<NavIcon, React.ReactNode> = {
  grid: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  cases: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3.2 1.9" />
    </>
  ),
  bulk: (
    <>
      <rect x="3" y="4" width="18" height="13" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </>
  ),
  watch: (
    <>
      <path d="M12 3.5 14.4 9l5.6.5-4.2 3.8 1.2 5.6L12 16l-5 2.9 1.2-5.6L4 9.5 9.6 9Z" />
    </>
  ),
  detections: (
    <>
      <path d="M12 3.2 20 7v5.6c0 4.3-3.3 7.6-8 8.2-4.7-.6-8-3.9-8-8.2V7Z" />
    </>
  ),
  alerts: (
    <>
      <path d="M18 9a6 6 0 1 0-12 0c0 5-2 6.5-2 6.5h16S18 14 18 9Z" />
      <path d="M10.4 19a2 2 0 0 0 3.2 0" />
    </>
  ),
  exclusions: (
    <>
      <path d="M4 4h16l-6.4 7.6V20L10.4 18v-6.4Z" />
    </>
  ),
  email: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3.6 6.6 8.4 6 8.4-6" />
    </>
  ),
  alertBody: (
    <>
      <path d="M6 3h8l4.5 4.5V21H6Z" />
      <path d="M14 3v5h4.5" />
      <path d="M9 13.5h6M9 17h4" />
    </>
  ),
  ip: (
    <>
      <circle cx="10.6" cy="10.6" r="6.6" />
      <path d="m15.4 15.4 4.6 4.6" />
    </>
  ),
  assistant: (
    <>
      <path d="m12 3 1.9 4.9L19 9.8l-4.2 3.3.6 5.3L12 15.8 8.6 18.4l.6-5.3L5 9.8l5.1-1.9Z" />
    </>
  ),
  clients: (
    <>
      <circle cx="9" cy="8.5" r="3.4" />
      <path d="M3.4 20a5.9 5.9 0 0 1 11.2 0" />
      <path d="M16.2 5.6a3.4 3.4 0 0 1 0 5.8M17.6 20a5.9 5.9 0 0 0-1.4-3.8" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 14.4a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-3-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.2-3l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 2.9-1.2V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 3 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.6 1.2Z" />
    </>
  ),
};

export default function NavIcon({ name }: { name: NavIcon }) {
  return (
    <svg className="app-sidebar__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {PATHS[name]}
    </svg>
  );
}
