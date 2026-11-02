"use client";

/**
 * The Threat Analyzer mark.
 *
 * Two colourways of the same artwork, swapped by theme rather than tinted:
 * the navy half of the mark is invisible on the app's near-black ground, so
 * the dark-surface file carries it in --shell-text instead. The blue and the
 * knocked-out star are identical in both.
 *
 * Rendered at a fixed height with automatic width — the mark is 1.58:1, and
 * forcing it into a square box wastes a third of the height it is given.
 */

import React from "react";

export default function BrandMark({ height = 24 }: { height?: number }) {
  return (
    <span className="app-brand__mark" style={{ height }}>
      <img
        className="app-brand__markImg app-brand__markImg--dark"
        src="/logo-mark-tight.png"
        alt=""
        height={height}
        aria-hidden="true"
      />
      <img
        className="app-brand__markImg app-brand__markImg--light"
        src="/logo-mark-tight-on-light.png"
        alt=""
        height={height}
        aria-hidden="true"
      />
    </span>
  );
}
