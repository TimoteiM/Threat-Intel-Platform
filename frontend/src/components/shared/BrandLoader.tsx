"use client";

/**
 * The one loading state.
 *
 * There used to be two: a CSS ring in `Spinner` and a bare line of text in
 * `LoadingState`, so the same wait looked different depending on which page
 * you were on. Both now render this.
 *
 * The motion is a radar sweep — a conic highlight rotating *behind the mark's
 * own alpha channel*, so only the logo's pixels light up and the shape never
 * moves. A rotating logo is the obvious idea and the wrong one: our waits run
 * 2-90 seconds (and ANY.RUN averages nearer 110), and something spinning that
 * long stops reading as "working" and starts reading as "stuck". A sweep
 * passing over a mark that stays put reads as scanning.
 *
 * `label` is not decoration. At these durations the words are what tell the
 * analyst the system is alive and what it is doing, so every call site keeps
 * the message it already had.
 */

import React from "react";

export default function BrandLoader({
  label,
  size = 44,
  inline = false,
}: {
  label?: string;
  size?: number;
  inline?: boolean;
}) {
  return (
    <div
      className={inline ? "brand-loader brand-loader--inline" : "brand-loader"}
      role="status"
      aria-live="polite"
    >
      <span className="brand-loader__mark" style={{ width: size, height: size }} />
      {label ? <span className="brand-loader__label">{label}</span> : null}
      <span className="sr-only">{label || "Loading"}</span>
    </div>
  );
}
