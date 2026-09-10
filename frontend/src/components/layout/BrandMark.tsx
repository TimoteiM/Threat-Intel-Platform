"use client";

import React from "react";

export default function BrandMark() {
  return (
    <div className="app-brand__mark" aria-hidden="true">
      <svg viewBox="0 0 48 48" className="app-brand__markSvg" role="presentation">
        <defs>
          <linearGradient id="brand-core" x1="8" y1="6" x2="40" y2="42" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#cdb8ff" />
            <stop offset="0.52" stopColor="#8b7bff" />
            <stop offset="1" stopColor="#5636cf" />
          </linearGradient>
          <linearGradient id="brand-ring" x1="10" y1="8" x2="38" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="rgba(255,255,255,0.92)" />
            <stop offset="1" stopColor="rgba(224,213,255,0.6)" />
          </linearGradient>
        </defs>
        <path
          d="M24 4 38 10v12c0 9.6-5.7 17.7-14 22-8.3-4.3-14-12.4-14-22V10L24 4Z"
          fill="url(#brand-core)"
        />
        <path
          d="M24 9.8 33.5 13.9v8.5c0 6.5-3.8 12.1-9.5 15.4-5.7-3.3-9.5-8.9-9.5-15.4v-8.5L24 9.8Z"
          fill="rgba(10,9,16,0.36)"
          stroke="rgba(224,213,255,0.36)"
          strokeWidth="1"
        />
        <circle cx="24" cy="23" r="7.5" fill="none" stroke="url(#brand-ring)" strokeWidth="2.2" />
        <circle cx="24" cy="23" r="2.6" fill="#faf8ff" />
        <path d="M24 15.2v-3.1" stroke="#faf8ff" strokeWidth="1.7" strokeLinecap="round" />
        <path d="m31.2 23h3.1" stroke="#e6ddff" strokeWidth="1.7" strokeLinecap="round" />
        <path d="M24 30.8v3.1" stroke="#e6ddff" strokeWidth="1.7" strokeLinecap="round" />
        <circle cx="16.8" cy="23" r="1.4" fill="#e6ddff" opacity="0.9" />
      </svg>
    </div>
  );
}
