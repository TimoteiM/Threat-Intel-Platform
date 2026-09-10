"use client";

/**
 * Kept as a thin alias so the six existing call sites keep working. The CSS
 * ring it used to draw is gone; there is one loading state now.
 */

import React from "react";
import BrandLoader from "@/components/shared/BrandLoader";

export default function Spinner({ size = 44, message }: { size?: number; message?: string }) {
  return <BrandLoader size={size} label={message} />;
}
