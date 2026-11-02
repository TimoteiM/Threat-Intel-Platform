"use client";

import { useEffect } from "react";

/**
 * Logs the build fingerprint **from the JavaScript bundle**.
 *
 * This is deliberately a client component, and the distinction is the whole
 * point. Its twin is a `<meta>` tag rendered server-side in the layout:
 *
 *   - the meta tag arrives with the HTML, which the browser does not cache
 *     the way it caches hashed JS
 *   - this line is compiled into the bundle, so a browser serving a stale
 *     bundle logs the fingerprint of the build that bundle came from
 *
 * So the two are not redundancy. **If they disagree, the HTML is fresh and
 * the bundle is cached** — which is the same instrument as comparing the API
 * and the worker, one layer up. Written as two readable copies of one fact,
 * nobody compares them; written as a pair, a mismatch has a meaning.
 *
 * The first version of this was an inline `<script>` in the layout, which
 * ships with the HTML and would therefore always have agreed with the meta
 * tag — a check incapable of returning the bad answer, which is the failure
 * this project spent 2026-10-12 learning to spot.
 */
export default function BuildStampClient() {
  useEffect(() => {
    const fromBundle =
      process.env.NEXT_PUBLIC_BUILD_FINGERPRINT || "unavailable: not set at build time";
    const fromHtml =
      document
        .querySelector('meta[name="x-build-fingerprint"]')
        ?.getAttribute("content") || "(no meta tag)";
    const agree = fromBundle === fromHtml;
    // eslint-disable-next-line no-console
    console.info(
      `build ${fromBundle.slice(0, 16)} (bundle) / ${fromHtml.slice(0, 16)} (html) — ` +
        (agree
          ? "agree. Compare with /health .code.code_fingerprint for the API."
          : "DISAGREE: the HTML is fresh and this bundle is cached. Hard-reload."),
    );
  }, []);
  return null;
}
