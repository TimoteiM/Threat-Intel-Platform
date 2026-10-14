/**
 * The seam: `request()` builds `${BASE}${path}` with BASE = "/api", so a path
 * that also begins with "/api" produces "/api/api/..." — served by nothing.
 *
 * This went live on the integrations page. The backend route was verified by
 * calling it with the correct path (401, so it existed) and the page was
 * verified by reading the served shell (200). Neither check touched the URL
 * the client actually builds, which is the one thing that was broken. Fourth
 * instance of the same shape this week: both halves right, the join wrong.
 *
 * So this tests the join, by reading the source rather than any one call.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const SRC = readFileSync(join(__dirname, "api.ts"), "utf8");

/** Every match, as the snippet around it, so a failure names the call site. */
function findAll(re: RegExp): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  while ((m = rx.exec(SRC)) !== null) {
    out.push(SRC.slice(m.index, m.index + 70).split("\n")[0]);
    if (m.index === rx.lastIndex) rx.lastIndex++;
  }
  return out;
}

describe("API client paths", () => {
  it("declares BASE as /api", () => {
    // If this changes, the rule below changes with it.
    expect(SRC).toMatch(/const BASE = "\/api";/);
  });

  it("never passes a path that already starts with /api to request()", () => {
    // Matches request<...>("/api/...") and request<...>(`/api/...`), which is
    // exactly how the integrations client was written.
    expect(findAll(/request<[^>]*>\(\s*[`"']\/api\//g)).toEqual([]);
  });

  it("builds no template path that starts with /api/", () => {
    // A path assembled into a const and passed in later would slip the check
    // above, so catch the literal prefix anywhere it is used as a request path.
    expect(findAll(/^\s*[`"']\/api\/(?!auth\/oidc)/gm)).toEqual([]);
  });

  it("keeps the absolute cross-origin upload URL, which is not a request() path", () => {
    // The direct-to-backend upload fallback legitimately carries /api because
    // it does not go through request(). Asserted so a future tightening of the
    // rules above does not break it silently.
    expect(SRC).toMatch(/directBackendBase\}\/api\/email-investigations\/upload/);
  });
});
