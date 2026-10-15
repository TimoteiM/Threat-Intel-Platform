/**
 * One way to say "how long ago", and one way to print a timestamp.
 *
 * `0.2h` is not a duration a person reads — it is a float with a unit stuck on
 * it. Below an hour the useful unit is minutes, and above a couple of days it
 * is days; the band in between is the only place hours belong.
 *
 * There are three more hand-rolled `${h}h ago` helpers in this app
 * (`watchlist`, `clients`, the dashboard) plus one in `DevicesTab`. They are
 * not consolidated here yet — this is the shared one to grow into, and the
 * two surfaces that were asked for use it.
 */

/** A duration in hours, as a person would say it. */
export function agoFromHours(hours: number | null | undefined): string | null {
  if (hours === null || hours === undefined || Number.isNaN(hours)) return null;
  const h = Math.max(0, hours);
  if (h < 1 / 60) return "just now";
  if (h < 1) {
    const minutes = Math.round(h * 60);
    return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  }
  if (h < 48) {
    // One decimal only under 10 hours, where it carries information; "37.4
    // hours ago" is false precision.
    const shown = h < 10 ? Math.round(h * 10) / 10 : Math.round(h);
    return `${shown} hour${shown === 1 ? "" : "s"} ago`;
  }
  const days = Math.round(h / 24);
  if (days < 31) return `${days} days ago`;
  const months = Math.round(days / 30);
  return `${months} month${months === 1 ? "" : "s"} ago`;
}

/** The same duration without the trailing "ago", for "silent for X". */
export function durationFromHours(hours: number | null | undefined): string | null {
  const ago = agoFromHours(hours);
  if (ago === null) return null;
  if (ago === "just now") return "under a minute";
  return ago.replace(/ ago$/, "");
}

/**
 * An ISO timestamp as `YYYY-MM-DD HH:MM`, in one form everywhere.
 *
 * Falcon returns `2026-10-08T07:32:11.784120438Z` — nanoseconds — and the
 * platform's own rows return microseconds. Neither belongs on a panel, and
 * showing one surface's and truncating another's made the same instant look
 * like two different kinds of fact.
 */
export function shortStamp(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const text = String(iso);
  const match = text.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
  if (match) return `${match[1]} ${match[2]}`;
  // Not an ISO string we recognise. Returned as-is rather than mangled: a
  // half-parsed timestamp is worse than an ugly one.
  return text;
}

/** Date only, for a first-seen where the time of day is noise. */
export function shortDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const match = String(iso).match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : String(iso);
}

/** A duration in milliseconds, as a person would say it.
 *
 *  Added rather than reusing `durationFromHours` through a ms→hours division:
 *  a step's duration is natively milliseconds, and routing it through hours
 *  to reuse a helper is how "0.0 hours" ends up on a page. */
export function durationFromMs(ms: number | null | undefined): string | null {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return null;
  const v = Math.max(0, ms);
  if (v < 1000) return `${Math.round(v)} ms`;
  if (v < 60_000) return `${(v / 1000).toFixed(1)} s`;
  return durationFromHours(v / 3_600_000);
}
