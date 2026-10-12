/**
 * Node label text, truncated on measured width rather than character count.
 *
 * The node box is 104x44 at font-size 10 with line-height 1.25, so three lines
 * of ~12.5px fit and a fourth does not. A technique node wants three: the id,
 * the ATT&CK name, and the kind caption. ATT&CK's leaf names have a median
 * length of 30 characters against a box that holds roughly 18, so the name
 * line has to be cut.
 *
 * Cut on *width*, not on length. In a proportional font "Disable or Modif…"
 * and eighteen capital W's are nothing like the same width, so slicing at a
 * character count overflows on some names and cuts others early — the same
 * class of error as measuring a bound in the wrong unit, and one that shows up
 * on a render as ragged line endings rather than as an obvious failure.
 *
 * Cytoscape can measure: `text-max-width` wraps on real width. But it wraps
 * rather than truncating, so a long name becomes a fourth line and overflows
 * the box; and `text-wrap: "ellipsis"`, which would truncate, does not honour
 * the manual newlines that separate the three lines. So the name is fitted
 * here, and `text-max-width` stays set as a backstop: if this measurement is
 * ever wrong, the label wraps inside the node instead of spilling across the
 * canvas.
 *
 * `measure` is injected so the real renderer can use the browser's own text
 * metrics for the font actually in use, and tests can prove the proportional
 * behaviour without a browser.
 */

/** Width of a string in pixels, for the font the label will be drawn in. */
export type Measure = (text: string) => number;

export const ELLIPSIS = "…";

/** The node is 104px wide; this leaves a little either side of the text. */
export const LABEL_MAX_PX = 96;

/**
 * The longest prefix of `text` that fits `maxPx`, with an ellipsis appended
 * when anything was dropped.
 *
 * Returns `text` untouched when it already fits, so the common case carries no
 * ellipsis. Returns an ellipsis alone when not even one character fits, rather
 * than something wider than the budget — a label that overflows its node is
 * worse than one that says only "there is more here".
 */
export function fitToWidth(text: string, maxPx: number, measure: Measure): string {
  const whole = String(text ?? "");
  if (!whole) return "";
  if (measure(whole) <= maxPx) return whole;

  // Binary search the prefix length. Linear would be fine at these sizes, but
  // this runs once per node and some cases draw 3,400 technique nodes.
  let low = 0;
  let high = whole.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (measure(whole.slice(0, mid) + ELLIPSIS) <= maxPx) low = mid;
    else high = mid - 1;
  }
  // Never cut mid-pair: a surrogate half renders as a replacement character.
  let cut = low;
  if (cut > 0 && cut < whole.length) {
    const code = whole.charCodeAt(cut - 1);
    if (code >= 0xd800 && code <= 0xdbff) cut -= 1;
  }
  const kept = whole.slice(0, cut).trimEnd();
  return kept ? kept + ELLIPSIS : ELLIPSIS;
}

/**
 * A measurer backed by the browser's own text metrics.
 *
 * `font` is a CSS font shorthand — "10px <family>" — and must be the font the
 * label is actually drawn in, or this measures something else accurately.
 * Returns null where a 2D context is unavailable (jsdom, a thumbnail capture,
 * a browser refusing the canvas), so the caller can fall back rather than
 * throw inside a render.
 */
export function canvasMeasurer(font: string): Measure | null {
  try {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d");
    if (!context) return null;
    context.font = font;
    // Probe it: a stubbed or crippled context can return 0 for everything,
    // which would silently report that every label fits.
    if (!(context.measureText("MMMM").width > 0)) return null;
    return (text: string) => context.measureText(text).width;
  } catch {
    return null;
  }
}

/**
 * Last resort when no real measurement is available: average advance width.
 *
 * Deliberately crude and deliberately pessimistic — 6px at font-size 10 is
 * wider than most lower-case glyphs — so a fallback label is more likely to be
 * cut short than to overflow. It is not a substitute for measuring, and the
 * `text-max-width` backstop is what keeps the result inside the node.
 */
export const APPROX_CHAR_PX = 6;

export function approximateMeasurer(charPx = APPROX_CHAR_PX): Measure {
  return (text: string) => String(text ?? "").length * charPx;
}
