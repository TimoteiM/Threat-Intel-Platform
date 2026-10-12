/**
 * The caption stamped into an exported PNG.
 *
 * A PNG leaves the product. It carries ATT&CK technique names, and some of
 * those names belong to ids ATT&CK has since retired — so a reader a month
 * from now needs to know which release the names came from, and the file
 * cannot tell them unless it says so. Without it the version becomes
 * something inferred from the file's timestamp, which is a guess about what
 * the catalogue said rather than a record of it.
 *
 * `cy.png()` renders the Cytoscape canvas alone: the legend that states the
 * version lives in the surrounding DOM and does not travel with the image. So
 * it is drawn into the bitmap here.
 */

export interface StampFacts {
  caseNumber?: number | string | null;
  attackVersion?: string | null;
  /** Technique nodes drawn whose id this ATT&CK release has retired. */
  retiredDrawn?: number | null;
  /** Technique nodes drawn whose id is not in the catalogue at all. */
  unnameableDrawn?: number | null;
  /** ISO timestamp. Passed in rather than read here, so this stays pure. */
  exportedAt?: string | null;
}

/**
 * The caption lines, in order.
 *
 * States the two counts only when they are non-zero — but states them as
 * counts rather than as a flag, because "2 ids this platform could not name"
 * is a finding about the data and a reader of the picture should see it
 * without having to open the JSON.
 */
export function stampLines(facts: StampFacts): string[] {
  const lines: string[] = [];
  const head = facts.caseNumber != null ? `Case #${facts.caseNumber}` : "Case graph";
  lines.push(
    facts.attackVersion
      ? `${head} · technique names from MITRE ATT&CK Enterprise ${facts.attackVersion}`
      : // Not "unknown version": the absence of a stated version is itself
        // the thing worth saying, because a name with no release behind it
        // cannot be checked against anything.
        `${head} · ATT&CK release not stated by this graph`,
  );

  const notes: string[] = [];
  if (facts.retiredDrawn) {
    notes.push(
      `${facts.retiredDrawn} id${facts.retiredDrawn === 1 ? "" : "s"} retired in ` +
        `this release, shown with the current equivalent`,
    );
  }
  if (facts.unnameableDrawn) {
    notes.push(
      `${facts.unnameableDrawn} id${facts.unnameableDrawn === 1 ? "" : "s"} not in ` +
        `the catalogue, shown unnamed`,
    );
  }
  if (notes.length) lines.push(notes.join(" · "));
  if (facts.exportedAt) lines.push(`exported ${facts.exportedAt}`);
  return lines;
}

/**
 * Draw `dataUrl` onto a new canvas with the caption beneath it.
 *
 * Returns the original image unchanged if a 2D context is unavailable — an
 * export without its caption is worse than one with, but an export that
 * throws is worse than both.
 */
export async function stampPng(
  dataUrl: string,
  facts: StampFacts,
  scale = 2,
): Promise<string> {
  const lines = stampLines(facts);
  if (!lines.length) return dataUrl;

  const image = await loadImage(dataUrl).catch(() => null);
  if (!image) return dataUrl;

  const pad = 10 * scale;
  const lineHeight = 15 * scale;
  const band = pad * 2 + lineHeight * lines.length;
  const canvas = document.createElement("canvas");
  canvas.width = image.width;
  canvas.height = image.height + band;
  const context = canvas.getContext("2d");
  if (!context) return dataUrl;

  context.fillStyle = "#101113";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.drawImage(image, 0, 0);
  context.fillStyle = "#9aa4b2";
  context.font = `${11 * scale}px sans-serif`;
  context.textBaseline = "top";
  lines.forEach((line, i) => {
    context.fillText(line, pad, image.height + pad + i * lineHeight);
  });
  return canvas.toDataURL("image/png");
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("could not read the rendered graph"));
    image.src = src;
  });
}
