/**
 * Keeping the analyst's place when the canvas changes size.
 *
 * Entering fullscreen, leaving it, or opening the side panel all change the
 * frame without changing the graph. Cytoscape notices a *window* resize but
 * not its container changing size, so the canvas kept its old width and the
 * drawing jumped.
 *
 * The fix is not to re-run the layout — positions, selection and mode all live
 * on the one Cytoscape instance and re-running would move every node. What a
 * resize actually changes is which part of the model sits under the middle of
 * the screen, so the model point at the centre is pinned across it.
 */

export type Pan = { x: number; y: number };
export type Size = { width: number; height: number };

/** The model coordinate currently under the centre of the viewport. */
export function centreOf(size: Size, zoom: number, pan: Pan): Pan {
  return {
    x: (size.width / 2 - pan.x) / zoom,
    y: (size.height / 2 - pan.y) / zoom,
  };
}

/** The pan that puts `centre` back under the middle of a differently sized frame. */
export function panToCentre(size: Size, zoom: number, centre: Pan): Pan {
  return {
    x: size.width / 2 - centre.x * zoom,
    y: size.height / 2 - centre.y * zoom,
  };
}

/**
 * The pan that keeps the same model point centred when the frame resizes.
 *
 * Zoom is deliberately untouched: a bigger frame should show *more* of the
 * graph at the same scale, not the same amount of graph larger. Fitting is a
 * separate, explicit action.
 */
export function recentre(
  before: Size, after: Size, zoom: number, pan: Pan,
): Pan {
  return panToCentre(after, zoom, centreOf(before, zoom, pan));
}
