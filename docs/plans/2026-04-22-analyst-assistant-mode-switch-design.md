# Analyst Assistant Mode Switch Design

**Goal:** Make the `Alert Analysis` and `Incident Correlation` controls larger, clearer, and easier to scan by replacing the small chip-like controls with a two-option segmented switch.

**Approach:** Keep the existing mode-switch location and behavior, but render both options inside a shared pill-shaped shell. The active option gets a filled, high-contrast visual treatment while the inactive option remains subdued but readable.

**Why this approach:** The two modes are mutually exclusive, so a segmented control communicates that relationship more clearly than two separate badge-like buttons. It also improves click target size and visual hierarchy without changing the surrounding workflow.

**Interaction details:**
- `Alert Analysis` remains the warning-toned option.
- `Incident Correlation` remains the success-toned option.
- Clicking either segment still only updates `mode`.
- No result, input, or session behavior changes.
