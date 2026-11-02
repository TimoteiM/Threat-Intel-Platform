/// <reference types="vitest" />
import path from "node:path";
import { defineConfig } from "vitest/config";

/**
 * The graph is the largest surface in this product and had no repository
 * tests at all. The band-containment rules shipped proven by a scratch
 * Chromium harness, which proves nothing to the next person who opens the
 * file — so the dependency arrives carrying its justification, and those
 * rules are its first tests.
 *
 * jsdom rather than a real browser: these tests assert the *decisions* the
 * component makes — which band a node belongs in, whether a band is drawn at
 * all, what the viewport controls do to zoom — not how Cytoscape paints them.
 * Layout and paint still need a real case and a real browser, which is the
 * monitor rule applied to the renderer.
 */
export default defineConfig({
  // Next compiles JSX itself and the repo tsconfig leaves `jsx: preserve`, so
  // esbuild has to be told here or every component test fails with
  // "React is not defined" — a test-environment false failure, which is the
  // same class as the headless Esc artefact.
  esbuild: { jsx: "automatic" },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    setupFiles: ["./vitest.setup.ts"],
  },
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
});
