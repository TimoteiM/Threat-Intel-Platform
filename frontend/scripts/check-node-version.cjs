#!/usr/bin/env node

const major = Number.parseInt(process.versions.node.split(".")[0], 10);

// Next.js 14 in this project is stable on Node 18/20/22.
if (!Number.isFinite(major) || major < 18 || major > 22) {
  console.error(
    `Unsupported Node.js version ${process.versions.node}. ` +
      "Use Node 20.x LTS (recommended) or Node 18/22."
  );
  process.exit(1);
}

