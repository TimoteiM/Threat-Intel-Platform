const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/**
 * A fingerprint of the source this bundle was built from.
 *
 * The backend answers "which code is this process running" at /health and
 * through a Celery task, because on 2026-10-12 seven commits were pushed and
 * unserved while every filesystem check said "deployed". The frontend had no
 * equivalent, which left a gap: if the page shows the wrong thing, the cause
 * is payload or bundle, and without this you are back to elimination with no
 * instrument — the same position, one layer up.
 *
 * Computed at BUILD time over the bytes of `src/`, so it describes what was
 * compiled rather than what is checked out. Content, not mtimes: `touch`
 * moves an mtime without moving the code.
 */
function sourceFingerprint() {
  const root = path.join(__dirname, "src");
  const digest = crypto.createHash("sha256");
  let files = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(ts|tsx|js|jsx|css)$/.test(entry.name)) {
        digest.update(path.relative(root, full));
        digest.update("\0");
        digest.update(fs.readFileSync(full));
        files += 1;
      }
    }
  };
  try {
    walk(root);
  } catch (err) {
    // Named, not blank: an empty value renders as "unknown" and reads as
    // "fine". The backend's git absence is handled the same way.
    return { id: `unavailable: could not read src (${err.code || "error"})`, files: 0 };
  }
  return { id: digest.digest("hex"), files };
}

const BUILD = sourceFingerprint();

/** @type {import('next').NextConfig} */
const apiProxyTarget =
  process.env.API_PROXY_TARGET ||
  "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  // Readable from the served page, so "is the browser running the build I
  // made" is one glance rather than an elimination.
  generateBuildId: async () => BUILD.id.slice(0, 16),
  env: {
    NEXT_PUBLIC_BUILD_FINGERPRINT: BUILD.id,
    NEXT_PUBLIC_BUILD_FILES: String(BUILD.files),
  },
  // Cost moved into Settings. A real server redirect rather than a redirect()
  // page: statically prerendered, that returned a 307 carrying no Location
  // header at all, which browsers follow but nothing else does.
  async redirects() {
    return [
      { source: "/cost", destination: "/settings#cost", permanent: false },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiProxyTarget}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
