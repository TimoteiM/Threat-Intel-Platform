/** @type {import('next').NextConfig} */
const apiProxyTarget =
  process.env.API_PROXY_TARGET ||
  "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
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
