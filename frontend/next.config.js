/** @type {import('next').NextConfig} */

// Static export (GitHub Pages) is opt-in via NEXT_OUTPUT_EXPORT=true so that
// local dev and the Docker deployment keep their dev-server rewrites/proxy.
const isExport = process.env.NEXT_OUTPUT_EXPORT === "true";
const basePath = process.env.NEXT_BASE_PATH || "";

const exportConfig = {
  output: "export",
  basePath: basePath || undefined,
  assetPrefix: basePath || undefined,
  images: { unoptimized: true },
  trailingSlash: true,
  // Exposed to the client so it can flag the backend-less static preview.
  env: {
    NEXT_PUBLIC_BASE_PATH: basePath,
  },
};

const serverConfig = {
  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    return [
      { source: "/api/:path*", destination: `${apiUrl}/api/:path*` },
      { source: "/ws/:path*", destination: `${apiUrl}/ws/:path*` },
    ];
  },
};

module.exports = isExport ? exportConfig : serverConfig;
