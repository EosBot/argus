/** @type {import('next').NextConfig} */
const nextConfig = {
  agentRules: false,
  // CI/local verification can use an isolated output directory when a
  // container-created .next directory belongs to another UID.
  distDir: process.env.ARGUS_NEXT_DIST_DIR || ".next",
  // Use the in-process TypeScript API. This also keeps production builds
  // deterministic in restricted environments where child stdout is unavailable.
  experimental: { useTypeScriptCli: false },
  // `npm run build` executes strict tsc first; avoid running the same check in
  // Next's isolated worker, whose child-process pipes are unavailable in some
  // hardened/sandboxed deployments.
  typescript: { ignoreBuildErrors: true },
  // Allow dev HMR/WebSocket access from these hosts. The app is accessed via
  // 127.0.0.1 (docker port forward); without this, Next 16 blocks the HMR
  // connection and the client bootstrap aborts before React hydrates.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
};

module.exports = nextConfig;
