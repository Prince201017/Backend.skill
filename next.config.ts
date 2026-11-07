import fs from 'node:fs';
import path from 'node:path';
import type {NextConfig} from 'next';
import {PHASE_DEVELOPMENT_SERVER} from 'next/constants';

const nextConfig = (phase: string): NextConfig => ({
  distDir: phase === PHASE_DEVELOPMENT_SERVER ? '.next-dev' : '.next',
  reactStrictMode: true,
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: false,
  },
  // Allow access to remote image placeholder.
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'picsum.photos',
        port: '',
        pathname: '/**', // This allows any path under the hostname
      },
    ],
  },
  output: 'standalone',
  transpilePackages: ['motion'],
  webpack: (config, {dev}) => {
    if (dev) {
      try {
        const devDistDir = path.join(process.cwd(), '.next-dev');
        fs.mkdirSync(devDistDir, {recursive: true});
        const routesManifestPath = path.join(devDistDir, 'routes-manifest.json');
        if (!fs.existsSync(routesManifestPath)) {
          fs.writeFileSync(
            routesManifestPath,
            JSON.stringify({
              version: 3,
              caseSensitive: false,
              basePath: '',
              rewrites: {beforeFiles: [], afterFiles: [], fallback: []},
              redirects: [
                {
                  source: '/:path+/',
                  destination: '/:path+',
                  permanent: true,
                  internal: true,
                  regex: '^(?:\\/((?:[^\\/]+?)(?:\\/(?:[^\\/]+?))*))\\/$',
                },
              ],
              headers: [],
            })
          );
        }
      } catch {
        // Ignore pre-seed errors if filesystem is read-only
      }
    }
    // HMR is disabled in AI Studio via DISABLE_HMR env var.
    // Do not modify—file watching is disabled to prevent flickering during agent edits.
    if (dev && process.env.DISABLE_HMR === 'true') {
      config.watchOptions = {
        ignored: /.*/,
      };
    }
    return config;
  },
});

export default nextConfig;
