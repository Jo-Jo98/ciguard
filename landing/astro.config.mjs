// https://astro.build/config
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://ciguard.dev",
  // Static output by default — renders to /dist/ as plain HTML/CSS at build
  // time. Cloudflare Pages serves the dist/ directory directly.
  output: "static",
  build: {
    // Hash filenames so far-future Cache-Control is safe.
    assets: "_assets",
  },
  // Tighten the prefetch policy: we only have one page, so prefetching adds
  // noise without value. Re-enable when there are crosslinks.
  prefetch: false,
  // Compress HTML output. Tiny win, but consistent with our minimal-byte
  // posture on the static surface.
  compressHTML: true,
});
