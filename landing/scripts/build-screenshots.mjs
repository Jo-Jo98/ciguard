// Snapshot the demo HTML artifacts at a fixed viewport for the
// landing page screenshot strip. Run AFTER `build_demos.py` has
// emitted the HTML into `landing/public/demos/`.
//
// Outputs PNGs into `landing/public/screenshots/`. PNGs are gitignored;
// the build chain regenerates them in CI before the Astro build.
//
// Run: `node landing/scripts/build-screenshots.mjs`

import { chromium } from "playwright";
import { mkdir, stat } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const LANDING_ROOT = resolve(HERE, "..");
const DEMOS_DIR = join(LANDING_ROOT, "public", "demos");
const OUT_DIR = join(LANDING_ROOT, "public", "screenshots");

// 4 deliverable thumbnails for the landing-page strip. We screenshot at
// 1280×800 then let the strip CSS scale the image down — gives crisp
// 2× rendering on retina displays without bloating the PNG with extra
// resolution we'll never use.
const SHOTS = [
  {
    name: "per-pipeline.png",
    source: "per-pipeline-bad.html",
    label: "Per-pipeline visualiser",
  },
  {
    name: "topology.png",
    source: "topology.html",
    label: "Multi-environment topology",
  },
  {
    name: "inventory.png",
    source: "inventory.html",
    label: "Infrastructure inventory",
  },
  {
    name: "org-dashboard.png",
    source: "org-dashboard.html",
    label: "Org-level audit dashboard",
  },
];

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  // Verify all source files exist before launching Chromium — clearer
  // error than letting goto() fail with a generic file-load message.
  for (const shot of SHOTS) {
    const src = join(DEMOS_DIR, shot.source);
    try {
      await stat(src);
    } catch {
      console.error(
        `error: missing source HTML: ${src}\n` +
        `Run \`python landing/scripts/build_demos.py\` first.`,
      );
      process.exit(1);
    }
  }

  const browser = await chromium.launch();
  try {
    for (const shot of SHOTS) {
      const src = join(DEMOS_DIR, shot.source);
      const out = join(OUT_DIR, shot.name);
      const ctx = await browser.newContext({
        viewport: { width: 1280, height: 800 },
        deviceScaleFactor: 2,
        colorScheme: "dark",
      });
      const page = await ctx.newPage();
      await page.goto(pathToFileURL(src).toString(), { waitUntil: "load" });
      // Give D3 a moment to paint the SVG layers — the per-pipeline
      // map renders nodes after a layout pass that fires post-load.
      await page.waitForTimeout(500);
      await page.screenshot({
        path: out,
        fullPage: false,
        animations: "disabled",
      });
      await ctx.close();
      console.log(`  ✓ ${out}  (${shot.label})`);
    }
  } finally {
    await browser.close();
  }

  console.log(`\nScreenshots written to ${OUT_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
