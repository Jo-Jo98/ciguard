// Canonical engine version for the landing page.
//
// Read at Astro build time from `pyproject.toml` -- the single source
// of truth for `ciguard` releases. Every PyPI / GHCR / git-tag bump
// goes through that file (per `release.sh` + the pinned `_checks.yml`
// templates test), so the landing page can never drift behind the
// shipped engine version: the next deploy after a release picks up
// the new value automatically.
//
// `?raw` is Vite's build-time inline-as-string query suffix. The
// bundler reads pyproject.toml at compile time and substitutes the
// contents as a literal string -- no fs access at runtime, no path
// resolution after bundling.
//
// If you find yourself editing this number by hand, the build is
// broken -- the regex below should match the `version = "X.Y.Z"`
// line under [project] in pyproject.toml.

import pyprojectRaw from "../../../pyproject.toml?raw";

function readVersion(): string {
  // Anchor on the `[project]` section so a stray `version = "..."`
  // somewhere else (e.g. inside a tool-config block) can't shadow it.
  const projectSection = pyprojectRaw
    .split(/^\[/m)
    .find((s: string) => s.startsWith("project]"));
  if (!projectSection) {
    throw new Error(
      "version.ts: could not find [project] section in pyproject.toml",
    );
  }
  const m = projectSection.match(/^version\s*=\s*"([^"]+)"/m);
  if (!m) {
    throw new Error(
      "version.ts: could not parse version from [project] section",
    );
  }
  return m[1];
}

export const CIGUARD_VERSION: string = readVersion();
