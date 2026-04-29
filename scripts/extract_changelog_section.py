#!/usr/bin/env python3
"""Extract a single version's section from CHANGELOG.md to stdout.

Used by:
  - Manual backfill of GitHub Releases (`scripts/backfill_releases.sh`)
  - The `release.yml` workflow's "Create GitHub Release" step

Usage:
  scripts/extract_changelog_section.py 0.9.4

Prints the markdown body between `## [0.9.4] — ...` and the next `## [` heading.
The version heading itself is dropped — `gh release create --title vX.Y.Z`
already supplies that. Exits 1 if the section is not found.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} X.Y.Z", file=sys.stderr)
        return 2
    version = sys.argv[1].lstrip("v")

    changelog = Path(__file__).parent.parent / "CHANGELOG.md"
    text = changelog.read_text()

    # Match `## [VERSION]` (anything after the bracket on the same line stays
    # in the heading line we skip). Capture the body up to the next `## [`.
    pattern = re.compile(
        rf"^##\s*\[{re.escape(version)}\][^\n]*\n(.*?)(?=^##\s*\[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        print(f"error: no `## [{version}]` section in {changelog}", file=sys.stderr)
        return 1

    sys.stdout.write(match.group(1).strip() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
