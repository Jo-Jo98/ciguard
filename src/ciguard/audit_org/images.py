"""
Cross-pipeline image extraction for the org audit (Slice 17, session 2).

Walks the same tempdir that `_scan_repo_files()` materialises for the
scan, re-parses each pipeline file, and yields one `ImageRecord` per
image reference encountered.

We re-parse rather than route through `scan_repo()` because
`scan_repo()` returns a finding-shaped dict and discards the parsed
target — adding image extraction to that helper would change a public
contract used by both the CLI and MCP. The extra parse pass is
bounded (tens of ms per file) and the org audit's per-repo cost is
already dominated by the GitHub API round trip, so the cost is
invisible.

The output shape is JSON-serialisable so it can ride on
`RepoScanRecord.images` and roundtrip through pydantic.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from ..analyzer.sca.image_extractor import classify_pin_status, extract_images
from ..discovery import discover_pipeline_files
from ..parser.github_actions import GitHubActionsParser
from ..parser.gitlab_parser import GitLabCIParser
from ..parser.jenkinsfile import JenkinsfileParser


def extract_repo_images(repo_root: Path) -> List[Dict[str, Any]]:
    """Walk `repo_root`, parse every recognised pipeline file, and
    return one dict per image reference. Errors are silently skipped —
    the org audit's image-inventory rollup is best-effort by design;
    the scan path is the authoritative source for posture findings."""
    records: List[Dict[str, Any]] = []
    for df in discover_pipeline_files(repo_root):
        try:
            target = _parse(df)
        except Exception:
            # Swallow parser failures here — `scan_repo()` already
            # captured them in the per-file `error` field.
            continue
        if target is None:
            continue
        for img in extract_images(target):
            records.append({
                "raw": img.raw,
                "name": img.name,
                "tag": img.tag,
                "cycle_id": img.cycle_id,
                "digest": img.digest,
                "registry": img.registry,
                "pin_status": classify_pin_status(img.raw),
                "file": str(df.path.relative_to(repo_root)),
                "platform": df.platform,
                "location": img.location,
            })
    return records


def _parse(df):
    """Dispatch to the right parser for a `DiscoveredFile`. Mirrors
    the dispatch inside `scan_one()` but returns the parsed model
    rather than the analysis report so we can iterate images."""
    if df.platform == "github-actions":
        return GitHubActionsParser().parse_file(df.path)
    if df.platform == "jenkins":
        return JenkinsfileParser().parse_file(df.path)
    return GitLabCIParser().parse_file(df.path)
