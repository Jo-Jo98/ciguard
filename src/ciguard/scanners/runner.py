"""
ciguard scanner runner.

Discovers which external scanners are available, runs them all, and
returns a merged list of ScannerFindings with source attribution.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from .base import ScannerFinding
from .gitlab_native import GitLabNativeScanner
from .scorecard import ScorecardScanner
from .semgrep import SemgrepScanner

log = logging.getLogger(__name__)

# All available scanner implementations
_ALL_SCANNERS = [
    SemgrepScanner(),
    ScorecardScanner(),
    GitLabNativeScanner(),
]


def run_all_scanners(
    path: Path,
    gitlab_report: Optional[Path] = None,
) -> List[ScannerFinding]:
    """
    Run every available scanner against ``path``.

    Args:
        path:             File or directory to scan (the uploaded pipeline file
                          or repo root).
        gitlab_report:    Optional path to a GitLab security report JSON.
                          If provided, the GitLab native scanner is also run
                          against this specific file.

    Returns:
        Merged list of ScannerFindings from all scanners that ran.
    """
    all_findings: List[ScannerFinding] = []

    for scanner in _ALL_SCANNERS:
        # GitLab native scanner: run against explicit report if given
        if isinstance(scanner, GitLabNativeScanner):
            target = gitlab_report or path
        else:
            target = path

        if not scanner.is_available():
            log.debug("%s: not available — skipping", scanner.name)
            continue

        try:
            findings = scanner.scan(target)
            all_findings.extend(findings)
            log.info("%s: %d findings", scanner.name, len(findings))
        except Exception as exc:
            log.warning("%s: scan failed: %s", scanner.name, exc)

    return all_findings


def available_scanners() -> List[str]:
    """Return names of scanners that are currently available."""
    return [s.name for s in _ALL_SCANNERS if s.is_available()]
