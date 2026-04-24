"""
OpenSSF Scorecard integration.

If `scorecard` CLI is on PATH, runs basic project-level checks and converts
results to ScannerFindings.

The scorecard tool requires a git repo and a GITHUB_AUTH_TOKEN.  We run it
only when those are available, otherwise degrade gracefully.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from .base import ScannerBase, ScannerFinding

log = logging.getLogger(__name__)

# Map scorecard score bands to ciguard severities
def _score_to_severity(score: float) -> str:
    if score <= 2:
        return "Critical"
    if score <= 4:
        return "High"
    if score <= 6:
        return "Medium"
    return "Low"


class ScorecardScanner(ScannerBase):
    """OpenSSF Scorecard integration (graceful degradation if not installed)."""

    @property
    def name(self) -> str:
        return "scorecard"

    def is_available(self) -> bool:
        return (
            shutil.which("scorecard") is not None
            and bool(os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
        )

    def scan(self, path: Path) -> List[ScannerFinding]:
        if not self.is_available():
            log.debug("scorecard not available (missing binary or GITHUB_AUTH_TOKEN)")
            return []

        # Scorecard operates on a git repo, not an individual file
        repo_path = path if path.is_dir() else path.parent
        if not (repo_path / ".git").exists():
            log.debug("scorecard: no .git directory found at %s", repo_path)
            return []

        cmd = [
            "scorecard",
            f"--local={repo_path}",
            "--format=json",
            "--checks=CI-Tests,CII-Best-Practices,Code-Review,"
                    "Dangerous-Workflow,Pinned-Dependencies,"
                    "Security-Policy,Token-Permissions",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=300,
            )
            raw = result.stdout.decode("utf-8", errors="replace")
            if not raw.strip():
                return []
            data = json.loads(raw)
        except subprocess.TimeoutExpired:
            log.warning("scorecard timed out")
            return []
        except Exception as exc:
            log.warning("scorecard error: %s", exc)
            return []

        findings: List[ScannerFinding] = []
        for check in data.get("checks", []):
            score = check.get("score", 10)
            if score >= 7:
                continue  # Only report meaningful issues

            name  = check.get("name", "Unknown")
            reason = check.get("reason", "")
            docs_url = check.get("documentation", {}).get("url", "")

            findings.append(ScannerFinding(
                scanner=self.name,
                rule_id=f"SCORECARD-{name.upper().replace('-', '_')}",
                name=f"Scorecard: {name}",
                description=reason,
                severity=_score_to_severity(score),
                location=str(repo_path),
                evidence=f"Score: {score}/10",
                remediation=check.get("documentation", {}).get("short", ""),
                url=docs_url or None,
            ))

        log.info("scorecard: %d findings", len(findings))
        return findings
