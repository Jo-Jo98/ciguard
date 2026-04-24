"""
GitLab native security report parser.

GitLab CI jobs can produce structured security reports as JSON artifacts in
the format defined by the GitLab security report schema.  This scanner
ingests those JSON files and surfaces their findings in ciguard.

Usage: pass the path to a GitLab security report JSON file (e.g.
  gl-sast-report.json, gl-dependency-scanning-report.json,
  gl-container-scanning-report.json) as the ``path`` argument.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List

from .base import ScannerBase, ScannerFinding

log = logging.getLogger(__name__)

# GitLab severity → ciguard severity
_SEV_MAP = {
    "critical":   "Critical",
    "high":        "High",
    "medium":      "Medium",
    "low":         "Low",
    "info":        "Info",
    "unknown":     "Info",
    "negligible":  "Info",
}


class GitLabNativeScanner(ScannerBase):
    """
    Parses GitLab security report JSON artifacts.

    Unlike the CLI-based scanners, this is always 'available' — it just
    requires a valid GitLab security report JSON file to be supplied.
    """

    @property
    def name(self) -> str:
        return "gitlab-native"

    def is_available(self) -> bool:
        return True  # Pure JSON parsing, no external dependency

    def scan(self, path: Path) -> List[ScannerFinding]:
        """
        ``path`` should be a GitLab security report JSON file.
        Returns [] if the file is not a valid GitLab report.
        """
        if path.is_dir():
            # Scan all GitLab report JSONs in the directory
            findings: List[ScannerFinding] = []
            for json_file in path.glob("gl-*-report.json"):
                findings.extend(self._parse_file(json_file))
            return findings
        return self._parse_file(path)

    def _parse_file(self, path: Path) -> List[ScannerFinding]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.debug("gitlab-native: cannot read %s: %s", path, exc)
            return []

        # Detect GitLab report format
        if "vulnerabilities" not in data and "findings" not in data:
            log.debug("gitlab-native: %s is not a GitLab security report", path)
            return []

        raw_vulns = data.get("vulnerabilities", data.get("findings", []))
        if not isinstance(raw_vulns, list):
            return []

        scanner_meta = data.get("scan", {}).get("scanner", {}).get("name", "GitLab")
        results: List[ScannerFinding] = []

        for vuln in raw_vulns:
            sev_raw = str(vuln.get("severity", "unknown")).lower()
            sev = _SEV_MAP.get(sev_raw, "Info")

            identifiers = vuln.get("identifiers", [])
            rule_id = (
                identifiers[0].get("value", "GL-UNKNOWN") if identifiers
                else vuln.get("id", "GL-UNKNOWN")
            )

            location = vuln.get("location", {})
            loc_str = location.get("file", str(path))
            if "start_line" in location:
                loc_str += f":{location['start_line']}"

            results.append(ScannerFinding(
                scanner=f"{self.name}/{scanner_meta}",
                rule_id=str(rule_id),
                name=vuln.get("name", "Unknown vulnerability"),
                description=vuln.get("description", ""),
                severity=sev,
                location=loc_str,
                evidence=vuln.get("message", ""),
                remediation=vuln.get("solution", ""),
                url=vuln.get("links", [{}])[0].get("url") if vuln.get("links") else None,
            ))

        log.info("gitlab-native: %d findings from %s", len(results), path)
        return results
