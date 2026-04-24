"""
Semgrep CE scanner integration.

If `semgrep` is installed and on PATH, runs it in JSON mode against the
uploaded file / directory and converts results to ScannerFindings.

Semgrep rule set: uses `auto` (community rules) or the caller may pass a
custom `--config` path via the CIGUARD_SEMGREP_CONFIG env var.
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

# Severity mapping from Semgrep → ciguard
_SEV_MAP = {
    "ERROR":   "Critical",
    "WARNING": "High",
    "INFO":    "Medium",
}


class SemgrepScanner(ScannerBase):
    """Semgrep CE integration (graceful degradation if not installed)."""

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, path: Path) -> List[ScannerFinding]:
        if not self.is_available():
            log.debug("semgrep not found — skipping")
            return []

        config = os.environ.get("CIGUARD_SEMGREP_CONFIG", "auto")
        cmd = [
            "semgrep", "--json", "--quiet",
            "--config", config,
            str(path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
            )
            raw = result.stdout.decode("utf-8", errors="replace")
            if not raw.strip():
                return []
            data = json.loads(raw)
        except subprocess.TimeoutExpired:
            log.warning("semgrep timed out scanning %s", path)
            return []
        except Exception as exc:
            log.warning("semgrep error: %s", exc)
            return []

        findings: List[ScannerFinding] = []
        for match in data.get("results", []):
            sev_raw = match.get("extra", {}).get("severity", "WARNING")
            sev = _SEV_MAP.get(sev_raw.upper(), "Medium")

            meta = match.get("extra", {}).get("metadata", {})
            rule_id = match.get("check_id", "semgrep.unknown")
            name = meta.get("description") or rule_id.split(".")[-1].replace("-", " ").title()

            findings.append(ScannerFinding(
                scanner=self.name,
                rule_id=rule_id,
                name=name,
                description=match.get("extra", {}).get("message", ""),
                severity=sev,
                location=match.get("path", str(path)),
                evidence=(
                    f"Line {match.get('start', {}).get('line', '?')}: "
                    + (match.get("extra", {}).get("lines", "").strip()[:200])
                ),
                remediation=meta.get("fix", ""),
                url=meta.get("references", [None])[0] if meta.get("references") else None,
            ))

        log.info("semgrep: %d findings in %s", len(findings), path)
        return findings
