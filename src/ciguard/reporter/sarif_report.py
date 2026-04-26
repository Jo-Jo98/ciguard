"""
SARIF 2.1.0 report writer.

SARIF (Static Analysis Results Interchange Format) is the format GitHub
Code Scanning consumes — uploading a SARIF file via the
`github/codeql-action/upload-sarif` action surfaces findings in the repo's
Security tab, and gates PRs the same way CodeQL does.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd02/sarif-v2.1.0-csprd02.html

Design choices:
  - One `run` per scan; ciguard's CLI scans a single file at a time.
  - Each finding becomes a SARIF `result`; rule definitions are aggregated
    into the run's `tool.driver.rules` array (deduped by rule_id).
  - Severity mapping:
        Critical, High → SARIF level "error"
        Medium         → SARIF level "warning"
        Low, Info      → SARIF level "note"
    The original ciguard severity is preserved in
    `result.properties["security-severity"]` (a numeric float that
    GitHub Code Scanning uses for ranking) and `properties["severity"]`
    (the human-readable level, for non-GitHub consumers).
  - We don't have line numbers (the parser doesn't track them yet), so
    each result's `physicalLocation.region` is omitted; only the
    `artifactLocation.uri` (the scanned filename) is set. SARIF allows
    omitting `region` and consumers (GitHub) handle this gracefully.
  - Compliance mappings (ISO 27001 / SOC 2 / NIST CSF) ride along in
    `result.properties` so downstream auditors get the framework refs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.pipeline import Finding, Report, Severity


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
TOOL_NAME = "ciguard"
TOOL_INFO_URI = "https://github.com/Jo-Jo98/ciguard"


def _level_for(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _security_severity(severity: Severity) -> str:
    """GitHub Code Scanning ranks SARIF results using a 0.0–10.0 score in
    `properties["security-severity"]`. Map ciguard severities into the
    standard CVSSv3 bands so the GitHub Security tab orders findings the
    way reviewers expect."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH:     "7.5",
        Severity.MEDIUM:   "5.0",
        Severity.LOW:      "3.0",
        Severity.INFO:     "0.0",
    }[severity]


def _rule_definition(finding: Finding) -> Dict[str, Any]:
    """Build the SARIF rule object for a given finding's rule_id.

    Rules are aggregated across the run by deduplicating on rule_id; the
    first finding seen wins for the descriptive fields (they should be
    identical across all firings of the same rule in any case).
    """
    return {
        "id": finding.rule_id,
        "name": finding.name.replace(" ", ""),
        "shortDescription": {"text": finding.name},
        "fullDescription":  {"text": finding.description},
        "defaultConfiguration": {"level": _level_for(finding.severity)},
        "helpUri": TOOL_INFO_URI,
        "help": {
            "text": finding.remediation,
            "markdown": f"**Remediation:**\n\n{finding.remediation}",
        },
        "properties": {
            "tags": _tags_for(finding),
            "security-severity": _security_severity(finding.severity),
        },
    }


def _tags_for(finding: Finding) -> List[str]:
    tags = ["security", finding.category.value.lower().replace(" & ", "-").replace(" ", "-")]
    # Compliance framework refs as tags so they're searchable in GH Code Scanning.
    if finding.compliance:
        for code in finding.compliance.iso_27001 or []:
            tags.append(f"iso-27001/{code}")
        for code in finding.compliance.soc2 or []:
            tags.append(f"soc2/{code}")
        for code in finding.compliance.nist or []:
            tags.append(f"nist/{code}")
    return tags


def _result(
    finding: Finding,
    artifact_uri: str,
    baseline_state: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert a Finding to a SARIF `result`.

    `baseline_state` is set when the report has a delta. SARIF 2.1.0
    defines `baselineState` as one of `"new"`, `"unchanged"`, `"updated"`,
    `"absent"`. ciguard maps:
      - `new` for findings absent from the baseline
      - `unchanged` for findings present in both
      - `absent` for resolved findings (rendered as separate results)"""
    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _level_for(finding.severity),
        "message": {"text": finding.description},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                # Region intentionally omitted — the parser does not currently
                # track line numbers. SARIF allows this; consumers degrade
                # gracefully to file-level findings.
            },
            "logicalLocations": [{"name": finding.location}] if finding.location else [],
        }],
        "partialFingerprints": {
            "ciguard/v1": finding.fingerprint,
        },
        "properties": {
            "severity": finding.severity.value,
            "security-severity": _security_severity(finding.severity),
            "category": finding.category.value,
            "evidence": finding.evidence,
        },
    }
    if baseline_state is not None:
        result["baselineState"] = baseline_state
    return result


def _tool_version() -> str:
    """Read the installed ciguard version. Falls back to 'unknown' if the
    package metadata isn't available (e.g. running from source without
    `pip install -e .`)."""
    try:
        from importlib.metadata import version as _v
        return _v("ciguard")
    except Exception:
        return "unknown"


class SARIFReporter:
    """Writes a SARIF 2.1.0 file from a Report."""

    def render(self, report: Report) -> str:
        """Return the SARIF JSON document as a string."""
        results: List[Dict[str, Any]] = []
        rules_by_id: Dict[str, Dict[str, Any]] = {}

        # Map fingerprints to baseline state when a delta is present.
        baseline_state_by_fp: Dict[str, str] = {}
        if report.delta is not None:
            for f in report.delta.new:
                baseline_state_by_fp[f.fingerprint] = "new"
            for f in report.delta.unchanged:
                baseline_state_by_fp[f.fingerprint] = "unchanged"

        for finding in report.findings:
            if finding.rule_id not in rules_by_id:
                rules_by_id[finding.rule_id] = _rule_definition(finding)
            results.append(_result(
                finding,
                artifact_uri=report.pipeline_name,
                baseline_state=baseline_state_by_fp.get(finding.fingerprint),
            ))

        # Resolved findings — render as `absent` results so SARIF consumers
        # (e.g. GitHub Code Scanning) can mark them as auto-closed.
        if report.delta is not None:
            for f in report.delta.resolved:
                if f.rule_id not in rules_by_id:
                    rules_by_id[f.rule_id] = _rule_definition(f)
                results.append(_result(
                    f,
                    artifact_uri=report.pipeline_name,
                    baseline_state="absent",
                ))

        # Suppressed findings (.ciguardignore, v0.7+) — render as results
        # carrying SARIF's native `suppressions` array. GitHub Code Scanning
        # honours this and auto-closes the alert with a "Suppressed" status,
        # which is exactly the audit-trail semantic we want.
        if report.suppressed:
            for f in report.suppressed:
                if f.rule_id not in rules_by_id:
                    rules_by_id[f.rule_id] = _rule_definition(f)
                suppressed_result = _result(
                    f,
                    artifact_uri=report.pipeline_name,
                    baseline_state=baseline_state_by_fp.get(f.fingerprint),
                )
                suppressed_result["suppressions"] = [{
                    "kind": "external",
                    "justification": (
                        f"Suppressed by {report.ignore_file_path or '.ciguardignore'}"
                    ),
                }]
                results.append(suppressed_result)

        sarif: Dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": _tool_version(),
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules_by_id.values()),
                        "properties": {
                            "platform": report.platform,
                        },
                    },
                },
                "results": results,
                "properties": {
                    "ciguard": {
                        "platform": report.platform,
                        "risk_score": report.risk_score.overall,
                        "grade": report.risk_score.grade,
                    },
                },
            }],
        }
        return json.dumps(sarif, indent=2)

    def write(self, report: Report, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.write_text(self.render(report), encoding="utf-8")
        return output_path
