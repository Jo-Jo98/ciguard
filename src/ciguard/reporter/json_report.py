"""
ciguard JSON report exporter.

Serialises the full Report (including policy results and scanner findings)
to a structured JSON file suitable for API consumers and integrations.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models.pipeline import Report


class JSONReporter:
    """Writes the full scan report as indented JSON."""

    def render(self, report: Report) -> str:
        """Return JSON string representation of the report."""
        data = report.model_dump(mode="json")

        # Flatten policy_report if present (it's a Pydantic model stored as Any)
        if report.policy_report is not None:
            try:
                data["policy_report"] = report.policy_report.model_dump(mode="json")
            except AttributeError:
                pass  # already a dict

        # Flatten scanner findings
        if report.scanner_findings:
            data["scanner_findings"] = [
                f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                for f in report.scanner_findings
            ]

        return json.dumps(data, indent=2, ensure_ascii=False)

    def write(self, report: Report, output_path: Path) -> None:
        """Write JSON report to file."""
        output_path.write_text(self.render(report), encoding="utf-8")
