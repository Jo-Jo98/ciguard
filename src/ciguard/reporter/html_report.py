"""
ciguard HTML report generator.

Renders a self-contained, dark-themed HTML report from a Report model.
No CDN dependencies — all CSS and JS are inline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models.pipeline import Category, Report, Severity

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.html"


class HTMLReporter:
    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        self._env.filters["severity_class"] = _severity_class
        self._env.filters["severity_icon"] = _severity_icon
        self._env.filters["category_icon"] = _category_icon
        self._env.filters["grade_class"] = _grade_class
        self._env.filters["score_colour"] = _score_colour

    def render(self, report: Report) -> str:
        template = self._env.get_template(TEMPLATE_NAME)

        # Pre-compute template data
        sorted_findings = report.sorted_findings()

        category_scores = {
            "Pipeline Integrity": report.risk_score.pipeline_integrity,
            "Identity & Access": report.risk_score.identity_access,
            "Runner Security": report.risk_score.runner_security,
            "Artifact Handling": report.risk_score.artifact_handling,
            "Deployment Governance": report.risk_score.deployment_governance,
            "Supply Chain": report.risk_score.supply_chain,
        }

        compliance_table = _build_compliance_table(sorted_findings)
        remediation_roadmap = _build_remediation_roadmap(sorted_findings)
        pipeline_stages = _build_stage_data(report)

        return template.render(
            report=report,
            sorted_findings=sorted_findings,
            category_scores=category_scores,
            compliance_table=compliance_table,
            remediation_roadmap=remediation_roadmap,
            pipeline_stages=pipeline_stages,
            severities=[s.value for s in Severity],
            categories=[c.value for c in Category],
            severity_counts=report.summary.get("by_severity", {}),
        )

    def write(self, report: Report, output_path: str | Path) -> None:
        html = self.render(report)
        Path(output_path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Template filters
# ---------------------------------------------------------------------------

def _severity_class(severity: str) -> str:
    return {
        "Critical": "sev-critical",
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
        "Info": "sev-info",
    }.get(severity, "sev-info")


def _severity_icon(severity: str) -> str:
    return {
        "Critical": "&#9679;",   # ● filled circle
        "High": "&#9650;",       # ▲ triangle
        "Medium": "&#9670;",     # ◆ diamond
        "Low": "&#9675;",        # ○ hollow circle
        "Info": "&#8505;",       # ℹ info
    }.get(severity, "&#8505;")


def _category_icon(category: str) -> str:
    return {
        "Pipeline Integrity": "&#9881;",       # ⚙
        "Identity & Access": "&#128274;",      # 🔒
        "Runner Security": "&#128187;",        # 💻
        "Artifact Handling": "&#128230;",      # 📦
        "Deployment Governance": "&#128640;",  # 🚀
        "Supply Chain": "&#128279;",           # 🔗
    }.get(category, "&#9632;")


def _grade_class(grade: str) -> str:
    return {
        "A": "grade-a",
        "B": "grade-b",
        "C": "grade-c",
        "D": "grade-d",
        "F": "grade-f",
    }.get(grade, "grade-f")


def _score_colour(score: float) -> str:
    if score >= 90:
        return "#3fb950"
    elif score >= 75:
        return "#58a6ff"
    elif score >= 60:
        return "#d29922"
    elif score >= 40:
        return "#f0883e"
    return "#da3633"


# ---------------------------------------------------------------------------
# Data preparation helpers
# ---------------------------------------------------------------------------

def _findings_to_json(findings: list) -> str:
    data = []
    for f in findings:
        data.append({
            "id": f.id,
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity.value,
            "category": f.category.value,
            "location": f.location,
            "evidence": f.evidence,
            "description": f.description,
            "remediation": f.remediation,
        })
    return json.dumps(data)


def _build_compliance_table(findings: list) -> List[Dict[str, Any]]:
    """Aggregate compliance mappings across all findings."""
    iso_set: set = set()
    soc2_set: set = set()
    nist_set: set = set()

    for f in findings:
        iso_set.update(f.compliance.iso_27001)
        soc2_set.update(f.compliance.soc2)
        nist_set.update(f.compliance.nist)

    rows = []
    # Build per-control rows: control → findings that map to it
    all_controls = (
        [("ISO 27001", c) for c in sorted(iso_set)]
        + [("SOC 2", c) for c in sorted(soc2_set)]
        + [("NIST CSF", c) for c in sorted(nist_set)]
    )

    for framework, control in all_controls:
        mapped = []
        for f in findings:
            if framework == "ISO 27001" and control in f.compliance.iso_27001:
                mapped.append(f)
            elif framework == "SOC 2" and control in f.compliance.soc2:
                mapped.append(f)
            elif framework == "NIST CSF" and control in f.compliance.nist:
                mapped.append(f)

        if mapped:
            max_sev = min(mapped, key=lambda x: x.severity_order)
            rows.append({
                "framework": framework,
                "control": control,
                "findings_count": len(mapped),
                "max_severity": max_sev.severity.value,
                "finding_names": [f.name for f in mapped[:3]],
            })

    return rows


def _build_remediation_roadmap(findings: list) -> List[Dict[str, Any]]:
    """Priority-ordered remediation steps, deduplicated by rule."""
    seen_rules: set = set()
    roadmap = []

    for f in sorted(findings, key=lambda x: x.severity_order):
        if f.rule_id in seen_rules:
            continue
        seen_rules.add(f.rule_id)
        roadmap.append({
            "rule_id": f.rule_id,
            "name": f.name,
            "severity": f.severity.value,
            "category": f.category.value,
            "remediation": f.remediation,
        })

    return roadmap


def _build_stage_data(report: Report) -> List[Dict[str, Any]]:
    """Build stage → jobs data for pipeline visualisation."""
    pipeline = report.pipeline
    stage_data = []

    for stage_name in pipeline.stages:
        jobs_in_stage = [j for j in pipeline.jobs if j.stage == stage_name]
        jobs_data = []
        for job in jobs_in_stage:
            job_findings = [f for f in report.findings if f.location == job.name]
            max_severity = None
            if job_findings:
                worst = min(job_findings, key=lambda x: x.severity_order)
                max_severity = worst.severity.value

            jobs_data.append({
                "name": job.name,
                "has_environment": job.environment is not None,
                "env_name": job.environment.name if job.environment else None,
                "is_manual": job.when == "manual",
                "findings_count": len(job_findings),
                "max_severity": max_severity,
            })

        stage_data.append({
            "name": stage_name,
            "jobs": jobs_data,
        })

    return stage_data
