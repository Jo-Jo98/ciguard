"""
ciguard analysis engine.

Runs all rules against a pipeline and produces a Report with risk scores.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from typing import Union

from pathlib import Path
from typing import Optional

from .. import __version__
from ..models.jenkinsfile import Jenkinsfile
from ..models.pipeline import (
    Category,
    Finding,
    Job as PipelineJob,
    Pipeline,
    Report,
    RiskScore,
    Severity,
)
from ..models.workflow import Workflow
from .gha_rules import GHA_RULES
from .jenkins_rules import JENKINS_RULES
from .rules import RULES, _reset_counters
from .sca.endoflife import EndOfLifeClient
from .sca_rules import SCA_RULES

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

_SEVERITY_DEDUCTION: Dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

_CATEGORY_CAP: Dict[Severity, float] = {
    Severity.CRITICAL: 50.0,
    Severity.HIGH: 30.0,
    Severity.MEDIUM: 21.0,
    Severity.LOW: 9.0,
    Severity.INFO: 5.0,
}

_CATEGORY_MAP: Dict[Category, str] = {
    Category.PIPELINE_INTEGRITY: "pipeline_integrity",
    Category.IDENTITY_ACCESS: "identity_access",
    Category.RUNNER_SECURITY: "runner_security",
    Category.ARTIFACT_HANDLING: "artifact_handling",
    Category.DEPLOYMENT_GOVERNANCE: "deployment_governance",
    Category.SUPPLY_CHAIN: "supply_chain",
}


class AnalysisEngine:
    """Runs security rules against a Pipeline (GitLab CI), Workflow
    (GitHub Actions), or Jenkinsfile (Jenkins Declarative Pipeline) and
    returns a unified `Report`."""

    def __init__(
        self,
        enable_sca: bool = True,
        sca_offline: bool = False,
        sca_cache_dir: Optional[Path] = None,
    ) -> None:
        # SCA enrichment (v0.6.0). Cache lives at `~/.ciguard/cache/`
        # by default — shared across pipeline scans on the same machine
        # so a single fetch of (e.g.) python EOL data benefits every
        # subsequent run for 24 hours.
        # `enable_sca=False` skips SCA entirely — useful for tests that
        # assert only platform-rule behaviour, and for any caller that
        # wants strict offline-no-cache behaviour.
        self.enable_sca = enable_sca
        cache_dir = sca_cache_dir or (Path.home() / ".ciguard" / "cache")
        self._eol_client = EndOfLifeClient(
            cache_dir=cache_dir,
            offline=sca_offline,
        )

    def analyse(
        self,
        target: Union[Pipeline, Workflow, Jenkinsfile],
        pipeline_name: str = "pipeline",
    ) -> Report:
        if isinstance(target, Workflow):
            report = self._analyse_workflow(target, pipeline_name)
        elif isinstance(target, Jenkinsfile):
            report = self._analyse_jenkinsfile(target, pipeline_name)
        else:
            report = self._analyse_pipeline(target, pipeline_name)
        # SCA rules run for every platform after the platform-specific
        # rule pass. They may add findings + need to be reflected in the
        # risk score and summary, so we recompute both.
        if self.enable_sca:
            sca_findings = self._run_sca(target)
            if sca_findings:
                report.findings.extend(sca_findings)
                report.risk_score = self._calculate_risk(report.findings)
                report.summary = self._build_summary(report.findings)
        return report

    def _run_sca(self, target: Union[Pipeline, Workflow, Jenkinsfile]) -> List[Finding]:
        """Run every SCA rule against the target. Each rule receives the
        shared EndOfLifeClient so cache state + offline mode are
        consistent across the run."""
        findings: List[Finding] = []
        for rule in SCA_RULES:
            try:
                findings.extend(rule(target, self._eol_client))
            except Exception as exc:
                import traceback
                print(f"[WARN] SCA rule {rule.__name__} raised: {exc}\n"
                      f"{traceback.format_exc()}")
        return findings

    # ------------------------------------------------------------------
    # GitLab CI path (existing)
    # ------------------------------------------------------------------

    def _analyse_pipeline(self, pipeline: Pipeline, pipeline_name: str) -> Report:
        _reset_counters()

        findings: List[Finding] = []
        for rule in RULES:
            try:
                rule_findings = rule(pipeline)
                findings.extend(rule_findings)
            except Exception as exc:
                # Don't let a single rule crash the whole scan
                import traceback
                print(f"[WARN] Rule {rule.__name__} raised: {exc}\n{traceback.format_exc()}")

        risk_score = self._calculate_risk(findings)
        summary = self._build_summary(findings)

        return Report(
            pipeline_name=pipeline_name,
            findings=findings,
            risk_score=risk_score,
            pipeline=pipeline,
            platform="gitlab-ci",
            summary=summary,
            scanner_version=__version__,
        )

    # ------------------------------------------------------------------
    # GitHub Actions path (new in v0.2.0)
    # ------------------------------------------------------------------

    def _analyse_workflow(self, workflow: Workflow, pipeline_name: str) -> Report:
        _reset_counters()

        findings: List[Finding] = []
        for rule in GHA_RULES:
            try:
                findings.extend(rule(workflow))
            except Exception as exc:
                import traceback
                print(f"[WARN] Rule {rule.__name__} raised: {exc}\n{traceback.format_exc()}")

        risk_score = self._calculate_risk(findings)
        summary = self._build_summary(findings)

        # Synthesise a minimal Pipeline shadow so the existing reporter / web
        # layer keep showing a job count and a meaningful "Target:" line.
        # GitHub Actions has no concept of stages, so stages stays empty.
        synthetic = Pipeline(
            stages=[],
            jobs=[PipelineJob(name=j.name or j.id) for j in workflow.jobs],
        )

        return Report(
            pipeline_name=pipeline_name,
            findings=findings,
            risk_score=risk_score,
            pipeline=synthetic,
            workflow=workflow,
            platform="github-actions",
            summary=summary,
            scanner_version=__version__,
        )

    # ------------------------------------------------------------------
    # Jenkins Declarative Pipeline path (new in v0.4.0)
    # ------------------------------------------------------------------

    def _analyse_jenkinsfile(self, jf: Jenkinsfile, pipeline_name: str) -> Report:
        _reset_counters()

        findings: List[Finding] = []
        for rule in JENKINS_RULES:
            try:
                findings.extend(rule(jf))
            except Exception as exc:
                import traceback
                print(f"[WARN] Rule {rule.__name__} raised: {exc}\n{traceback.format_exc()}")

        risk_score = self._calculate_risk(findings)
        summary = self._build_summary(findings)

        # Synthesise a Pipeline shadow so reporters / web UI keep showing a
        # job-equivalent count. Each Jenkins stage becomes a Pipeline job.
        # Jenkins doesn't have GitLab-style stages, so stages stays empty.
        synthetic = Pipeline(
            stages=[],
            jobs=[PipelineJob(name=s.name) for s in jf.stages],
        )

        return Report(
            pipeline_name=pipeline_name,
            findings=findings,
            risk_score=risk_score,
            pipeline=synthetic,
            platform="jenkins",
            summary=summary,
            scanner_version=__version__,
        )

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk(self, findings: List[Finding]) -> RiskScore:
        # Per-category scores (start at 100, apply deductions)
        category_scores: Dict[str, float] = {
            "pipeline_integrity": 100.0,
            "identity_access": 100.0,
            "runner_security": 100.0,
            "artifact_handling": 100.0,
            "deployment_governance": 100.0,
            "supply_chain": 100.0,
        }

        # Track deductions applied per (category, severity) to enforce caps
        category_severity_deductions: Dict[tuple, float] = defaultdict(float)

        for finding in findings:
            cat_key = _CATEGORY_MAP[finding.category]
            deduction = _SEVERITY_DEDUCTION[finding.severity]
            cap = _CATEGORY_CAP[finding.severity]
            key = (cat_key, finding.severity)

            already_deducted = category_severity_deductions[key]
            remaining_cap = max(0.0, cap - already_deducted)
            actual_deduction = min(deduction, remaining_cap)

            category_scores[cat_key] = max(0.0, category_scores[cat_key] - actual_deduction)
            category_severity_deductions[key] += actual_deduction

        # Overall score: weighted mean across 5 logical domains
        # Slice-5 spec: integrity 25%, identity 20%, deployment 20%,
        #               testing 15% (split evenly between runner + artifacts),
        #               supply chain 20%
        weights = {
            "pipeline_integrity":    0.25,
            "identity_access":       0.20,
            "runner_security":       0.075,
            "artifact_handling":     0.075,
            "deployment_governance": 0.20,
            "supply_chain":          0.20,
        }
        overall = sum(
            category_scores[cat] * weight for cat, weight in weights.items()
        )
        overall = round(max(0.0, min(100.0, overall)), 1)

        return RiskScore(
            overall=overall,
            pipeline_integrity=round(category_scores["pipeline_integrity"], 1),
            identity_access=round(category_scores["identity_access"], 1),
            runner_security=round(category_scores["runner_security"], 1),
            artifact_handling=round(category_scores["artifact_handling"], 1),
            deployment_governance=round(category_scores["deployment_governance"], 1),
            supply_chain=round(category_scores["supply_chain"], 1),
            grade=RiskScore.grade_from_score(overall),
        )

    def _build_summary(self, findings: List[Finding]) -> dict:
        by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        by_category: Dict[str, int] = {c.value: 0 for c in Category}

        for finding in findings:
            by_severity[finding.severity.value] += 1
            by_category[finding.category.value] += 1

        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
        }
