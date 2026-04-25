"""
ciguard Policy Evaluator.

Evaluates a list of PolicyDefinitions against a (Pipeline, Report) pair and
returns a PolicyReport.  All evaluation is pure Python — no OPA/Conftest.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from ..models.pipeline import Pipeline, Report, Severity
from .models import PolicyCondition, PolicyDefinition, PolicyReport, PolicyResult


# ---------------------------------------------------------------------------
# Named pipeline-check functions
# ---------------------------------------------------------------------------

def _check_has_security_scanning(pipeline: Pipeline, report: Report) -> bool:
    """True if any job runs a SAST/DAST/secret/dependency scan tool, or
    the pipeline includes a GitLab Security/* template that does."""
    import re
    scan_re = re.compile(
        r"(sast|dast|trivy|snyk|grype|syft|retire|pip.audit|bundler.audit|"
        r"dependency.scan|software.composition|owasp|semgrep|bandit|safety|"
        r"secret.detection|gitleaks|trufflehog|detect.secrets|gemnasium)",
        re.I,
    )
    all_text = " ".join(
        [j.name for j in pipeline.jobs]
        + pipeline.stages
        + [line for j in pipeline.jobs for line in j.all_scripts()]
        + [pipeline.include_text()]
    )
    return bool(scan_re.search(all_text))


def _check_no_hardcoded_secrets(pipeline: Pipeline, report: Report) -> bool:
    from ..models.pipeline import Category
    return not any(
        f.category == Category.IDENTITY_ACCESS and f.rule_id == "IAM-001"
        for f in report.findings
    )


def _check_all_images_pinned(pipeline: Pipeline, report: Report) -> bool:
    return not any(f.rule_id == "PIPE-001" for f in report.findings)


def _check_has_dependency_scanning(pipeline: Pipeline, report: Report) -> bool:
    return not any(f.rule_id == "SC-003" for f in report.findings)


def _check_production_protected(pipeline: Pipeline, report: Report) -> bool:
    return not any(f.rule_id in ("PIPE-004", "DEP-002") for f in report.findings)


_NAMED_CHECKS: Dict[str, Callable[[Pipeline, Report], bool]] = {
    "has_security_scanning":   _check_has_security_scanning,
    "no_hardcoded_secrets":    _check_no_hardcoded_secrets,
    "all_images_pinned":       _check_all_images_pinned,
    "has_dependency_scanning": _check_has_dependency_scanning,
    "production_protected":    _check_production_protected,
}


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------

def _evaluate_condition(
    condition: PolicyCondition,
    pipeline: Pipeline,
    report: Report,
) -> tuple[bool, str]:
    """Return (passed, evidence)."""

    t = condition.type

    if t == "no_rule_findings":
        if not condition.rule_ids:
            return True, "No rule_ids specified — trivially passing"
        triggered = [
            f for f in report.findings if f.rule_id in condition.rule_ids
        ]
        if triggered:
            detail = ", ".join(
                f"{f.rule_id} @ {f.location}" for f in triggered
            )
            return False, f"Rules triggered: {detail}"
        return True, f"No findings for rules: {', '.join(condition.rule_ids)}"

    elif t == "max_findings":
        count = len(report.findings)
        max_c = condition.max_count if condition.max_count is not None else 0
        if count > max_c:
            return False, f"Finding count {count} exceeds maximum {max_c}"
        return True, f"Finding count {count} ≤ maximum {max_c}"

    elif t == "min_risk_score":
        score = report.risk_score.overall
        min_s = condition.min_score if condition.min_score is not None else 70.0
        if score < min_s:
            return False, f"Overall score {score:.1f} below minimum {min_s:.1f}"
        return True, f"Overall score {score:.1f} ≥ minimum {min_s:.1f}"

    elif t == "no_severity":
        sev_name = (condition.severity or "Critical").capitalize()
        # Map string to Severity enum
        sev_map = {s.value: s for s in Severity}
        sev = sev_map.get(sev_name)
        if sev is None:
            return True, f"Unknown severity {sev_name!r} — check skipped"
        bad = [f for f in report.findings if f.severity == sev]
        if bad:
            return False, f"{len(bad)} {sev_name} findings present"
        return True, f"No {sev_name} findings"

    elif t == "min_category_score":
        cat = condition.category or ""
        min_s = condition.min_score if condition.min_score is not None else 70.0
        score_obj = report.risk_score
        cat_score = getattr(score_obj, cat, None)
        if cat_score is None:
            return True, f"Unknown category {cat!r} — check skipped"
        if cat_score < min_s:
            return False, f"{cat} score {cat_score:.1f} below minimum {min_s:.1f}"
        return True, f"{cat} score {cat_score:.1f} ≥ minimum {min_s:.1f}"

    elif t == "pipeline_check":
        check_name = condition.check or ""
        fn = _NAMED_CHECKS.get(check_name)
        if fn is None:
            return True, f"Unknown check {check_name!r} — skipped"
        result = fn(pipeline, report)
        if result:
            return True, f"Check '{check_name}' passed"
        return False, f"Check '{check_name}' failed"

    else:
        return True, f"Unknown condition type {t!r} — skipped"


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    """Evaluates a list of policies against a (Pipeline, Report) pair."""

    def evaluate(
        self,
        policies: List[PolicyDefinition],
        pipeline: Pipeline,
        report: Report,
    ) -> PolicyReport:
        results: List[PolicyResult] = []

        for policy in policies:
            # Skip policies that don't apply to this scan's platform.
            # `platforms=[]` means "applies everywhere" (default for user
            # policies that test platform-agnostic conditions).
            if not policy.applies_to(report.platform):
                continue

            try:
                passed, evidence = _evaluate_condition(
                    policy.condition, pipeline, report
                )
            except Exception as exc:
                passed, evidence = False, f"Evaluation error: {exc}"

            results.append(PolicyResult(
                policy=policy,
                passed=passed,
                evidence=evidence,
            ))

        passed_count = sum(1 for r in results if r.passed)
        return PolicyReport(
            policies_evaluated=len(results),
            passed=passed_count,
            failed=len(results) - passed_count,
            results=results,
        )
