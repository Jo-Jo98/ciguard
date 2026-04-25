"""
Tests for the ciguard Policy Engine.

Covers:
  - Policy model creation and serialisation
  - Built-in policies pass/fail on good/bad pipelines
  - Custom policy loading from YAML
  - Policy evaluator output shape
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.policy.builtin import BUILTIN_POLICIES
from ciguard.policy.evaluator import PolicyEvaluator
from ciguard.policy.loader import load_policies_from_directory, load_policies_from_file
from ciguard.policy.models import (
    PolicyCondition,
    PolicyDefinition,
    PolicyReport,
    PolicyResult,
    PolicySeverity,
)

FIXTURES = Path(__file__).parent / "fixtures"
parser  = GitLabCIParser()
engine  = AnalysisEngine()
evaluator = PolicyEvaluator()


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestPolicyModels:
    def test_builtin_count(self):
        assert len(BUILTIN_POLICIES) == 7

    def test_builtin_ids_unique(self):
        ids = [p.id for p in BUILTIN_POLICIES]
        assert len(ids) == len(set(ids))

    def test_builtin_have_required_fields(self):
        for p in BUILTIN_POLICIES:
            assert p.id.startswith("POL-")
            assert p.name
            assert p.description
            assert p.remediation
            assert p.condition.type

    def test_policy_severity_enum(self):
        assert PolicySeverity.CRITICAL.value == "critical"
        assert PolicySeverity.HIGH.value == "high"

    def test_policy_report_pass_rate(self):
        rpt = PolicyReport(policies_evaluated=10, passed=8, failed=2)
        assert rpt.pass_rate == 80.0

    def test_policy_report_zero_division(self):
        rpt = PolicyReport()
        assert rpt.pass_rate == 100.0


# ---------------------------------------------------------------------------
# Evaluator: good pipeline should pass most policies
# ---------------------------------------------------------------------------

class TestGoodPipelinePolicies:
    def setup_method(self):
        pipeline = parser.parse_file(FIXTURES / "good_pipeline.yml")
        self.report  = engine.analyse(pipeline, "good_pipeline.yml")
        self.pipeline = pipeline
        self.pol_report = evaluator.evaluate(BUILTIN_POLICIES, pipeline, self.report)

    def test_returns_policy_report(self):
        assert isinstance(self.pol_report, PolicyReport)

    def test_correct_count(self):
        assert self.pol_report.policies_evaluated == len(BUILTIN_POLICIES)

    def test_most_pass(self):
        # Good pipeline should pass the majority of policies
        assert self.pol_report.passed >= len(BUILTIN_POLICIES) * 0.5

    def test_result_shape(self):
        for r in self.pol_report.results:
            assert isinstance(r, PolicyResult)
            assert isinstance(r.passed, bool)
            assert r.evidence
            assert r.policy.id


# ---------------------------------------------------------------------------
# Evaluator: bad pipeline should fail most policies
# ---------------------------------------------------------------------------

class TestBadPipelinePolicies:
    def setup_method(self):
        pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        self.report  = engine.analyse(pipeline, "bad_pipeline.yml")
        self.pipeline = pipeline
        self.pol_report = evaluator.evaluate(BUILTIN_POLICIES, pipeline, self.report)

    def test_has_failures(self):
        assert self.pol_report.failed > 0

    def test_pol_001_fails_no_approval(self):
        """POL-001: No direct-to-production — should FAIL on bad pipeline."""
        r = next(r for r in self.pol_report.results if r.policy.id == "POL-001")
        assert not r.passed

    def test_pol_002_fails_unpinned_images(self):
        """POL-002: Pinned images — should FAIL on bad pipeline."""
        r = next(r for r in self.pol_report.results if r.policy.id == "POL-002")
        assert not r.passed

    def test_pol_006_fails_no_dep_scan(self):
        """POL-006: Dependency scan — should FAIL on bad pipeline."""
        r = next(r for r in self.pol_report.results if r.policy.id == "POL-006")
        assert not r.passed


# ---------------------------------------------------------------------------
# Condition types
# ---------------------------------------------------------------------------

class TestConditionTypes:
    def setup_method(self):
        self.pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        self.report   = engine.analyse(self.pipeline, "bad_pipeline.yml")

    def _eval(self, condition: PolicyCondition) -> PolicyResult:
        policy = PolicyDefinition(
            id="TEST-001", name="Test", description="Test policy",
            severity=PolicySeverity.MEDIUM,
            condition=condition,
            remediation="Fix it",
        )
        pr = evaluator.evaluate([policy], self.pipeline, self.report)
        return pr.results[0]

    def test_no_rule_findings_pass(self):
        # ART-002 might or might not fire; use a rule that clearly doesn't exist
        r = self._eval(PolicyCondition(type="no_rule_findings", rule_ids=["NONEXISTENT-999"]))
        assert r.passed

    def test_no_rule_findings_fail(self):
        # IAM-001 definitely fires on bad pipeline
        r = self._eval(PolicyCondition(type="no_rule_findings", rule_ids=["IAM-001"]))
        assert not r.passed

    def test_max_findings_fail(self):
        r = self._eval(PolicyCondition(type="max_findings", max_count=0))
        assert not r.passed

    def test_max_findings_pass(self):
        r = self._eval(PolicyCondition(type="max_findings", max_count=9999))
        assert r.passed

    def test_min_risk_score_fail(self):
        r = self._eval(PolicyCondition(type="min_risk_score", min_score=99.0))
        assert not r.passed

    def test_min_risk_score_pass(self):
        r = self._eval(PolicyCondition(type="min_risk_score", min_score=0.0))
        assert r.passed

    def test_no_severity_fail(self):
        r = self._eval(PolicyCondition(type="no_severity", severity="Critical"))
        assert not r.passed

    def test_no_severity_pass(self):
        # Info severity unlikely on bad pipeline
        r = self._eval(PolicyCondition(type="no_severity", severity="Info"))
        assert r.passed

    def test_min_category_score_fail(self):
        r = self._eval(PolicyCondition(type="min_category_score",
                                       category="pipeline_integrity", min_score=90.0))
        assert not r.passed

    def test_min_category_score_pass(self):
        r = self._eval(PolicyCondition(type="min_category_score",
                                       category="pipeline_integrity", min_score=0.0))
        assert r.passed

    def test_pipeline_check_has_security_scanning(self):
        # bad pipeline has no security scanning
        r = self._eval(PolicyCondition(type="pipeline_check", check="has_security_scanning"))
        assert not r.passed

    def test_unknown_condition_type_skips(self):
        r = self._eval(PolicyCondition(type="completely_unknown_type"))
        assert r.passed  # unknown types are skipped (pass)

    def test_unknown_pipeline_check_skips(self):
        r = self._eval(PolicyCondition(type="pipeline_check", check="nonexistent_check"))
        assert r.passed  # unknown checks are skipped


# ---------------------------------------------------------------------------
# Include-template detection (regression: POL-003 + SC-003 false-negative)
# ---------------------------------------------------------------------------

class TestIncludeTemplateScanningDetection:
    """`include: template: Security/...gitlab-ci.yml` is a valid way to add
    SAST / Secret-Detection / Dependency-Scanning to a pipeline. The scanning
    rules and the `has_security_scanning` policy check must recognise this,
    not just job-name / script-line text."""

    def setup_method(self):
        self.pipeline = parser.parse_file(FIXTURES / "realworld_demo.gitlab-ci.yml")
        self.report   = engine.analyse(self.pipeline, "realworld_demo.gitlab-ci.yml")

    def test_sc_003_not_fired_when_dependency_scanning_template_included(self):
        sc_003 = [f for f in self.report.findings if f.rule_id == "SC-003"]
        assert sc_003 == [], (
            "SC-003 should not fire when "
            "`include: template: Security/Dependency-Scanning.gitlab-ci.yml` is present"
        )

    def test_has_security_scanning_passes_with_sast_and_secret_templates(self):
        policy = PolicyDefinition(
            id="TEST-INC", name="Test", description="Test",
            severity=PolicySeverity.HIGH,
            condition=PolicyCondition(type="pipeline_check", check="has_security_scanning"),
            remediation="-",
        )
        pr = evaluator.evaluate([policy], self.pipeline, self.report)
        assert pr.results[0].passed, (
            "has_security_scanning should pass when SAST + Secret-Detection "
            "templates are pulled in via `include:`"
        )

    def test_include_text_flattens_template_refs(self):
        text = self.pipeline.include_text()
        assert "Security/SAST.gitlab-ci.yml" in text
        assert "Security/Secret-Detection.gitlab-ci.yml" in text
        assert "Security/Dependency-Scanning.gitlab-ci.yml" in text


# ---------------------------------------------------------------------------
# Custom policy loader
# ---------------------------------------------------------------------------

class TestPolicyLoader:
    def test_load_single_policy_file(self, tmp_path):
        policy_yaml = tmp_path / "my_policy.yml"
        policy_yaml.write_text(textwrap.dedent("""
            id: ORG-001
            name: "No critical findings"
            description: "Organisation requires zero critical findings"
            severity: critical
            condition:
              type: no_severity
              severity: Critical
            remediation: "Fix all critical findings before merging"
            tags: [org, critical]
        """), encoding="utf-8")
        policies = load_policies_from_file(policy_yaml)
        assert len(policies) == 1
        assert policies[0].id == "ORG-001"
        assert policies[0].severity == PolicySeverity.CRITICAL
        assert policies[0].condition.type == "no_severity"

    def test_load_multi_policy_file(self, tmp_path):
        policy_yaml = tmp_path / "multi.yml"
        policy_yaml.write_text(textwrap.dedent("""
            policies:
              - id: ORG-002
                name: Policy Two
                description: Test
                severity: high
                condition:
                  type: max_findings
                  max_count: 5
                remediation: Fix
              - id: ORG-003
                name: Policy Three
                description: Test
                severity: low
                condition:
                  type: min_risk_score
                  min_score: 50
                remediation: Fix
        """), encoding="utf-8")
        policies = load_policies_from_file(policy_yaml)
        assert len(policies) == 2
        assert {p.id for p in policies} == {"ORG-002", "ORG-003"}

    def test_load_from_directory(self, tmp_path):
        (tmp_path / "p1.yml").write_text(textwrap.dedent("""
            id: DIR-001
            name: Dir Policy 1
            description: Test
            severity: medium
            condition:
              type: no_rule_findings
              rule_ids: [PIPE-001]
            remediation: Fix
        """), encoding="utf-8")
        (tmp_path / "p2.yaml").write_text(textwrap.dedent("""
            id: DIR-002
            name: Dir Policy 2
            description: Test
            severity: low
            condition:
              type: max_findings
              max_count: 10
            remediation: Fix
        """), encoding="utf-8")
        policies = load_policies_from_directory(tmp_path)
        assert len(policies) == 2

    def test_load_invalid_yaml_graceful(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text(": : }{", encoding="utf-8")
        policies = load_policies_from_file(bad)
        assert policies == []

    def test_load_missing_directory_graceful(self, tmp_path):
        policies = load_policies_from_directory(tmp_path / "does_not_exist")
        assert policies == []

    def test_custom_policy_source_set(self, tmp_path):
        policy_yaml = tmp_path / "custom.yml"
        policy_yaml.write_text(textwrap.dedent("""
            id: SRC-001
            name: Source Test
            description: Test
            severity: medium
            condition:
              type: max_findings
              max_count: 100
            remediation: Fix
        """), encoding="utf-8")
        policies = load_policies_from_file(policy_yaml)
        assert policies[0].source == str(policy_yaml)

    def test_combined_builtin_and_custom(self, tmp_path):
        """Run built-in + custom policies together against bad pipeline."""
        policy_yaml = tmp_path / "custom.yml"
        policy_yaml.write_text(textwrap.dedent("""
            id: CUSTOM-001
            name: Max 20 findings
            description: No more than 20 findings allowed
            severity: high
            condition:
              type: max_findings
              max_count: 20
            remediation: Fix all findings
        """), encoding="utf-8")
        custom_policies = load_policies_from_file(policy_yaml)
        all_policies = BUILTIN_POLICIES + custom_policies

        pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report   = engine.analyse(pipeline)
        pol_report = evaluator.evaluate(all_policies, pipeline, report)

        assert pol_report.policies_evaluated == len(BUILTIN_POLICIES) + 1
        # CUSTOM-001 should fail (bad pipeline has > 20 findings)
        custom_result = next(r for r in pol_report.results if r.policy.id == "CUSTOM-001")
        assert not custom_result.passed
