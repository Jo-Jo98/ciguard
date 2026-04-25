"""
Tests for the SARIF 2.1.0 reporter.

These cover:
  - Top-level shape (`version`, `$schema`, `runs[0].tool.driver.{name,rules}`)
  - Severity → SARIF level mapping (Critical/High → error, Medium → warning,
    Low/Info → note) and the `security-severity` numeric ranking GitHub uses
  - Rule deduplication (every finding produces a result, but rules array is
    deduped by rule_id)
  - Compliance framework tags ride along on each rule's `properties.tags`
  - Both GitLab CI and GitHub Actions findings serialise correctly
  - The output file is valid JSON and round-trips through `json.loads`
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.parser.github_actions import GitHubActionsParser
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.reporter.sarif_report import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    SARIFReporter,
)

FIXTURES = Path(__file__).parent / "fixtures"
GHA_FIXTURES = FIXTURES / "github_actions"


# ---------------------------------------------------------------------------
# GitLab CI bad fixture → SARIF
# ---------------------------------------------------------------------------

class TestSARIFFromGitLabCI:
    def setup_method(self):
        p = GitLabCIParser().parse_file(FIXTURES / "bad_pipeline.yml")
        self.report = AnalysisEngine().analyse(p, "bad_pipeline.yml")
        self.sarif = json.loads(SARIFReporter().render(self.report))

    def test_top_level_shape(self):
        assert self.sarif["version"] == SARIF_VERSION
        assert self.sarif["$schema"] == SARIF_SCHEMA
        assert len(self.sarif["runs"]) == 1

    def test_tool_driver(self):
        driver = self.sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_NAME
        assert driver["informationUri"].startswith("https://github.com/")
        assert isinstance(driver["rules"], list)
        assert driver["rules"]   # at least one rule definition
        assert driver["properties"]["platform"] == "gitlab-ci"

    def test_results_count_matches_findings(self):
        results = self.sarif["runs"][0]["results"]
        assert len(results) == len(self.report.findings)

    def test_rules_array_deduplicated_by_rule_id(self):
        rules = self.sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))

    def test_severity_level_mapping(self):
        results = self.sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        # bad_pipeline has Critical + High + Medium findings → expect a mix
        assert "error" in levels
        assert "warning" in levels or "note" in levels
        assert levels <= {"error", "warning", "note", "none"}

    def test_security_severity_numeric_present(self):
        # GitHub Code Scanning ranks by `properties.security-severity`
        for result in self.sarif["runs"][0]["results"]:
            ssev = result["properties"]["security-severity"]
            assert isinstance(ssev, str)
            assert 0.0 <= float(ssev) <= 10.0

    def test_compliance_tags_on_rules(self):
        rules = self.sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            tags = rule["properties"]["tags"]
            # Every rule has at least the `security` tag
            assert "security" in tags

    def test_artifact_uri_is_pipeline_name(self):
        result = self.sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uri"] == "bad_pipeline.yml"

    def test_writes_valid_json_file(self, tmp_path):
        out = tmp_path / "report.sarif"
        SARIFReporter().write(self.report, out)
        assert out.exists()
        # Round-trip
        loaded = json.loads(out.read_text())
        assert loaded["version"] == SARIF_VERSION


# ---------------------------------------------------------------------------
# GitHub Actions bad fixture → SARIF
# ---------------------------------------------------------------------------

class TestSARIFFromGitHubActions:
    def setup_method(self):
        wf = GitHubActionsParser().parse_file(GHA_FIXTURES / "bad_actions.yml")
        self.report = AnalysisEngine().analyse(wf, "bad_actions.yml")
        self.sarif = json.loads(SARIFReporter().render(self.report))

    def test_platform_recorded_in_tool_properties(self):
        platform = self.sarif["runs"][0]["tool"]["driver"]["properties"]["platform"]
        assert platform == "github-actions"

    def test_results_use_gha_rule_ids(self):
        rule_ids = {r["ruleId"] for r in self.sarif["runs"][0]["results"]}
        assert all(rid.startswith("GHA-") for rid in rule_ids), rule_ids

    def test_logical_locations_set(self):
        # We populate `logicalLocations` from finding.location (job/step path).
        # This gives reviewers context in tools that read SARIF beyond GitHub.
        for r in self.sarif["runs"][0]["results"]:
            loc = r["locations"][0]
            # logicalLocations may be empty for global findings, but if present
            # must have a `name`.
            for ll in loc.get("logicalLocations", []):
                assert "name" in ll

    def test_run_properties_carry_score_and_grade(self):
        props = self.sarif["runs"][0]["properties"]["ciguard"]
        assert "risk_score" in props
        assert "grade" in props
        assert props["platform"] == "github-actions"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestSARIFEdgeCases:
    def test_empty_report_has_zero_results(self):
        # Good_pipeline.yml produces zero findings — the SARIF output should
        # still be valid (empty results array, empty rules array).
        p = GitLabCIParser().parse_file(FIXTURES / "good_pipeline.yml")
        report = AnalysisEngine().analyse(p, "good_pipeline.yml")
        sarif = json.loads(SARIFReporter().render(report))
        run = sarif["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []

    def test_severity_level_critical_maps_to_error(self):
        from ciguard.models.pipeline import (
            Category, ComplianceMapping, Finding, Pipeline, Report,
            RiskScore, Severity,
        )
        finding = Finding(
            id="X-001-001",
            rule_id="X-001",
            name="Test",
            description="Test",
            severity=Severity.CRITICAL,
            category=Category.PIPELINE_INTEGRITY,
            location="x",
            evidence="x",
            remediation="x",
            compliance=ComplianceMapping(),
        )
        rs = RiskScore(
            overall=50, pipeline_integrity=50, identity_access=100,
            runner_security=100, artifact_handling=100, deployment_governance=100,
            supply_chain=100, grade="F",
        )
        report = Report(
            pipeline_name="x.yml", findings=[finding], risk_score=rs,
            pipeline=Pipeline(),
        )
        sarif = json.loads(SARIFReporter().render(report))
        assert sarif["runs"][0]["results"][0]["level"] == "error"
        assert sarif["runs"][0]["results"][0]["properties"]["security-severity"] == "9.5"
