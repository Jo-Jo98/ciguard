"""
Tests for ciguard report exporters.

Covers:
  - JSON reporter: output structure, serialisation
  - PDF reporter: requires reportlab; skips gracefully if not installed
  - CLI --format flag and --policies integration
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.policy.builtin import BUILTIN_POLICIES
from ciguard.policy.evaluator import PolicyEvaluator
from ciguard.reporter.json_report import JSONReporter

FIXTURES = Path(__file__).parent / "fixtures"
parser    = GitLabCIParser()
engine    = AnalysisEngine(enable_sca=False)
evaluator = PolicyEvaluator()


def _bad_report():
    pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
    report   = engine.analyse(pipeline, "bad_pipeline.yml")
    report.policy_report = evaluator.evaluate(BUILTIN_POLICIES, pipeline, report)
    return report


def _good_report():
    pipeline = parser.parse_file(FIXTURES / "good_pipeline.yml")
    report   = engine.analyse(pipeline, "good_pipeline.yml")
    report.policy_report = evaluator.evaluate(BUILTIN_POLICIES, pipeline, report)
    return report


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

class TestJSONReporter:
    def setup_method(self):
        self.reporter = JSONReporter()
        self.bad_report  = _bad_report()
        self.good_report = _good_report()

    def test_render_returns_string(self):
        out = self.reporter.render(self.bad_report)
        assert isinstance(out, str)

    def test_valid_json(self):
        out = self.reporter.render(self.bad_report)
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_has_required_keys(self):
        data = json.loads(self.reporter.render(self.bad_report))
        for key in ("pipeline_name", "scan_timestamp", "findings",
                    "risk_score", "summary", "pipeline"):
            assert key in data, f"Missing key: {key}"

    def test_findings_serialised(self):
        data = json.loads(self.reporter.render(self.bad_report))
        assert len(data["findings"]) > 0
        f = data["findings"][0]
        for key in ("id", "rule_id", "name", "severity", "category",
                    "location", "evidence", "remediation"):
            assert key in f

    def test_risk_score_structure(self):
        data = json.loads(self.reporter.render(self.bad_report))
        rs = data["risk_score"]
        assert "overall" in rs
        assert "grade" in rs
        assert rs["grade"] in ("A", "B", "C", "D", "F")

    def test_policy_report_included(self):
        data = json.loads(self.reporter.render(self.bad_report))
        assert "policy_report" in data
        pr = data["policy_report"]
        assert "policies_evaluated" in pr
        assert "passed" in pr
        assert "failed" in pr
        assert "results" in pr

    def test_policy_results_structure(self):
        data = json.loads(self.reporter.render(self.bad_report))
        results = data["policy_report"]["results"]
        assert len(results) > 0
        r = results[0]
        assert "passed" in r
        assert "evidence" in r
        assert "policy" in r
        assert "id" in r["policy"]

    def test_write_to_file(self, tmp_path):
        output = tmp_path / "report.json"
        self.reporter.write(self.bad_report, output)
        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert "findings" in data

    def test_good_pipeline_has_fewer_findings(self):
        bad_data  = json.loads(self.reporter.render(self.bad_report))
        good_data = json.loads(self.reporter.render(self.good_report))
        assert len(bad_data["findings"]) > len(good_data["findings"])

    def test_grade_bands(self):
        bad_data  = json.loads(self.reporter.render(self.bad_report))
        good_data = json.loads(self.reporter.render(self.good_report))
        assert bad_data["risk_score"]["grade"] in ("D", "F")
        assert good_data["risk_score"]["grade"] in ("A", "B")

    def test_source_field_in_findings(self):
        data = json.loads(self.reporter.render(self.bad_report))
        for f in data["findings"]:
            assert "source" in f
            assert f["source"] == "ciguard"


# ---------------------------------------------------------------------------
# PDF reporter
# ---------------------------------------------------------------------------

class TestPDFReporter:
    @pytest.fixture(autouse=True)
    def skip_if_no_reportlab(self):
        pytest.importorskip("reportlab", reason="reportlab not installed")

    def setup_method(self):
        from ciguard.reporter.pdf_report import PDFReporter
        self.reporter = PDFReporter()

    def test_write_bad_pipeline(self, tmp_path):
        report = _bad_report()
        output = tmp_path / "report.pdf"
        self.reporter.write(report, output)
        assert output.exists()
        assert output.stat().st_size > 1000  # non-trivial PDF

    def test_write_good_pipeline(self, tmp_path):
        report = _good_report()
        output = tmp_path / "report.pdf"
        self.reporter.write(report, output)
        assert output.exists()
        assert output.stat().st_size > 1000

    def test_pdf_starts_with_pdf_magic(self, tmp_path):
        report = _bad_report()
        output = tmp_path / "report.pdf"
        self.reporter.write(report, output)
        magic = output.read_bytes()[:4]
        assert magic == b"%PDF"

    def test_write_without_policy_report(self, tmp_path):
        pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report   = engine.analyse(pipeline, "bad_pipeline.yml")
        # No policy report set
        output = tmp_path / "report.pdf"
        self.reporter.write(report, output)
        assert output.exists()

    def test_write_with_all_fixtures(self, tmp_path):
        for fixture in FIXTURES.glob("*.yml"):
            pipeline = parser.parse_file(fixture)
            report   = engine.analyse(pipeline, fixture.name)
            report.policy_report = evaluator.evaluate(BUILTIN_POLICIES, pipeline, report)
            output = tmp_path / f"{fixture.stem}.pdf"
            self.reporter.write(report, output)
            assert output.exists(), f"PDF not generated for {fixture.name}"


# ---------------------------------------------------------------------------
# Risk scoring grade bands
# ---------------------------------------------------------------------------

class TestGradeBands:
    def test_a_grade_threshold(self):
        from ciguard.models.pipeline import RiskScore
        assert RiskScore.grade_from_score(100.0) == "A"
        assert RiskScore.grade_from_score(90.0)  == "A"
        assert RiskScore.grade_from_score(89.9)  == "B"

    def test_b_grade_threshold(self):
        from ciguard.models.pipeline import RiskScore
        assert RiskScore.grade_from_score(80.0) == "B"
        assert RiskScore.grade_from_score(79.9) == "C"

    def test_c_grade_threshold(self):
        from ciguard.models.pipeline import RiskScore
        assert RiskScore.grade_from_score(70.0) == "C"
        assert RiskScore.grade_from_score(69.9) == "D"

    def test_d_grade_threshold(self):
        from ciguard.models.pipeline import RiskScore
        assert RiskScore.grade_from_score(60.0) == "D"
        assert RiskScore.grade_from_score(59.9) == "F"

    def test_f_grade_threshold(self):
        from ciguard.models.pipeline import RiskScore
        assert RiskScore.grade_from_score(0.0)  == "F"
        assert RiskScore.grade_from_score(59.9) == "F"
