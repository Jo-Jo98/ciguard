"""
Tests for the v0.5 baseline / delta machinery.

Covers:
  - Finding fingerprint stability (line numbers, evidence whitespace)
  - Baseline write + read round-trip
  - Delta calculation: new / resolved / unchanged classification
  - Delta.new_at_or_above severity threshold logic
  - Engine.scanner_version is populated on every report
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.baseline import (
    BASELINE_FORMAT_VERSION,
    compute_delta,
    default_baseline_path,
    load_baseline,
    write_baseline,
)
from ciguard.analyzer.engine import AnalysisEngine
from ciguard.models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Severity,
    _compute_finding_fingerprint,
)
from ciguard.parser.gitlab_parser import GitLabCIParser


FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_same_inputs_produce_same_fingerprint(self):
        fp1 = _compute_finding_fingerprint("PIPE-001", "job[build]", "image: alpine:latest")
        fp2 = _compute_finding_fingerprint("PIPE-001", "job[build]", "image: alpine:latest")
        assert fp1 == fp2

    def test_line_number_drift_does_not_change_fingerprint(self):
        # Two scans of the same pipeline after a code shuffle that moves
        # the offending line — should hash to the same fingerprint.
        fp1 = _compute_finding_fingerprint("PIPE-003", "stage[Build].steps:5", "curl http://x|bash")
        fp2 = _compute_finding_fingerprint("PIPE-003", "stage[Build].steps:127", "curl http://x|bash")
        assert fp1 == fp2

    def test_evidence_whitespace_normalised(self):
        fp1 = _compute_finding_fingerprint("PIPE-001", "global", "image: alpine:latest")
        fp2 = _compute_finding_fingerprint("PIPE-001", "global", "  image:   alpine:latest  ")
        assert fp1 == fp2

    def test_evidence_case_insensitive(self):
        fp1 = _compute_finding_fingerprint("PIPE-001", "global", "image: ALPINE:LATEST")
        fp2 = _compute_finding_fingerprint("PIPE-001", "global", "image: alpine:latest")
        assert fp1 == fp2

    def test_different_rule_id_changes_fingerprint(self):
        fp1 = _compute_finding_fingerprint("PIPE-001", "global", "image: alpine:latest")
        fp2 = _compute_finding_fingerprint("PIPE-002", "global", "image: alpine:latest")
        assert fp1 != fp2

    def test_different_location_changes_fingerprint(self):
        fp1 = _compute_finding_fingerprint("PIPE-001", "job[build]", "image: alpine:latest")
        fp2 = _compute_finding_fingerprint("PIPE-001", "job[deploy]", "image: alpine:latest")
        assert fp1 != fp2

    def test_finding_exposes_fingerprint_property(self):
        f = Finding(
            id="PIPE-001-001",
            rule_id="PIPE-001",
            name="Unpinned image",
            description="x",
            severity=Severity.HIGH,
            category=Category.PIPELINE_INTEGRITY,
            location="global",
            evidence="image: alpine:latest",
            remediation="pin it",
            compliance=ComplianceMapping(),
        )
        assert f.fingerprint == _compute_finding_fingerprint(
            "PIPE-001", "global", "image: alpine:latest"
        )

    def test_fingerprint_is_serialised(self):
        # @computed_field — must appear in JSON output of the model
        f = Finding(
            id="x", rule_id="PIPE-001", name="x", description="x",
            severity=Severity.HIGH, category=Category.PIPELINE_INTEGRITY,
            location="global", evidence="image: alpine:latest",
            remediation="x", compliance=ComplianceMapping(),
        )
        data = f.model_dump(mode="json")
        assert "fingerprint" in data
        assert data["fingerprint"] == f.fingerprint


# ---------------------------------------------------------------------------
# Baseline I/O round-trip
# ---------------------------------------------------------------------------

class TestBaselineRoundTrip:
    def setup_method(self):
        parser = GitLabCIParser()
        engine = AnalysisEngine()
        pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        self.report = engine.analyse(pipeline, pipeline_name="bad_pipeline.yml")

    def test_write_and_read_baseline(self, tmp_path):
        out = tmp_path / "baseline.json"
        write_baseline(self.report, out)
        assert out.exists()
        data = load_baseline(out)
        assert data["format_version"] == BASELINE_FORMAT_VERSION
        assert data["pipeline_name"] == "bad_pipeline.yml"
        assert data["platform"] == "gitlab-ci"
        assert len(data["findings"]) == len(self.report.findings)

    def test_baseline_records_scanner_version(self, tmp_path):
        out = tmp_path / "baseline.json"
        write_baseline(self.report, out)
        data = load_baseline(out)
        # Whatever version is installed, it should be recorded.
        assert data["scanner_version"]
        assert isinstance(data["scanner_version"], str)

    def test_load_baseline_rejects_future_format(self, tmp_path):
        out = tmp_path / "baseline.json"
        out.write_text(json.dumps({"format_version": 99, "findings": []}))
        try:
            load_baseline(out)
        except ValueError as e:
            assert "newer ciguard" in str(e)
        else:
            raise AssertionError("Expected ValueError for future format_version")

    def test_default_baseline_path(self, tmp_path):
        pipeline_file = tmp_path / "ci.yml"
        pipeline_file.write_text("stages: [build]\n")
        path = default_baseline_path(pipeline_file)
        assert path.name == "baseline.json"
        assert path.parent.name == ".ciguard"


# ---------------------------------------------------------------------------
# Delta calculation
# ---------------------------------------------------------------------------

class TestDelta:
    def setup_method(self):
        parser = GitLabCIParser()
        engine = AnalysisEngine()
        pipeline = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        self.report = engine.analyse(pipeline, pipeline_name="bad_pipeline.yml")

    def test_identical_scan_against_own_baseline_has_no_changes(self, tmp_path):
        out = tmp_path / "baseline.json"
        write_baseline(self.report, out)
        baseline_data = load_baseline(out)
        delta = compute_delta(self.report, baseline_data, out)
        assert len(delta.new) == 0
        assert len(delta.resolved) == 0
        assert len(delta.unchanged) == len(self.report.findings)
        assert delta.score_delta == 0.0
        assert delta.has_regressions is False

    def test_empty_baseline_marks_everything_new(self, tmp_path):
        out = tmp_path / "empty-baseline.json"
        out.write_text(json.dumps({
            "format_version": 1,
            "scanner_version": "0.5.0",
            "scan_timestamp": "2026-04-25T00:00:00",
            "pipeline_name": "x",
            "platform": "gitlab-ci",
            "overall_score": 100.0,
            "grade": "A",
            "findings": [],
        }))
        baseline_data = load_baseline(out)
        delta = compute_delta(self.report, baseline_data, out)
        assert len(delta.new) == len(self.report.findings)
        assert len(delta.resolved) == 0
        assert len(delta.unchanged) == 0
        assert delta.has_regressions is True

    def test_baseline_with_no_current_findings_marks_everything_resolved(self, tmp_path):
        # Baseline has the bad-pipeline findings; current report is the
        # good-pipeline report with zero findings.
        out = tmp_path / "baseline.json"
        write_baseline(self.report, out)
        baseline_data = load_baseline(out)

        clean_pipeline = GitLabCIParser().parse_file(FIXTURES / "good_pipeline.yml")
        clean_report = AnalysisEngine().analyse(clean_pipeline, pipeline_name="good_pipeline.yml")
        delta = compute_delta(clean_report, baseline_data, out)
        assert len(delta.new) == 0
        assert len(delta.resolved) == len(self.report.findings)
        assert len(delta.unchanged) == 0
        assert delta.score_delta > 0  # going from F to A is a positive change
        assert delta.has_regressions is False

    def test_new_at_or_above_threshold(self, tmp_path):
        # Baseline = empty → all findings are 'new'. Threshold = High → only
        # Critical + High findings should match.
        out = tmp_path / "empty.json"
        out.write_text(json.dumps({
            "format_version": 1, "scanner_version": "0.5.0",
            "scan_timestamp": "2026-04-25T00:00:00",
            "pipeline_name": "x", "platform": "gitlab-ci",
            "overall_score": 100.0, "grade": "A", "findings": [],
        }))
        delta = compute_delta(self.report, load_baseline(out), out)

        critical_or_above = delta.new_at_or_above(Severity.CRITICAL)
        high_or_above = delta.new_at_or_above(Severity.HIGH)
        info_or_above = delta.new_at_or_above(Severity.INFO)

        assert all(f.severity == Severity.CRITICAL for f in critical_or_above)
        assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in high_or_above)
        assert len(info_or_above) == len(delta.new)  # everything counts at INFO
        assert len(critical_or_above) <= len(high_or_above) <= len(info_or_above)


# ---------------------------------------------------------------------------
# Engine populates scanner_version
# ---------------------------------------------------------------------------

class TestEngineScannerVersion:
    def test_gitlab_report_has_scanner_version(self):
        pipeline = GitLabCIParser().parse_file(FIXTURES / "good_pipeline.yml")
        report = AnalysisEngine().analyse(pipeline, pipeline_name="good")
        assert report.scanner_version  # any non-empty string
