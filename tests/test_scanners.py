"""
Tests for ciguard scanner integrations.

Since external tools (semgrep, scorecard) may not be installed in CI,
we test:
  - is_available() returns bool without crashing
  - scan() returns [] gracefully when tool not present
  - GitLab native scanner (pure Python) works correctly
  - Runner discovers and runs available scanners
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.scanners.base import ScannerFinding
from ciguard.scanners.gitlab_native import GitLabNativeScanner
from ciguard.scanners.runner import available_scanners, run_all_scanners
from ciguard.scanners.scorecard import ScorecardScanner
from ciguard.scanners.semgrep import SemgrepScanner

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Base / structural tests
# ---------------------------------------------------------------------------

class TestScannerBase:
    def test_semgrep_availability_returns_bool(self):
        scanner = SemgrepScanner()
        result = scanner.is_available()
        assert isinstance(result, bool)

    def test_scorecard_availability_returns_bool(self):
        scanner = ScorecardScanner()
        result = scanner.is_available()
        assert isinstance(result, bool)

    def test_gitlab_native_always_available(self):
        scanner = GitLabNativeScanner()
        assert scanner.is_available() is True

    def test_scanner_names(self):
        assert SemgrepScanner().name == "semgrep"
        assert ScorecardScanner().name == "scorecard"
        assert GitLabNativeScanner().name == "gitlab-native"

    def test_available_scanners_returns_list(self):
        result = available_scanners()
        assert isinstance(result, list)
        # gitlab-native is always available
        assert "gitlab-native" in result


# ---------------------------------------------------------------------------
# Graceful degradation when tools not installed
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    def test_semgrep_scan_returns_empty_when_unavailable(self, tmp_path):
        scanner = SemgrepScanner()
        if scanner.is_available():
            pytest.skip("semgrep is installed — skipping degradation test")
        results = scanner.scan(tmp_path / "nonexistent.yml")
        assert results == []

    def test_scorecard_scan_returns_empty_when_unavailable(self, tmp_path):
        scanner = ScorecardScanner()
        if scanner.is_available():
            pytest.skip("scorecard is installed — skipping degradation test")
        results = scanner.scan(tmp_path)
        assert results == []

    def test_run_all_scanners_returns_list(self):
        """run_all_scanners must always return a list, never raise."""
        results = run_all_scanners(FIXTURES / "bad_pipeline.yml")
        assert isinstance(results, list)

    def test_run_all_scanners_on_nonexistent_path(self, tmp_path):
        """Scanners should not crash on non-existent path."""
        results = run_all_scanners(tmp_path / "does_not_exist.yml")
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# GitLab native scanner (pure Python — always testable)
# ---------------------------------------------------------------------------

class TestGitLabNativeScanner:
    def setup_method(self):
        self.scanner = GitLabNativeScanner()

    def _make_report(self, tmp_path, vulns):
        """Create a fake GitLab security report JSON."""
        data = {
            "scan": {
                "scanner": {"name": "Test Scanner"},
                "type": "sast",
            },
            "vulnerabilities": vulns,
        }
        report = tmp_path / "gl-sast-report.json"
        report.write_text(json.dumps(data), encoding="utf-8")
        return report

    def test_non_gitlab_json_returns_empty(self, tmp_path):
        f = tmp_path / "random.json"
        f.write_text('{"hello": "world"}', encoding="utf-8")
        assert self.scanner.scan(f) == []

    def test_non_json_file_returns_empty(self, tmp_path):
        f = tmp_path / "pipeline.yml"
        f.write_text("stages: [test]", encoding="utf-8")
        assert self.scanner.scan(f) == []

    def test_empty_vulnerabilities(self, tmp_path):
        report = self._make_report(tmp_path, [])
        results = self.scanner.scan(report)
        assert results == []

    def test_parses_critical_vulnerability(self, tmp_path):
        report = self._make_report(tmp_path, [{
            "id": "VULN-001",
            "name": "SQL Injection",
            "description": "Untrusted input used in SQL query",
            "severity": "Critical",
            "location": {"file": "app/db.py", "start_line": 42},
            "solution": "Use parameterised queries",
            "identifiers": [{"type": "cve", "name": "CVE-2024-0001", "value": "CVE-2024-0001"}],
        }])
        results = self.scanner.scan(report)
        assert len(results) == 1
        assert results[0].severity == "Critical"
        assert results[0].name == "SQL Injection"
        assert results[0].location == "app/db.py:42"

    def test_severity_mapping(self, tmp_path):
        severities = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "unknown": "Info",
            "negligible": "Info",
        }
        vulns = [
            {"id": f"V{i}", "name": f"Vuln {sev}", "severity": sev,
             "location": {"file": "test.py"}, "identifiers": []}
            for i, sev in enumerate(severities)
        ]
        report = self._make_report(tmp_path, vulns)
        results = self.scanner.scan(report)
        for r in results:
            sev_input = r.name.split(" ")[-1].lower()
            assert r.severity == severities[sev_input]

    def test_scanner_attribution(self, tmp_path):
        report = self._make_report(tmp_path, [{
            "id": "V1", "name": "Test", "severity": "High",
            "location": {"file": "x.py"}, "identifiers": [],
        }])
        results = self.scanner.scan(report)
        assert "gitlab-native" in results[0].scanner

    def test_scans_directory_for_gl_reports(self, tmp_path):
        """Passing a directory scans all gl-*-report.json files."""
        self._make_report(tmp_path, [{
            "id": "V1", "name": "Issue 1", "severity": "High",
            "location": {"file": "a.py"}, "identifiers": [],
        }])
        # Also create a non-matching JSON
        (tmp_path / "other.json").write_text('{"x": 1}', encoding="utf-8")

        results = self.scanner.scan(tmp_path)
        assert len(results) == 1

    def test_finding_model_fields(self, tmp_path):
        report = self._make_report(tmp_path, [{
            "id": "V1", "name": "XSS", "severity": "medium",
            "description": "Cross-site scripting",
            "location": {"file": "views.py", "start_line": 10},
            "solution": "Escape output",
            "identifiers": [{"type": "cwe", "name": "CWE-79", "value": "CWE-79"}],
        }])
        results = self.scanner.scan(report)
        r = results[0]
        assert isinstance(r, ScannerFinding)
        assert r.scanner
        assert r.rule_id
        assert r.name
        assert r.severity == "Medium"
        assert r.location
