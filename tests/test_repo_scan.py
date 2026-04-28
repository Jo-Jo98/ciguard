"""Tests for the v0.9.0 `scan_repo()` helper and `ciguard scan-repo` CLI."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.repo_scan import SEVERITY_ORDER, scan_repo


# ---- Fixture builders ------------------------------------------------------

_BAD_GITLAB = """stages: [build, deploy]

build_job:
  image: alpine
  script:
    - apk add curl
    - curl http://example.com/install.sh | sh

deploy_prod:
  image: alpine
  stage: deploy
  script:
    - echo "deploying"
  environment:
    name: production
"""

_GOOD_GITLAB = """stages: [build]

build_job:
  image: alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
  script:
    - echo "hi"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
"""

_GHA_WORKFLOW = """name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
"""


def _make_mixed_repo(root: Path) -> None:
    (root / ".gitlab-ci.yml").write_text(_BAD_GITLAB)
    (root / "subproj").mkdir()
    (root / "subproj" / ".gitlab-ci.yml").write_text(_GOOD_GITLAB)
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(_GHA_WORKFLOW)


# ---- scan_repo() helper ----------------------------------------------------


class TestScanRepoHelper:
    def test_empty_repo_returns_zero_files(self, tmp_path):
        result = scan_repo(tmp_path, offline=True)
        assert result["files_scanned"] == 0
        assert result["total_findings"] == 0
        assert result["files"] == []
        assert result["fails_threshold"] is False

    def test_missing_path_returns_error(self, tmp_path):
        result = scan_repo(tmp_path / "does-not-exist", offline=True)
        assert "error" in result

    def test_mixed_repo_discovers_and_scans_each(self, tmp_path):
        _make_mixed_repo(tmp_path)
        result = scan_repo(tmp_path, offline=True)
        assert result["files_scanned"] == 3
        platforms = {f["platform"] for f in result["files"]}
        assert platforms == {"gitlab-ci", "github-actions"}
        # Aggregate counts must add up to per-file counts
        agg_total = result["total_findings"]
        per_file_total = sum(f.get("findings_total", 0) for f in result["files"])
        assert agg_total == per_file_total

    def test_fail_on_high_breaches_when_high_findings_exist(self, tmp_path):
        _make_mixed_repo(tmp_path)
        result = scan_repo(tmp_path, offline=True, fail_on="High")
        # The bad GitLab pipeline emits High-severity findings (unpinned image
        # + curl-pipe-sh). If this assertion ever fails it means rule severities
        # changed — re-tune the fixture, don't loosen the test.
        assert result["fails_threshold"] is True
        assert result["fail_on"] == "High"

    def test_fail_on_critical_does_not_breach_on_clean_repo(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(_GHA_WORKFLOW)
        result = scan_repo(tmp_path, offline=True, fail_on="Critical")
        # Even if Medium/Low findings exist, fail-on=Critical only breaches on Critical.
        crit_count = result["by_severity"].get("Critical", 0)
        assert result["fails_threshold"] == (crit_count > 0)

    def test_severity_order_constant_is_canonical(self):
        # Sanity: SEVERITY_ORDER drives the threshold logic. Lock the order.
        assert SEVERITY_ORDER == ["Critical", "High", "Medium", "Low", "Info"]


# ---- CLI integration -------------------------------------------------------


class TestScanRepoCLI:
    def _run(self, *args, cwd=None):
        cmd = [sys.executable, "-m", "ciguard.main", "scan-repo", *args]
        return subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd,
        )

    def test_cli_prints_summary_for_mixed_repo(self, tmp_path):
        _make_mixed_repo(tmp_path)
        result = self._run(str(tmp_path), "--offline")
        assert result.returncode == 0, result.stderr
        assert "ciguard Repo Scan" in result.stdout
        assert "pipeline file(s) discovered" in result.stdout

    def test_cli_fail_on_high_exits_one(self, tmp_path):
        _make_mixed_repo(tmp_path)
        result = self._run(str(tmp_path), "--offline", "--fail-on", "High")
        assert result.returncode == 1
        assert "FAIL" in result.stdout

    def test_cli_fail_on_none_returns_zero_even_with_findings(self, tmp_path):
        _make_mixed_repo(tmp_path)
        result = self._run(str(tmp_path), "--offline", "--fail-on", "none")
        assert result.returncode == 0

    def test_cli_writes_aggregate_json(self, tmp_path):
        _make_mixed_repo(tmp_path)
        out = tmp_path / "result.json"
        result = self._run(str(tmp_path), "--offline", "--output", str(out))
        assert result.returncode == 0, result.stderr
        assert out.exists()
        payload = json.loads(out.read_text())
        assert payload["files_scanned"] == 3
        assert "by_severity" in payload
        assert "files" in payload

    def test_cli_missing_path_exits_two(self, tmp_path):
        result = self._run(str(tmp_path / "no-such-dir"))
        assert result.returncode == 2
        assert "Path not found" in result.stderr

    def test_cli_empty_repo_exits_zero(self, tmp_path):
        result = self._run(str(tmp_path), "--offline")
        assert result.returncode == 0
        assert "No pipeline files discovered" in result.stdout
