"""
Tests for the GitLab CI parser and rule engine.

Run with: pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path


# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.models.pipeline import Severity
from ciguard.parser.gitlab_parser import GitLabCIParser

FIXTURES = Path(__file__).parent / "fixtures"

parser = GitLabCIParser()
engine = AnalysisEngine(enable_sca=False)


# ---------------------------------------------------------------------------
# Parser smoke tests
# ---------------------------------------------------------------------------

class TestParser:
    def test_parse_bad_pipeline(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        assert len(p.jobs) > 0
        assert "deploy_prod" in [j.name for j in p.jobs]

    def test_parse_good_pipeline(self):
        p = parser.parse_file(FIXTURES / "good_pipeline.yml")
        assert len(p.jobs) >= 8
        assert p.image is not None
        assert "@sha256:" in p.image  # Pinned

    def test_parse_typical_pipeline(self):
        p = parser.parse_file(FIXTURES / "typical_pipeline.yml")
        stages = p.stages
        assert "test" in stages
        assert "deploy-prod" in [j.name for j in p.jobs]

    def test_parse_complex_pipeline(self):
        p = parser.parse_file(FIXTURES / "complex_pipeline.yml")
        # Should have multiple stages
        assert len(p.stages) >= 8
        # Should have includes
        assert len(p.includes) >= 2
        # Should have matrix job
        unit_test = next((j for j in p.jobs if j.name == "unit-test"), None)
        assert unit_test is not None

    def test_job_scripts_are_lists(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        for job in p.jobs:
            assert isinstance(job.script, list)
            assert isinstance(job.before_script, list)
            assert isinstance(job.after_script, list)

    def test_environment_parsing(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        deploy = next(j for j in p.jobs if j.name == "deploy_prod")
        assert deploy.environment is not None
        assert deploy.environment.name == "production"

    def test_artifact_parsing(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        build = next(j for j in p.jobs if j.name == "build")
        assert build.artifacts is not None
        assert "**/*" in build.artifacts.paths
        assert build.artifacts.expire_in is None

    def test_includes_parsing(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        assert len(p.includes) > 0
        # Should detect the remote include
        remote_includes = [i for i in p.includes if "remote" in i]
        assert len(remote_includes) > 0

    def test_variables_parsing(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        assert "DB_PASSWORD" in p.variables
        assert "AWS_ACCESS_KEY_ID" in p.variables

    def test_iam_001_no_false_positive_on_path_variables(self, tmp_path):
        """IAM-001 must not fire on `*_PATH` variables.

        Regression: `pat` (Personal Access Token) was a substring in the
        secret-key regex; every CI variable ending in `_PATH` matched
        because `PAT` is a substring of `PATH`. Caught by Phase A
        corpus validation against gitlab-org/gitlab (17/17 false positives).
        """
        yml = tmp_path / "paths.yml"
        yml.write_text(
            "stages: [test]\n"
            "variables:\n"
            "  RSPEC_PROFILING_FOLDER_PATH: \"rspec/profiling\"\n"
            "  GLCI_PREDICTIVE_MAPPING_PATH: \"crystalball/mapping.json\"\n"
            "  TEST_PATTERN: \"spec/**/*_spec.rb\"\n"
            "  PATCH_LEVEL: \"1.2.3\"\n"
            "test_job:\n"
            "  stage: test\n"
            "  script: [echo hi]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "paths.yml")
        iam_001 = [f for f in report.findings if f.rule_id == "IAM-001"]
        assert iam_001 == [], (
            f"IAM-001 fired on PATH/PATTERN/PATCH variables (false positive): "
            f"{[f.evidence for f in iam_001]}"
        )

    def test_pipe_004_no_false_positive_on_release_build(self, tmp_path):
        """PIPE-004 must not fire on `*release-build`, `*test`, `notify-*` jobs.

        Regression: name-only deploy heuristic substring-matched
        `release`/`publish` even when the job was clearly a build/test/notify.
        Caught by Phase A corpus on graphviz, fdroid, gitlab-org/cli.
        """
        yml = tmp_path / "build_jobs.yml"
        yml.write_text(
            "stages: [build, test]\n"
            "windows-cmake-x64-release-build:\n"
            "  stage: build\n"
            "  script: [cmake --build .]\n"
            "assembleRelease test:\n"
            "  stage: test\n"
            "  script: [./gradlew test]\n"
            "notify-issues-on-release:\n"
            "  stage: test\n"
            "  script: [echo done]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "build_jobs.yml")
        pipe_004 = [f for f in report.findings if f.rule_id == "PIPE-004"]
        assert pipe_004 == [], f"PIPE-004 false-positives on build/test/notify jobs: {[f.location for f in pipe_004]}"

    def test_pipe_004_skips_hidden_templates(self, tmp_path):
        """PIPE-004 must not fire on hidden `.template` jobs (extends anchors)."""
        yml = tmp_path / "templates.yml"
        yml.write_text(
            "stages: [deploy]\n"
            ".docker_publish_template:\n"
            "  stage: deploy\n"
            "  script: [docker push myimage]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "templates.yml")
        pipe_004 = [f for f in report.findings if f.rule_id == "PIPE-004"]
        assert pipe_004 == [], f"PIPE-004 fired on hidden template: {[f.location for f in pipe_004]}"

    def test_run_003_no_false_positive_on_untagged_build_jobs(self, tmp_path):
        """RUN-003 must not fire on plain untagged build/test jobs.

        Regression: rule fired on every untagged job, producing 10/10 FPs on
        `good_pipeline.yml`. Now restricted to sensitive jobs (deploys,
        prod-targeting, secret-handling).
        """
        yml = tmp_path / "untagged.yml"
        yml.write_text(
            "stages: [build, test]\n"
            "build_app:\n"
            "  stage: build\n"
            "  script: [npm run build]\n"
            "unit_tests:\n"
            "  stage: test\n"
            "  script: [npm test]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "untagged.yml")
        run_003 = [f for f in report.findings if f.rule_id == "RUN-003"]
        assert run_003 == [], f"RUN-003 fired on plain build/test jobs: {[f.location for f in run_003]}"

    def test_run_003_still_catches_untagged_sensitive_jobs(self, tmp_path):
        """RUN-003 must still fire on untagged jobs that deploy/handle secrets."""
        yml = tmp_path / "sensitive_untagged.yml"
        yml.write_text(
            "stages: [deploy]\n"
            "deploy_to_prod:\n"
            "  stage: deploy\n"
            "  environment:\n"
            "    name: production\n"
            "  script: [./deploy.sh]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "sensitive_untagged.yml")
        run_003 = [f for f in report.findings if f.rule_id == "RUN-003"]
        assert run_003, "RUN-003 should fire on untagged production-deploy job"

    def test_pipe_004_still_catches_real_unprotected_deploys(self, tmp_path):
        """Sanity: heuristic tightening must not break detection of real unprotected deploys."""
        yml = tmp_path / "real_deploys.yml"
        yml.write_text(
            "stages: [deploy]\n"
            "deploy_nightly:\n"
            "  stage: deploy\n"
            "  script: [./deploy.sh]\n"
            "publish_to_npm:\n"
            "  stage: deploy\n"
            "  script: [npm publish]\n"
            "docker_push_prod:\n"
            "  stage: deploy\n"
            "  script: [docker push prod]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "real_deploys.yml")
        pipe_004 = {f.location for f in report.findings if f.rule_id == "PIPE-004"}
        assert {"deploy_nightly", "publish_to_npm", "docker_push_prod"} <= pipe_004, (
            f"PIPE-004 missed real unprotected deploys; got {pipe_004}"
        )

    def test_iam_001_still_catches_real_secrets(self, tmp_path):
        """Sanity: removing `pat` must not weaken detection of real secrets."""
        yml = tmp_path / "secrets.yml"
        yml.write_text(
            "stages: [test]\n"
            "variables:\n"
            "  DB_PASSWORD: \"hunter2hunter2\"\n"
            "  API_TOKEN: \"abc123def456ghi\"\n"
            "  MY_SECRET: \"longenoughvalue\"\n"
            "test_job:\n"
            "  stage: test\n"
            "  script: [echo hi]\n"
        )
        p = parser.parse_file(yml)
        report = engine.analyse(p, "secrets.yml")
        iam_001 = [f for f in report.findings if f.rule_id == "IAM-001"]
        flagged = {f.evidence.split(":")[0].strip() for f in iam_001}
        assert {"DB_PASSWORD", "API_TOKEN", "MY_SECRET"} <= flagged, (
            f"Expected DB_PASSWORD, API_TOKEN, MY_SECRET to fire IAM-001; got {flagged}"
        )

    def test_reference_tag_does_not_crash(self, tmp_path):
        """GitLab `!reference` must parse without error; analysis must still run.

        Real-world repros: gitlab-org/cli, wireshark/wireshark,
        freedesktop-sdk/freedesktop-sdk all failed Phase A corpus validation
        on this tag before the SafeLoader subclass was added.
        """
        yml = tmp_path / "with_reference.yml"
        yml.write_text(
            "stages: [test]\n"
            ".snippet:\n"
            "  script:\n"
            "    - echo hello\n"
            "job1:\n"
            "  stage: test\n"
            "  script:\n"
            "    - echo start\n"
            "    - !reference [.snippet, script]\n"
        )
        p = parser.parse_file(yml)
        assert len(p.jobs) >= 1
        scripts = [s for j in p.jobs for s in j.script]
        # the !reference target is preserved as an opaque marker
        assert any("<<reference: .snippet.script>>" in s for s in scripts)
        # engine must still run cleanly
        engine.analyse(p, "with_reference.yml")


# ---------------------------------------------------------------------------
# Rule engine: bad pipeline (should find many issues)
# ---------------------------------------------------------------------------

class TestBadPipeline:
    def setup_method(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        self.report = engine.analyse(p, "bad_pipeline.yml")

    def test_finds_multiple_issues(self):
        assert len(self.report.findings) >= 10, (
            f"Expected at least 10 findings, got {len(self.report.findings)}: "
            + ", ".join(f.rule_id for f in self.report.findings)
        )

    def test_has_critical_findings(self):
        crits = self.report.findings_by_severity(Severity.CRITICAL)
        assert len(crits) >= 3, (
            f"Expected at least 3 Critical findings, got {len(crits)}"
        )

    def test_detects_unpinned_images(self):
        pipe_001 = [f for f in self.report.findings if f.rule_id == "PIPE-001"]
        assert len(pipe_001) >= 2, "Should flag multiple :latest images"

    def test_detects_hardcoded_secrets(self):
        iam_001 = [f for f in self.report.findings if f.rule_id == "IAM-001"]
        assert len(iam_001) >= 2, "Should flag hardcoded DB_PASSWORD and AWS key"

    def test_detects_curl_pipe_bash(self):
        pipe_003 = [f for f in self.report.findings if f.rule_id == "PIPE-003"]
        assert len(pipe_003) >= 1, "Should flag curl|bash"

    def test_detects_dind(self):
        run_002 = [f for f in self.report.findings if f.rule_id == "RUN-002"]
        assert len(run_002) >= 1, "Should flag docker:dind"

    def test_detects_shared_runner(self):
        run_003 = [f for f in self.report.findings if f.rule_id == "RUN-003"]
        assert len(run_003) >= 1, "Should flag shared runner tag"

    def test_detects_artifacts_without_expiry(self):
        art_001 = [f for f in self.report.findings if f.rule_id == "ART-001"]
        assert len(art_001) >= 2, "Should flag multiple artifacts without expiry"

    def test_detects_broad_artifact_paths(self):
        art_002 = [f for f in self.report.findings if f.rule_id == "ART-002"]
        assert len(art_002) >= 1, "Should flag **/* artifact path"

    def test_detects_direct_to_prod(self):
        dep_001 = [f for f in self.report.findings if f.rule_id == "DEP-001"]
        assert len(dep_001) >= 1, "Should flag deploy_prod without manual gate"

    def test_detects_remote_include(self):
        pipe_002 = [f for f in self.report.findings if f.rule_id == "PIPE-002"]
        assert len(pipe_002) >= 1, "Should flag remote include URL"

    def test_detects_no_dependency_scan(self):
        sc_003 = [f for f in self.report.findings if f.rule_id == "SC-003"]
        assert len(sc_003) >= 1, "Should flag missing dependency scan"

    def test_risk_score_is_low(self):
        # Bad pipeline should score poorly
        assert self.report.risk_score.overall < 50, (
            f"Expected risk score < 50, got {self.report.risk_score.overall}"
        )

    def test_grade_is_d_or_f(self):
        assert self.report.risk_score.grade in ("D", "F"), (
            f"Expected grade D or F, got {self.report.risk_score.grade}"
        )


# ---------------------------------------------------------------------------
# Rule engine: good pipeline (should find minimal issues)
# ---------------------------------------------------------------------------

class TestGoodPipeline:
    def setup_method(self):
        p = parser.parse_file(FIXTURES / "good_pipeline.yml")
        self.report = engine.analyse(p, "good_pipeline.yml")

    def test_no_critical_findings(self):
        crits = self.report.findings_by_severity(Severity.CRITICAL)
        assert len(crits) == 0, (
            "Expected 0 Critical findings, got: "
            + ", ".join(f"{f.rule_id}: {f.name}" for f in crits)
        )

    def test_no_high_findings(self):
        highs = self.report.findings_by_severity(Severity.HIGH)
        assert len(highs) == 0, (
            "Expected 0 High findings, got: "
            + ", ".join(f"{f.rule_id}: {f.name}" for f in highs)
        )

    def test_risk_score_is_high(self):
        assert self.report.risk_score.overall >= 80, (
            f"Expected risk score >= 80, got {self.report.risk_score.overall}"
        )

    def test_grade_is_a_or_b(self):
        assert self.report.risk_score.grade in ("A", "B"), (
            f"Expected grade A or B, got {self.report.risk_score.grade}"
        )


# ---------------------------------------------------------------------------
# Rule engine: include-only pipelines (root file is just `include:` directives)
# ---------------------------------------------------------------------------

class TestIncludeOnlyPipeline:
    """When a root .gitlab-ci.yml has 0 jobs and only `include:` directives,
    text-based global rules (SC-003) cannot reliably evaluate the included
    files — so they must not fire."""

    def setup_method(self):
        import os
        import tempfile
        import textwrap
        yaml = textwrap.dedent("""
            stages: [build, test, publish]
            include:
              - local: '.gitlab/ci/build.gitlab-ci.yml'
              - local: '.gitlab/ci/test.gitlab-ci.yml'
        """)
        fd, path = tempfile.mkstemp(suffix=".yml")
        os.write(fd, yaml.encode())
        os.close(fd)
        try:
            p = parser.parse_file(path)
            self.pipeline = p
            self.report = engine.analyse(p, "include_only.yml")
        finally:
            os.unlink(path)

    def test_zero_jobs_parsed(self):
        assert len(self.pipeline.jobs) == 0
        assert len(self.pipeline.includes) == 2

    def test_sc_003_does_not_fire(self):
        sc_003 = [f for f in self.report.findings if f.rule_id == "SC-003"]
        assert sc_003 == [], (
            "SC-003 cannot reliably evaluate include-only pipelines and must not fire"
        )


# ---------------------------------------------------------------------------
# Rule engine: typical pipeline
# ---------------------------------------------------------------------------

class TestTypicalPipeline:
    def setup_method(self):
        p = parser.parse_file(FIXTURES / "typical_pipeline.yml")
        self.report = engine.analyse(p, "typical_pipeline.yml")

    def test_has_some_findings(self):
        assert len(self.report.findings) >= 2

    def test_detects_dind(self):
        run_002 = [f for f in self.report.findings if f.rule_id == "RUN-002"]
        assert len(run_002) >= 1, "Should flag docker:dind usage"

    def test_grade_is_c_or_better(self):
        assert self.report.risk_score.grade in ("A", "B", "C"), (
            f"Typical pipeline should score C or better, got {self.report.risk_score.grade}"
        )


# ---------------------------------------------------------------------------
# Risk score mechanics
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_bad_score_lower_than_good(self):
        bad = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        good = parser.parse_file(FIXTURES / "good_pipeline.yml")
        bad_report = engine.analyse(bad)
        good_report = engine.analyse(good)
        assert bad_report.risk_score.overall < good_report.risk_score.overall

    def test_score_between_0_and_100(self):
        for fixture in FIXTURES.glob("*.yml"):
            p = parser.parse_file(fixture)
            report = engine.analyse(p, fixture.name)
            assert 0 <= report.risk_score.overall <= 100, (
                f"{fixture.name}: score {report.risk_score.overall} out of range"
            )

    def test_report_has_summary(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report = engine.analyse(p)
        assert "total" in report.summary
        assert "by_severity" in report.summary
        assert "by_category" in report.summary

    def test_sorted_findings_by_severity(self):
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report = engine.analyse(p)
        findings = report.sorted_findings()
        for i in range(len(findings) - 1):
            assert findings[i].severity_order <= findings[i + 1].severity_order


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------

class TestHTMLReporter:
    def test_html_renders(self):
        from ciguard.reporter.html_report import HTMLReporter
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report = engine.analyse(p, "bad_pipeline.yml")
        reporter = HTMLReporter()
        html = reporter.render(report)
        assert "<!DOCTYPE html>" in html
        assert "ciguard" in html
        assert "bad_pipeline.yml" in html

    def test_html_contains_findings(self):
        from ciguard.reporter.html_report import HTMLReporter
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report = engine.analyse(p, "bad_pipeline.yml")
        reporter = HTMLReporter()
        html = reporter.render(report)
        assert "PIPE-001" in html
        assert "IAM-001" in html
        assert "Critical" in html

    def test_html_is_self_contained(self):
        from ciguard.reporter.html_report import HTMLReporter
        p = parser.parse_file(FIXTURES / "bad_pipeline.yml")
        report = engine.analyse(p, "bad_pipeline.yml")
        reporter = HTMLReporter()
        html = reporter.render(report)
        # No CDN links
        assert "cdn.jsdelivr.net" not in html
        assert "cdnjs.cloudflare.com" not in html
        assert "unpkg.com" not in html


# ---------------------------------------------------------------------------
# PRD acceptance criterion 3: <3s on a 500-job pipeline
# ---------------------------------------------------------------------------

class TestPerformance:
    """Closes PRD acceptance criterion 3.

    Phase A corpus showed mean 28 ms / max 87 ms across 17 real-world
    pipelines (largest: graphviz with 94 jobs). This test extends the
    measurement to the PRD's 500-job scale with a synthetic fixture.
    """

    def _build_500_job_yaml(self) -> str:
        # Realistic mix: build/test/deploy stages, varying images, scripts,
        # artifacts, environments, tags. Includes shapes that exercise most
        # rules so the analyser actually walks finding-construction paths.
        lines = [
            "stages: [lint, build, test, security, deploy]",
            "image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "variables:",
            "  CI_REGISTRY: \"registry.example.com\"",
            "",
        ]
        # 100 lint, 100 build, 200 test, 50 security, 50 deploy = 500 jobs
        for i in range(100):
            lines += [f"lint-{i}:", "  stage: lint", "  tags: [shared-lint]",
                      "  script: [ruff check src/]"]
        for i in range(100):
            lines += [f"build-{i}:", "  stage: build", "  tags: [shared-build]",
                      "  script: [python -m build]",
                      "  artifacts:", "    paths: [dist/]", "    expire_in: 1 week"]
        for i in range(200):
            lines += [f"test-{i}:", "  stage: test", "  tags: [shared-test]",
                      "  script: [pytest tests/]"]
        for i in range(50):
            lines += [f"security-{i}:", "  stage: security", "  tags: [shared-sec]",
                      "  script: [bandit -r src/]"]
        for i in range(50):
            lines += [f"deploy-{i}:", "  stage: deploy", "  tags: [dedicated-deploy]",
                      "  environment:", f"    name: env-{i}",
                      "  when: manual",
                      f"  script: [./deploy.sh env-{i}]"]
        return "\n".join(lines) + "\n"

    def test_500_job_pipeline_under_3s(self, tmp_path):
        import time
        yml = tmp_path / "synth_500.yml"
        yml.write_text(self._build_500_job_yaml())
        # End-to-end: parse + analyse, mirroring the CLI hot path
        t0 = time.perf_counter()
        pipeline = parser.parse_file(yml)
        report = engine.analyse(pipeline, "synth_500.yml")
        elapsed = time.perf_counter() - t0
        # Sanity checks before the perf assertion
        assert len(pipeline.jobs) == 500
        assert report.risk_score is not None
        # PRD criterion 3: <3 seconds
        assert elapsed < 3.0, (
            f"500-job pipeline took {elapsed:.2f}s — PRD criterion 3 (<3s) violated"
        )
