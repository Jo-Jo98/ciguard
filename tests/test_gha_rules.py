"""
GitHub Actions rule firing tests (Slice 6 part 2).

Mirror the structure of `test_parser.py::TestBadPipeline` and `TestGoodPipeline`,
applied to the bad_actions / good_actions fixtures. PRD acceptance criteria
for the GHA platform:

  - Recall on bad_actions.yml: every expected rule fires at least once
  - False positives on good_actions.yml: zero
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.analyzer.gha_rules import GHA_RULES
from ciguard.models.pipeline import Severity
from ciguard.parser.github_actions import GitHubActionsParser

FIXTURES = Path(__file__).parent / "fixtures" / "github_actions"
parser = GitHubActionsParser()
engine = AnalysisEngine(enable_sca=False)


# ---------------------------------------------------------------------------
# Bad fixture — every rule should fire at least once
# ---------------------------------------------------------------------------

class TestBadActionsFiring:
    def setup_method(self):
        wf = parser.parse_file(FIXTURES / "bad_actions.yml")
        self.report = engine.analyse(wf, pipeline_name="bad_actions.yml")
        self.fired = {f.rule_id for f in self.report.findings}

    def test_platform_set_to_github_actions(self):
        assert self.report.platform == "github-actions"

    def test_workflow_attached_to_report(self):
        assert self.report.workflow is not None
        assert len(self.report.workflow.jobs) == 5

    def test_synthetic_pipeline_for_reporters(self):
        # Reporters/web read `report.pipeline.jobs` — must be populated.
        assert len(self.report.pipeline.jobs) == 5

    def test_pipe_001_fires_on_unpinned_container(self):
        # `node:latest` on the test job
        assert "GHA-PIPE-001" in self.fired

    def test_iam_001_fires_on_hardcoded_secrets(self):
        assert "GHA-IAM-001" in self.fired

    def test_iam_004_fires_on_workflow_write_all(self):
        # `permissions: write-all` at the workflow level
        assert "GHA-IAM-004" in self.fired

    def test_run_002_fires_on_privileged_dind(self):
        # `services.docker.image: docker:dind` + `options: --privileged`
        assert "GHA-RUN-002" in self.fired

    def test_dep_001_fires_on_deploy_job_without_environment(self):
        # `deploy_prod` has no `environment:` block (and includes underscore —
        # regression against the original `\b` regex bug)
        assert "GHA-DEP-001" in self.fired

    def test_sc_001_fires_on_curl_pipe_bash(self):
        assert "GHA-SC-001" in self.fired

    def test_sc_002_fires_on_unpinned_action_refs(self):
        # `actions/checkout@v4`, `setup-node@v4`, reusable workflow @main
        assert "GHA-SC-002" in self.fired

    def test_all_twelve_gha_rules_fire(self):
        # Stronger collective check — easier to spot regressions if a single
        # rule silently stops firing.
        expected = {
            "GHA-PIPE-001",
            "GHA-PIPE-002",
            "GHA-IAM-001",
            "GHA-IAM-004",
            "GHA-IAM-006",
            "GHA-RUN-002",
            "GHA-RUN-003",
            "GHA-DEP-001",
            "GHA-SC-001",
            "GHA-SC-002",
            "GHA-SC-003",
        }
        # GHA-IAM-005 is excluded — bad_actions.yml has `permissions: write-all`
        # declared, so the "no permissions" rule cannot fire (covered by the
        # no_permissions.yml fixture below).
        missing = expected - self.fired
        assert not missing, f"GHA rules failed to fire: {missing}"

    def test_pipe_002_fires_once_for_pull_request_target(self):
        pipe_002 = [f for f in self.report.findings if f.rule_id == "GHA-PIPE-002"]
        assert len(pipe_002) == 1

    def test_iam_006_fires_once_per_unprotected_checkout(self):
        # build, test, deploy_prod each have an unprotected checkout
        iam_006 = [f for f in self.report.findings if f.rule_id == "GHA-IAM-006"]
        assert len(iam_006) >= 3

    def test_run_003_fires_on_bare_self_hosted(self):
        run_003 = [f for f in self.report.findings if f.rule_id == "GHA-RUN-003"]
        assert len(run_003) == 1
        assert "smoke-on-self-hosted" in run_003[0].location

    def test_sc_003_fires_on_inherit_secrets_unpinned_workflow(self):
        sc_003 = [f for f in self.report.findings if f.rule_id == "GHA-SC-003"]
        assert len(sc_003) == 1
        assert "call-shared" in sc_003[0].location

    def test_grade_is_d_or_f(self):
        assert self.report.risk_score.grade in ("D", "F")

    def test_critical_findings_present(self):
        assert len(self.report.findings_by_severity(Severity.CRITICAL)) >= 5


# ---------------------------------------------------------------------------
# Good fixture — zero findings expected (PRD criterion 2 for GHA)
# ---------------------------------------------------------------------------

class TestGoodActionsFiring:
    def setup_method(self):
        wf = parser.parse_file(FIXTURES / "good_actions.yml")
        self.report = engine.analyse(wf, pipeline_name="good_actions.yml")

    def test_zero_findings(self):
        assert len(self.report.findings) == 0, (
            "Expected 0 findings on good_actions.yml. Got: "
            + ", ".join(f"{f.rule_id} @ {f.location}" for f in self.report.findings)
        )

    def test_score_is_perfect(self):
        assert self.report.risk_score.overall == 100.0

    def test_grade_is_a(self):
        assert self.report.risk_score.grade == "A"


# ---------------------------------------------------------------------------
# Engine dispatcher behaviour
# ---------------------------------------------------------------------------

class TestEngineDispatch:
    def test_workflow_dispatch_runs_only_gha_rules(self):
        # Sanity: a Workflow input does not accidentally invoke GitLab rules
        # (which would crash trying to access pipeline.stages, .includes, etc.).
        wf = parser.parse_file(FIXTURES / "bad_actions.yml")
        report = engine.analyse(wf)
        for f in report.findings:
            assert f.rule_id.startswith("GHA-"), (
                f"Non-GHA rule {f.rule_id} fired against a Workflow target"
            )

    def test_pipeline_path_still_only_runs_gitlab_rules(self):
        # Sanity: GitLab CI scans don't accidentally fire GHA-* findings.
        from ciguard.parser.gitlab_parser import GitLabCIParser
        gl_parser = GitLabCIParser()
        p = gl_parser.parse_file(Path(__file__).parent / "fixtures" / "bad_pipeline.yml")
        report = engine.analyse(p)
        for f in report.findings:
            assert not f.rule_id.startswith("GHA-"), (
                f"GHA rule {f.rule_id} fired against a Pipeline target"
            )

    def test_gha_rules_registry_count(self):
        assert len(GHA_RULES) == 12


# ---------------------------------------------------------------------------
# IAM-005 has its own fixture because bad_actions.yml has `permissions: write-all`
# declared, so the "no permissions block declared" rule cannot fire there.
# ---------------------------------------------------------------------------

class TestNoPermissionsFixture:
    def setup_method(self):
        wf = parser.parse_file(FIXTURES / "no_permissions.yml")
        self.report = engine.analyse(wf, pipeline_name="no_permissions.yml")

    def test_iam_005_fires_when_no_permissions_anywhere(self):
        ids = [f.rule_id for f in self.report.findings]
        assert "GHA-IAM-005" in ids

    def test_iam_005_only_finding(self):
        # The fixture is otherwise clean — we only expect GHA-IAM-005.
        ids = {f.rule_id for f in self.report.findings}
        assert ids == {"GHA-IAM-005"}, f"Unexpected findings: {ids}"

    def test_grade_still_a(self):
        # Single High finding doesn't drop to D
        assert self.report.risk_score.grade == "A"
