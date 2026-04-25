"""
Parser-level tests for the GitHub Actions workflow parser (Slice 6 part 1).

These cover:
  - Loading the bad_actions / good_actions fixtures
  - Round-tripping the model fields we'll need for rule adaptation
    (uses refs, env, permissions, environment, container, services)
  - Format auto-detection between GitLab CI and GitHub Actions
  - The YAML 1.1 `on: True` boolean coercion gotcha

Rule firing on GHA is Slice 6 part 2 and intentionally not tested here.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.parser.github_actions import (
    GitHubActionsParser,
    detect_format,
    parse_file as auto_parse,
)
from ciguard.parser.gitlab_parser import GitLabCIParser
from ciguard.models.workflow import Workflow

FIXTURES = Path(__file__).parent / "fixtures" / "github_actions"
GITLAB_FIXTURES = Path(__file__).parent / "fixtures"
gha_parser = GitHubActionsParser()


# ---------------------------------------------------------------------------
# Bad fixture
# ---------------------------------------------------------------------------

class TestBadActionsFixture:
    def setup_method(self):
        self.wf = gha_parser.parse_file(FIXTURES / "bad_actions.yml")

    def test_parses_workflow_name(self):
        assert self.wf.name == "deploy-prod"

    def test_parses_event_triggers(self):
        # YAML 1.1 may coerce `on:` to True; parser should still surface events.
        events = self.wf.event_names()
        assert "push" in events
        assert "pull_request" in events

    def test_parses_workflow_permissions_string(self):
        assert self.wf.permissions == "write-all"

    def test_parses_top_level_env(self):
        assert "AWS_ACCESS_KEY_ID" in self.wf.env
        assert "DB_PASSWORD" in self.wf.env
        assert self.wf.env["DB_PASSWORD"] == "hunter2hunter2_demo"

    def test_jobs_count(self):
        # build / test / deploy_prod / call-shared
        assert len(self.wf.jobs) == 4

    def test_uses_refs_collected(self):
        refs = self.wf.all_action_uses()
        # Step-level uses
        assert "actions/checkout@v4" in refs
        assert "actions/setup-node@v4" in refs
        # Reusable workflow call (job-level uses)
        assert any("shared-workflows" in r for r in refs)

    def test_action_pin_sha_detection(self):
        # checkout@v4 is a tag, not a SHA — every step should report False
        build = next(j for j in self.wf.jobs if j.id == "build")
        for step in build.steps:
            if step.uses:
                assert step.action_ref_pinned_to_sha() is False

    def test_test_job_has_dind_service(self):
        test_job = next(j for j in self.wf.jobs if j.id == "test")
        assert "docker" in test_job.services
        assert test_job.services["docker"].get("image") == "docker:dind"

    def test_test_job_unpinned_container_image(self):
        test_job = next(j for j in self.wf.jobs if j.id == "test")
        # `node:latest` is the worst-case unpinned reference
        assert test_job.container_image() == "node:latest"

    def test_deploy_prod_has_no_environment_block(self):
        deploy = next(j for j in self.wf.jobs if j.id == "deploy_prod")
        assert deploy.targets_environment() is None

    def test_curl_pipe_bash_visible_in_run_lines(self):
        all_lines = self.wf.all_run_lines()
        assert any("curl" in line and "| bash" in line for line in all_lines)

    def test_reusable_workflow_call_detected(self):
        call = next(j for j in self.wf.jobs if j.id == "call-shared")
        assert call.is_reusable_workflow_call()
        assert "@main" in call.uses


# ---------------------------------------------------------------------------
# Good fixture
# ---------------------------------------------------------------------------

class TestGoodActionsFixture:
    def setup_method(self):
        self.wf = gha_parser.parse_file(FIXTURES / "good_actions.yml")

    def test_workflow_permissions_least_privilege(self):
        assert isinstance(self.wf.permissions, dict)
        assert self.wf.permissions.get("contents") == "read"

    def test_all_step_uses_pinned_to_sha(self):
        for job in self.wf.jobs:
            for step in job.steps:
                if step.uses:
                    assert step.action_ref_pinned_to_sha() is True, (
                        f"{step.uses} in job {job.id} is not SHA-pinned"
                    )

    def test_deploy_targets_environment(self):
        deploy = next(j for j in self.wf.jobs if j.id == "deploy")
        assert deploy.targets_environment() == "production"

    def test_container_pinned_to_sha_digest(self):
        build = next(j for j in self.wf.jobs if j.id == "build_image")
        assert "@sha256:" in build.container_image()


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------

class TestFormatDetection:
    def test_gitlab_ci_detected_via_stages(self):
        assert detect_format({"stages": ["build", "test"], "jobs": {}}) == "gitlab-ci"

    def test_gitlab_ci_detected_via_include(self):
        assert detect_format({"include": [{"local": "x.yml"}]}) == "gitlab-ci"

    def test_github_actions_detected_via_jobs_runs_on(self):
        data = {"on": ["push"], "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}}}
        assert detect_format(data) == "github-actions"

    def test_github_actions_detected_via_reusable_workflow_call(self):
        data = {"on": "push", "jobs": {"shared": {"uses": "org/repo/.github/workflows/x.yml@v1"}}}
        assert detect_format(data) == "github-actions"

    def test_ambiguous_defaults_to_gitlab_ci(self):
        # Bare `jobs:` without `on:` and without runs-on — keep v0.1.x behaviour.
        assert detect_format({"jobs": {"build": {"script": "echo"}}}) == "gitlab-ci"

    def test_yaml_on_boolean_coercion_handled(self):
        # YAML 1.1 turns unquoted `on:` into True. Detection must still work.
        data = {True: ["push"], "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}}}
        assert detect_format(data) == "github-actions"


class TestAutoParse:
    def test_auto_parse_dispatches_to_gha(self):
        result = auto_parse(FIXTURES / "bad_actions.yml")
        assert isinstance(result, Workflow)

    def test_auto_parse_dispatches_to_gitlab(self):
        result = auto_parse(GITLAB_FIXTURES / "bad_pipeline.yml")
        # GitLab CI parser returns a Pipeline (not a Workflow)
        from ciguard.models.pipeline import Pipeline
        assert isinstance(result, Pipeline)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_workflow_parses(self):
        wf = gha_parser.parse({"name": "empty"})
        assert wf.name == "empty"
        assert wf.jobs == []

    def test_invalid_yaml_raises_value_error(self, tmp_path):
        f = tmp_path / "invalid.yml"
        f.write_text("name: bad\n  : nope\n  - 1")
        with pytest.raises(ValueError):
            gha_parser.parse_file(f)

    def test_non_mapping_yaml_raises_value_error(self, tmp_path):
        f = tmp_path / "list.yml"
        f.write_text("- one\n- two\n")
        with pytest.raises(ValueError):
            gha_parser.parse_file(f)

    def test_oversized_file_raises_value_error(self, tmp_path):
        f = tmp_path / "huge.yml"
        f.write_bytes(b"x: y\n" * (3 * 1024 * 1024))   # ~15 MB > 10 MB limit
        with pytest.raises(ValueError, match="too large"):
            gha_parser.parse_file(f)

    def test_gitlab_parser_unaffected_by_new_module(self):
        # Sanity: the existing GitLab parser still works after the GHA module
        # is introduced (no circular import or accidental shared state).
        p = GitLabCIParser().parse_file(GITLAB_FIXTURES / "good_pipeline.yml")
        assert p.stages
