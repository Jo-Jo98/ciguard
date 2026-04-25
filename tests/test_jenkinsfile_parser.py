"""
Parser-level tests for the Jenkins Declarative Pipeline parser (v0.4).

Covers:
  - Loading the bad/good Jenkinsfile fixtures into the model
  - Brace-balanced block extraction (nested stages, parallel)
  - Comment + string-literal handling (// and /* */ inside source,
    `{` inside string literals)
  - Agent / environment / steps captures
  - The Scripted-Pipeline fallback (no `pipeline {}` block)
  - The `looks_like_jenkinsfile` heuristic
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.parser.jenkinsfile import JenkinsfileParser, looks_like_jenkinsfile


FIXTURES = Path(__file__).parent / "fixtures" / "jenkins"
parser = JenkinsfileParser()


# ---------------------------------------------------------------------------
# Bad fixture
# ---------------------------------------------------------------------------

class TestBadJenkinsfile:
    def setup_method(self):
        self.jf = parser.parse_file(FIXTURES / "bad_jenkinsfile.Jenkinsfile")

    def test_top_level_agent_is_any(self):
        assert self.jf.agent is not None
        assert self.jf.agent.kind == "any"

    def test_top_level_env_has_three_bindings(self):
        keys = {b.key for b in self.jf.environment}
        assert {"API_TOKEN", "DB_PASSWORD", "GITHUB_TOKEN"} <= keys

    def test_credentials_binding_classified(self):
        gh = next(b for b in self.jf.environment if b.key == "GITHUB_TOKEN")
        assert gh.source == "credentials"
        assert gh.credential_id == "github-pat"

    def test_literal_secret_classified(self):
        tok = next(b for b in self.jf.environment if b.key == "API_TOKEN")
        assert tok.source == "literal"
        assert tok.value.startswith("AbCd")

    def test_two_stages(self):
        assert [s.name for s in self.jf.stages] == ["Build", "Deploy"]

    def test_per_stage_docker_agent_image_captured(self):
        build = self.jf.stages[0]
        assert build.agent is not None
        assert build.agent.kind == "docker"
        assert build.agent.image == "maven:latest"
        # `args` is captured (used by JKN-RUN-002 for the privileged-agent rule)
        assert build.agent.args is not None
        assert "--privileged" in build.agent.args

    def test_bare_image_no_tag_captured_as_alpine(self):
        deploy = self.jf.stages[1]
        assert deploy.agent.kind == "docker"
        assert deploy.agent.image == "alpine"

    def test_sh_step_bodies_captured(self):
        scripts = [body for _, body in self.jf.all_step_scripts()]
        assert any("curl -sSL" in s for s in scripts)
        assert any("eval" in s for s in scripts)
        assert any("wget -O -" in s for s in scripts)


# ---------------------------------------------------------------------------
# Good fixture
# ---------------------------------------------------------------------------

class TestGoodJenkinsfile:
    def setup_method(self):
        self.jf = parser.parse_file(FIXTURES / "good_jenkinsfile.Jenkinsfile")

    def test_label_agent(self):
        assert self.jf.agent.kind == "label"
        assert self.jf.agent.label == "build-trusted"

    def test_all_secret_envs_use_credentials(self):
        for b in self.jf.environment:
            if "TOKEN" in b.key or "PASSWORD" in b.key:
                assert b.source == "credentials", f"{b.key} should use credentials()"

    def test_non_secret_literal_kept(self):
        be = next(b for b in self.jf.environment if b.key == "BUILD_ENV")
        assert be.source == "literal"
        assert be.value == "production"

    def test_docker_image_sha_pinned(self):
        build = self.jf.stages[0]
        assert "@sha256:" in build.agent.image


# ---------------------------------------------------------------------------
# Edge-case parsing
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_scripted_pipeline_falls_back(self):
        scripted = "node('master') {\n    sh 'echo hi'\n}\n"
        jf = parser.parse(scripted)
        assert jf.is_scripted is True
        assert jf.parse_warnings, "should surface a warning"
        assert jf.stages == []

    def test_braces_in_strings_dont_break_block_extraction(self):
        src = """
        pipeline {
            agent any
            stages {
                stage('Build') {
                    steps {
                        sh 'echo "{ this is not a real brace }"'
                    }
                }
            }
        }
        """
        jf = parser.parse(src)
        assert len(jf.stages) == 1
        scripts = jf.all_step_scripts()
        assert scripts and "{ this is not a real brace }" in scripts[0][1]

    def test_line_and_block_comments_stripped(self):
        src = """
        // top-level comment
        pipeline {
            /* block
               comment */
            agent any
            stages {
                stage('A') { steps { sh 'true' } }
            }
        }
        """
        jf = parser.parse(src)
        assert jf.agent.kind == "any"
        assert jf.stages[0].name == "A"

    def test_parallel_stages_captured(self):
        src = """
        pipeline {
            agent any
            stages {
                stage('Tests') {
                    parallel {
                        stage('Unit') { steps { sh 'pytest' } }
                        stage('Lint') { steps { sh 'ruff check .' } }
                    }
                }
            }
        }
        """
        jf = parser.parse(src)
        assert jf.stages[0].name == "Tests"
        names = [s.name for s in jf.stages[0].parallel_stages]
        assert names == ["Unit", "Lint"]


# ---------------------------------------------------------------------------
# Format detection helper
# ---------------------------------------------------------------------------

class TestLooksLikeJenkinsfile:
    def test_filename_match(self, tmp_path):
        p = tmp_path / "Jenkinsfile"
        p.write_text("// nothing groovy here\n")
        assert looks_like_jenkinsfile(p) is True

    def test_content_match(self, tmp_path):
        p = tmp_path / "ci.groovy"
        p.write_text("pipeline { agent any; stages { } }\n")
        assert looks_like_jenkinsfile(p) is True

    def test_yaml_does_not_match(self, tmp_path):
        p = tmp_path / "ci.yml"
        p.write_text("stages:\n  - build\n")
        assert looks_like_jenkinsfile(p) is False
