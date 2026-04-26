"""
Rule-firing tests for the v0.4 Jenkins starter ruleset.

Each rule is exercised against the bad / good fixtures plus a couple of
small synthetic inputs that pin down a specific edge.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.analyzer.engine import AnalysisEngine
from ciguard.analyzer.jenkins_rules import (
    rule_jkn_iam_001,
    rule_jkn_lib_001,
    rule_jkn_pipe_001,
    rule_jkn_run_001,
    rule_jkn_run_002,
    rule_jkn_sc_001,
    rule_jkn_sc_002,
)
from ciguard.analyzer.rules import _reset_counters
from ciguard.parser.jenkinsfile import JenkinsfileParser


FIXTURES = Path(__file__).parent / "fixtures" / "jenkins"
parser = JenkinsfileParser()


def _bad():
    _reset_counters()
    return parser.parse_file(FIXTURES / "bad_jenkinsfile.Jenkinsfile")


def _good():
    _reset_counters()
    return parser.parse_file(FIXTURES / "good_jenkinsfile.Jenkinsfile")


# ---------------------------------------------------------------------------
# JKN-PIPE-001 — Unpinned docker image
# ---------------------------------------------------------------------------

class TestPipe001:
    def test_fires_on_latest_tag(self):
        findings = rule_jkn_pipe_001(_bad())
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids.count("JKN-PIPE-001") == 2  # maven:latest + alpine
        ev = " ".join(f.evidence for f in findings)
        assert "maven:latest" in ev
        assert "alpine" in ev

    def test_silent_on_pinned_images(self):
        findings = rule_jkn_pipe_001(_good())
        assert findings == []


# ---------------------------------------------------------------------------
# JKN-IAM-001 — Hardcoded secret in environment
# ---------------------------------------------------------------------------

class TestIam001:
    def test_fires_on_literal_secret(self):
        findings = rule_jkn_iam_001(_bad())
        keys = [f.evidence.split(" =")[0] for f in findings]
        assert "API_TOKEN" in keys
        assert "DB_PASSWORD" in keys
        # GITHUB_TOKEN uses credentials() — must NOT fire.
        assert not any("GITHUB_TOKEN" in k for k in keys)

    def test_silent_on_credentials_wrapped(self):
        findings = rule_jkn_iam_001(_good())
        assert findings == []

    def test_silent_on_non_secret_key(self):
        src = """
        pipeline {
            agent { label 'x' }
            environment {
                BUILD_ENV = 'production'
                FOO_PATH  = '/usr/local/bin'
            }
            stages { stage('A') { steps { sh 'true' } } }
        }
        """
        jf = parser.parse(src)
        assert rule_jkn_iam_001(jf) == []


# ---------------------------------------------------------------------------
# JKN-RUN-001 — Unconstrained agent any
# ---------------------------------------------------------------------------

class TestRun001:
    def test_fires_when_top_level_agent_any(self):
        findings = rule_jkn_run_001(_bad())
        assert len(findings) == 1
        assert findings[0].evidence == "agent any"

    def test_silent_when_label_agent(self):
        assert rule_jkn_run_001(_good()) == []

    def test_silent_when_top_level_docker_agent(self):
        src = """
        pipeline {
            agent { docker { image 'alpine@sha256:abc' } }
            stages { stage('A') { steps { sh 'true' } } }
        }
        """
        assert rule_jkn_run_001(parser.parse(src)) == []


# ---------------------------------------------------------------------------
# JKN-RUN-002 — Privileged docker agent
# ---------------------------------------------------------------------------

class TestRun002:
    def test_fires_on_privileged_args(self):
        findings = rule_jkn_run_002(_bad())
        assert len(findings) == 1
        assert "privileged" in findings[0].evidence.lower() or "docker.sock" in findings[0].evidence
        assert findings[0].severity.value == "Critical"

    def test_silent_on_clean_args(self):
        assert rule_jkn_run_002(_good()) == []

    def test_fires_on_pid_host(self):
        src = """
        pipeline {
            agent { docker { image 'alpine@sha256:abc' args '--pid=host' } }
            stages { stage('A') { steps { sh 'true' } } }
        }
        """
        findings = rule_jkn_run_002(parser.parse(src))
        assert len(findings) == 1
        assert "pid=host" in findings[0].evidence.lower()


# ---------------------------------------------------------------------------
# JKN-SC-001 — Dangerous shell pattern
# ---------------------------------------------------------------------------

class TestSc001:
    def test_fires_on_curl_pipe_bash(self):
        findings = rule_jkn_sc_001(_bad())
        evidences = [f.evidence for f in findings]
        # Both `curl … | bash` and `wget … | sh` and `eval "$VAR"` should hit.
        assert any("curl" in e and "bash" in e for e in evidences)
        assert any("wget" in e for e in evidences)
        assert any("eval" in e for e in evidences)

    def test_silent_on_clean_steps(self):
        assert rule_jkn_sc_001(_good()) == []


# ---------------------------------------------------------------------------
# JKN-SC-002 — Dynamic Groovy script block
# ---------------------------------------------------------------------------

class TestSc002:
    def test_fires_on_script_block(self):
        findings = rule_jkn_sc_002(_bad())
        assert len(findings) == 1
        assert findings[0].severity.value == "Info"
        assert "Jenkins.instance" in findings[0].evidence or "manifest" in findings[0].evidence

    def test_silent_when_no_script_block(self):
        assert rule_jkn_sc_002(_good()) == []


# ---------------------------------------------------------------------------
# End-to-end engine integration
# ---------------------------------------------------------------------------

class TestEngineIntegration:
    def test_engine_dispatches_to_jenkins_path(self):
        report = AnalysisEngine(enable_sca=False).analyse(_bad(), pipeline_name="bad_jenkinsfile.Jenkinsfile")
        assert report.platform == "jenkins"
        # Synthesised pipeline shadow shows our two stages as jobs.
        assert {j.name for j in report.pipeline.jobs} == {"Build", "Deploy"}
        # Multiple findings expected from the bad fixture.
        assert report.summary["total"] >= 8
        assert report.risk_score.overall < 100
        # All six v0.4 rule families should fire.
        rule_ids = {f.rule_id for f in report.findings}
        assert rule_ids == {
            "JKN-PIPE-001", "JKN-IAM-001", "JKN-RUN-001",
            "JKN-RUN-002", "JKN-SC-001", "JKN-SC-002",
        }

    def test_good_fixture_is_clean(self):
        report = AnalysisEngine(enable_sca=False).analyse(_good(), pipeline_name="good_jenkinsfile.Jenkinsfile")
        assert report.platform == "jenkins"
        assert report.summary["total"] == 0
        assert report.risk_score.grade == "A"


# ---------------------------------------------------------------------------
# JKN-LIB-001 — Shared-library delegation (v0.4.1)
# ---------------------------------------------------------------------------

class TestLib001:
    def test_fires_on_shared_library_call(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "shared_library_call.Jenkinsfile")
        findings = rule_jkn_lib_001(jf)
        assert len(findings) == 1
        assert findings[0].rule_id == "JKN-LIB-001"
        assert findings[0].severity.value == "Info"
        assert "buildPlugin" in findings[0].evidence

    def test_silent_on_declarative(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "good_jenkinsfile.Jenkinsfile")
        assert rule_jkn_lib_001(jf) == []

    def test_silent_on_node_scripted(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "good_node_scripted.Jenkinsfile")
        assert rule_jkn_lib_001(jf) == []


# ---------------------------------------------------------------------------
# Node-scripted end-to-end (v0.4.1) — existing rules must work unchanged
# ---------------------------------------------------------------------------

class TestNodeScriptedIntegration:
    def test_bad_node_scripted_fires_expected_rules(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "bad_node_scripted.Jenkinsfile")
        report = AnalysisEngine(enable_sca=False).analyse(jf, pipeline_name="bad_node_scripted.Jenkinsfile")
        assert report.platform == "jenkins"
        rule_ids = {f.rule_id for f in report.findings}
        # JKN-RUN-001 fires because `node` (no label) → agent.kind == "any".
        # JKN-SC-001 fires twice on curl|bash and eval $VAR.
        assert "JKN-RUN-001" in rule_ids
        assert "JKN-SC-001" in rule_ids
        # Should NOT fire JKN-LIB-001 (no shared-library call).
        assert "JKN-LIB-001" not in rule_ids

    def test_good_node_scripted_clean(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "good_node_scripted.Jenkinsfile")
        report = AnalysisEngine(enable_sca=False).analyse(jf, pipeline_name="good_node_scripted.Jenkinsfile")
        assert report.summary["total"] == 0
        assert report.risk_score.grade == "A"

    def test_shared_library_only_fires_lib_001(self):
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "shared_library_call.Jenkinsfile")
        report = AnalysisEngine(enable_sca=False).analyse(jf, pipeline_name="shared_library_call.Jenkinsfile")
        rule_ids = {f.rule_id for f in report.findings}
        assert rule_ids == {"JKN-LIB-001"}

    def test_freeform_scripted_silent(self):
        # Genuinely free-form Scripted produces zero findings — rules
        # cannot reason about arbitrary Groovy. The CLI surfaces the
        # warning; here we just confirm the engine doesn't crash and
        # doesn't fabricate findings.
        _reset_counters()
        jf = parser.parse_file(FIXTURES / "freeform_scripted.Jenkinsfile")
        report = AnalysisEngine(enable_sca=False).analyse(jf, pipeline_name="freeform_scripted.Jenkinsfile")
        assert report.summary["total"] == 0
        assert jf.is_scripted is True
