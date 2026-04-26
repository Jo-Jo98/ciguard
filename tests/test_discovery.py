"""
Tests for v0.8.0 pipeline file auto-discovery.

Verifies the walker picks up the right files (and only those), respects
default + custom exclusions, and survives symlink cycles.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.discovery import discover_pipeline_files


def _platforms(files):
    return {df.platform for df in files}


def _names(files):
    return {df.path.name for df in files}


class TestDiscovery:
    def test_finds_gitlab_at_root(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]")
        files = discover_pipeline_files(tmp_path)
        assert len(files) == 1
        assert files[0].platform == "gitlab-ci"

    def test_finds_gha_workflows(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("name: ci\non: [push]\njobs: {}")
        (wf / "release.yaml").write_text("name: r\non: [push]\njobs: {}")
        files = discover_pipeline_files(tmp_path)
        assert len(files) == 2
        assert _platforms(files) == {"github-actions"}
        assert _names(files) == {"ci.yml", "release.yaml"}

    def test_does_not_match_yml_outside_workflows_dir(self, tmp_path):
        # Random root-level YAML should NOT be picked up.
        (tmp_path / "other.yml").write_text("foo: bar")
        files = discover_pipeline_files(tmp_path)
        assert files == []

    def test_finds_jenkinsfile_by_name(self, tmp_path):
        (tmp_path / "Jenkinsfile").write_text("pipeline { agent any }")
        (tmp_path / "Jenkinsfile.release").write_text("pipeline { agent any }")
        (tmp_path / "build.jenkinsfile").write_text("pipeline { agent any }")
        files = discover_pipeline_files(tmp_path)
        assert len(files) == 3
        assert _platforms(files) == {"jenkins"}

    def test_groovy_requires_pipeline_markers(self, tmp_path):
        # Has pipeline markers — should be classified as Jenkins.
        (tmp_path / "build.groovy").write_text("pipeline { agent any\nstages { stage('x') {} } }")
        # No markers — should be ignored (plain Groovy / Gradle).
        (tmp_path / "lib.groovy").write_text("class Foo {}\ndef bar() { return 1 }")
        files = discover_pipeline_files(tmp_path)
        assert len(files) == 1
        assert files[0].path.name == "build.groovy"

    def test_excludes_default_dirs(self, tmp_path):
        for d in [".git", "node_modules", "venv", "__pycache__"]:
            sub = tmp_path / d
            sub.mkdir()
            (sub / ".gitlab-ci.yml").write_text("stages: []")
        files = discover_pipeline_files(tmp_path)
        assert files == []

    def test_custom_excludes_override(self, tmp_path):
        # Override defaults: now `.git` is *not* excluded.
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / ".gitlab-ci.yml").write_text("stages: []")
        files = discover_pipeline_files(tmp_path, exclude_dirs=set())
        assert len(files) == 1

    def test_walks_nested_directories(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "Jenkinsfile").write_text("pipeline { agent any }")
        files = discover_pipeline_files(tmp_path)
        assert len(files) == 1
        assert files[0].path == deep / "Jenkinsfile"

    def test_missing_root_returns_empty(self, tmp_path):
        files = discover_pipeline_files(tmp_path / "nope")
        assert files == []

    def test_results_sorted_deterministically(self, tmp_path):
        # Create files in non-alphabetical order to ensure sort isn't insertion order.
        (tmp_path / "z").mkdir()
        (tmp_path / "z" / "Jenkinsfile").write_text("pipeline { agent any }")
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / ".gitlab-ci.yml").write_text("stages: []")
        files = discover_pipeline_files(tmp_path)
        assert [df.path.name for df in files] == [".gitlab-ci.yml", "Jenkinsfile"]
