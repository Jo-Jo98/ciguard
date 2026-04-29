"""Tests for the v0.9.4 reusable CI workflow templates under templates/.

Templates ship as reference YAML for users to drop into their own repos.
These tests guard against:

  - YAML syntax errors slipping in on edits
  - Drift between template flag invocations and the real ciguard CLI
    (e.g. someone bumps a flag name in the parser without updating
    the templates — would silently break every downstream consumer)
  - The pinned ciguard version in templates falling out of sync with
    the project's own version

If you bump the project version in pyproject.toml, also bump the pin in
every template under templates/.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
TEMPLATES_DIR = REPO_ROOT / "templates"

GHA_TEMPLATES = sorted((TEMPLATES_DIR / "github-actions").glob("*.yml"))
GITLAB_TEMPLATES = sorted((TEMPLATES_DIR / "gitlab-ci").glob("*.yml"))
JENKINS_TEMPLATES = sorted((TEMPLATES_DIR / "jenkins").glob("Jenkinsfile*"))


def _project_version() -> str:
    """Read the [project] version from pyproject.toml without importing tomllib
    extras — this test runs against the source tree, not the installed pkg."""
    text = (REPO_ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "could not find version line in pyproject.toml"
    return match.group(1)


# ---- YAML validity ----------------------------------------------------------


@pytest.mark.parametrize("path", GHA_TEMPLATES + GITLAB_TEMPLATES, ids=lambda p: p.name)
def test_yaml_template_is_valid(path: Path) -> None:
    """Every YAML template must parse cleanly with yaml.safe_load."""
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict), f"{path.name}: top-level must be a mapping"


# ---- GitHub Actions templates ----------------------------------------------


@pytest.mark.parametrize("path", GHA_TEMPLATES, ids=lambda p: p.name)
def test_gha_template_has_required_keys(path: Path) -> None:
    """GHA templates must declare name, on, permissions, jobs."""
    data = yaml.safe_load(path.read_text())
    assert "name" in data
    # PyYAML parses bare `on:` as Python True (YAML 1.1 boolean) so check both.
    assert "on" in data or True in data
    assert "permissions" in data
    assert "jobs" in data
    assert len(data["jobs"]) >= 1


@pytest.mark.parametrize("path", GHA_TEMPLATES, ids=lambda p: p.name)
def test_gha_template_pins_actions_by_sha(path: Path) -> None:
    """Every uses: line must pin to a 40-char commit SHA, not a tag.
    This dogfoods the GHA-IAM-006 rule we ship."""
    text = path.read_text()
    uses_lines = re.findall(r"uses:\s*([\S]+)", text)
    assert uses_lines, f"{path.name}: no `uses:` lines found"
    for ref in uses_lines:
        assert "@" in ref, f"{path.name}: `{ref}` missing @ref"
        sha_part = ref.split("@", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{40}", sha_part), (
            f"{path.name}: `{ref}` not pinned to a commit SHA "
            "(GHA-IAM-006 — templates must dogfood our own rules)"
        )


@pytest.mark.parametrize("path", GHA_TEMPLATES, ids=lambda p: p.name)
def test_gha_template_pins_ciguard_to_project_version(path: Path) -> None:
    """The `pip install ciguard==X.Y.Z` line must match pyproject.toml."""
    version = _project_version()
    text = path.read_text()
    assert f"ciguard=={version}" in text, (
        f"{path.name}: pinned ciguard version drifted from pyproject "
        f"(expected ciguard=={version})"
    )


# ---- GitLab CI templates ----------------------------------------------------


@pytest.mark.parametrize("path", GITLAB_TEMPLATES, ids=lambda p: p.name)
def test_gitlab_template_pins_ciguard_to_project_version(path: Path) -> None:
    version = _project_version()
    text = path.read_text()
    assert f"ciguard=={version}" in text, (
        f"{path.name}: pinned ciguard version drifted from pyproject "
        f"(expected ciguard=={version})"
    )


@pytest.mark.parametrize("path", GITLAB_TEMPLATES, ids=lambda p: p.name)
def test_gitlab_template_declares_artifacts(path: Path) -> None:
    """GitLab job must export the JSON results as an artifact."""
    data = yaml.safe_load(path.read_text())
    job = next((v for v in data.values() if isinstance(v, dict) and "script" in v), None)
    assert job is not None, f"{path.name}: no job with `script:` block"
    assert "artifacts" in job, f"{path.name}: missing artifacts block"


# ---- Jenkins templates ------------------------------------------------------


@pytest.mark.parametrize("path", JENKINS_TEMPLATES, ids=lambda p: p.name)
def test_jenkins_template_pins_ghcr_image_to_project_version(path: Path) -> None:
    version = _project_version()
    text = path.read_text()
    assert f"ghcr.io/jo-jo98/ciguard:v{version}" in text, (
        f"{path.name}: pinned GHCR image tag drifted from pyproject "
        f"(expected ghcr.io/jo-jo98/ciguard:v{version})"
    )


@pytest.mark.parametrize("path", JENKINS_TEMPLATES, ids=lambda p: p.name)
def test_jenkins_template_uses_declarative_pipeline(path: Path) -> None:
    """Sanity check that the Jenkinsfile uses declarative pipeline syntax."""
    text = path.read_text()
    assert text.lstrip().startswith("//") or "pipeline {" in text
    assert "pipeline {" in text
    assert "stages {" in text


# ---- CLI flag round-trip ----------------------------------------------------


def _harvest_real_cli_flags() -> set[str]:
    """Harvest every long-form flag the real ciguard CLI advertises by
    invoking `ciguard <subcommand> --help` via subprocess and grepping
    the output. Goes through the same code path users hit."""
    import subprocess

    flags: set[str] = set()
    for sub in ("scan", "scan-repo", "mcp", "web"):
        try:
            out = subprocess.check_output(
                ["ciguard", sub, "--help"], stderr=subprocess.STDOUT, text=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        flags.update(re.findall(r"(--[a-z][a-z0-9-]+)", out))
    return flags


def _harvest_ciguard_invocation_flags(text: str) -> set[str]:
    """Walk the template line-by-line, isolate runs that start with a
    `ciguard <subcmd>` invocation (across shell line-continuations), and
    return the long flags inside those runs only. Skips flags belonging
    to neighbouring tools (pip --upgrade, jq --slurpfile, docker --rm)."""
    flags: set[str] = set()
    in_ciguard = False
    # Trigger on either a bare `ciguard <subcmd>` invocation, or a
    # docker-run reference to the published GHCR image (Jenkinsfile case).
    trigger = re.compile(
        r"\bciguard\s+(scan-repo|scan|mcp|web)\b"
        r"|ghcr\.io/jo-jo98/ciguard:"
    )
    for raw in text.splitlines():
        if trigger.search(raw):
            in_ciguard = True
        if in_ciguard:
            flags.update(re.findall(r"(--[a-z][a-z0-9-]+)", raw))
            # Continuation? Trailing `\` keeps us in-block; otherwise
            # the invocation ends with this line.
            if not raw.rstrip().endswith("\\"):
                in_ciguard = False
    return flags


@pytest.mark.parametrize(
    "path",
    GHA_TEMPLATES + GITLAB_TEMPLATES + JENKINS_TEMPLATES,
    ids=lambda p: p.name,
)
def test_template_only_uses_real_ciguard_flags(path: Path) -> None:
    """Every long flag inside a ciguard invocation must exist on the real
    CLI. Catches typos and flags that get renamed without a template bump."""
    template_flags = _harvest_ciguard_invocation_flags(path.read_text())
    if not template_flags:
        pytest.skip(f"{path.name}: no ciguard flags to check")

    real_flags = _harvest_real_cli_flags()
    if not real_flags:
        pytest.skip("ciguard CLI not available on PATH")

    unknown = template_flags - real_flags
    assert not unknown, (
        f"{path.name}: template references flags missing from ciguard CLI: "
        f"{sorted(unknown)}"
    )
