"""Regressions for crashes found by the weekly Atheris fuzz job.

Each test pins the bug *class* surfaced by a fuzz finding and asserts the
production parser path now handles it gracefully (raises ValueError, never
the original uncaught exception). The original Atheris artifact is kept
under tests/fixtures/fuzz/ for forensic reference.
"""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "fuzz"


def test_issue_18_pyyaml_recursion_error_handled(tmp_path: Path) -> None:
    """Issue #18 (2026-05-03): pyyaml raised RecursionError on deeply-nested
    YAML, escaping the parsers' yaml.YAMLError handler. Now wrapped as
    ValueError so CLI / MCP / App entry points can surface a clean error."""
    from ciguard.parser.github_actions import GitHubActionsParser
    from ciguard.parser.gitlab_parser import GitLabCIParser

    # Synthetic payload that reliably triggers RecursionError in pyyaml's
    # composer on Python's default recursion limit (1000). The Atheris
    # crashing artifact (recursion-yaml-issue-18.bin) hits the same code
    # path with a ~50-level nest plus repeated tokens; this synthetic form
    # is deterministic across Python versions.
    payload = "[" * 2000 + "1" + "]" * 2000
    yaml_path = tmp_path / "pipeline.yml"
    yaml_path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid YAML"):
        GitHubActionsParser().parse_file(yaml_path)

    with pytest.raises(ValueError, match="Invalid YAML"):
        GitLabCIParser().parse_file(yaml_path)


def test_issue_18_atheris_artifact_preserved() -> None:
    """The original Atheris crashing input is preserved on disk for
    forensic reference even though the regression test above uses a
    synthetic payload (the artifact contains non-UTF-8 bytes that fail
    earlier than the recursion site, so it can't be replayed through
    parse_file directly)."""
    artifact = FIXTURES / "recursion-yaml-issue-18.bin"
    assert artifact.exists(), "Atheris crash artifact must remain under VCS"
    assert artifact.stat().st_size > 0
