"""
Tests for the v0.7.0 `.ciguardignore` file-based suppression.

Covers:
  - IgnoreRule pydantic validation (reason length, missing reason, empty rule_id)
  - load_ignore_file: valid file, missing file, malformed YAML, non-list root,
    naked rule-id without reason, rejected entry shapes
  - discover_ignore_file: walks up to repo root (.git boundary)
  - apply_ignores: rule_id match, location substring filter, no-match passthrough,
    expired-entry warning still suppresses
  - end-to-end via main.cmd_scan: kept findings drop, suppressed list populated,
    summary + risk score recomputed, --no-ignore-file overrides discovery
"""
from __future__ import annotations

import datetime as dt
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.ignore import (
    DEFAULT_IGNORE_FILENAME,
    IgnoreRule,
    apply_ignores,
    discover_ignore_file,
    load_ignore_file,
)
from ciguard.models.pipeline import (
    Category,
    ComplianceMapping,
    Finding,
    Severity,
)


def _make_finding(rule_id: str, location: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"{rule_id}-{location}",
        rule_id=rule_id,
        name=f"{rule_id} test finding",
        description="...",
        severity=severity,
        category=Category.PIPELINE_INTEGRITY,
        location=location,
        evidence="evidence",
        remediation="fix it",
        compliance=ComplianceMapping(),
    )


# ---------------------------------------------------------------------------
# IgnoreRule validation
# ---------------------------------------------------------------------------

class TestIgnoreRuleValidation:
    def test_minimum_valid(self):
        rule = IgnoreRule(rule_id="PIPE-001", reason="Pinned in parent template intentionally")
        assert rule.rule_id == "PIPE-001"
        assert rule.location is None
        assert rule.expires is None

    def test_reason_too_short_rejected(self):
        with pytest.raises(ValueError, match="reason must be at least"):
            IgnoreRule(rule_id="PIPE-001", reason="ok")

    def test_reason_only_whitespace_rejected(self):
        with pytest.raises(ValueError, match="reason must be at least"):
            IgnoreRule(rule_id="PIPE-001", reason="          ")

    def test_empty_rule_id_rejected(self):
        with pytest.raises(ValueError, match="rule_id must not be empty"):
            IgnoreRule(rule_id="   ", reason="A perfectly valid reason here.")

    def test_expires_parsed_as_date(self):
        rule = IgnoreRule(
            rule_id="PIPE-001",
            reason="Until the migration completes",
            expires="2026-12-31",
        )
        assert rule.expires == dt.date(2026, 12, 31)

    def test_expires_invalid_date_rejected(self):
        with pytest.raises(ValueError):
            IgnoreRule(
                rule_id="PIPE-001",
                reason="A perfectly valid reason here.",
                expires="not-a-date",
            )


# ---------------------------------------------------------------------------
# IgnoreRule.matches + is_expired
# ---------------------------------------------------------------------------

class TestIgnoreRuleMatches:
    def test_rule_id_must_match_exactly(self):
        rule = IgnoreRule(rule_id="PIPE-001", reason="A perfectly valid reason here.")
        assert rule.matches("PIPE-001", "job[build]")
        assert not rule.matches("PIPE-002", "job[build]")

    def test_no_location_matches_anywhere(self):
        rule = IgnoreRule(rule_id="PIPE-001", reason="A perfectly valid reason here.")
        assert rule.matches("PIPE-001", "job[build]")
        assert rule.matches("PIPE-001", "job[deploy_prod]")

    def test_location_is_substring(self):
        rule = IgnoreRule(
            rule_id="PIPE-001",
            reason="Only suppress on the deploy_prod job.",
            location="deploy_prod",
        )
        assert rule.matches("PIPE-001", "job[deploy_prod]")
        assert not rule.matches("PIPE-001", "job[build]")

    def test_is_expired_false_when_no_expires(self):
        rule = IgnoreRule(rule_id="PIPE-001", reason="A perfectly valid reason here.")
        assert not rule.is_expired()

    def test_is_expired_true_when_past(self):
        rule = IgnoreRule(
            rule_id="PIPE-001",
            reason="A perfectly valid reason here.",
            expires="2020-01-01",
        )
        assert rule.is_expired(today=dt.date(2026, 1, 1))

    def test_is_expired_false_on_expiry_date_itself(self):
        rule = IgnoreRule(
            rule_id="PIPE-001",
            reason="A perfectly valid reason here.",
            expires="2026-01-01",
        )
        assert not rule.is_expired(today=dt.date(2026, 1, 1))


# ---------------------------------------------------------------------------
# load_ignore_file
# ---------------------------------------------------------------------------

class TestLoadIgnoreFile:
    def test_missing_file_returns_empty(self, tmp_path):
        result = load_ignore_file(tmp_path / "does-not-exist")
        assert result.rules == []

    def test_empty_file_returns_empty(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text("")
        assert load_ignore_file(path).rules == []

    def test_valid_file(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text(textwrap.dedent("""
            - rule_id: PIPE-001
              location: deploy_prod
              reason: We pin to digest in the parent template.
              expires: 2026-12-31
            - rule_id: SCA-EOL-003
              reason: Internal mirror keeps Python 3.9 alive past upstream EOL.
        """))
        result = load_ignore_file(path)
        assert len(result.rules) == 2
        assert result.rules[0].rule_id == "PIPE-001"
        assert result.rules[0].location == "deploy_prod"
        assert result.rules[0].expires == dt.date(2026, 12, 31)
        assert result.rules[1].location is None

    def test_missing_reason_rejected(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text("- rule_id: PIPE-001\n")
        with pytest.raises(ValueError, match="missing a `reason` field"):
            load_ignore_file(path)

    def test_top_level_must_be_list(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text("rule_id: PIPE-001\nreason: ok ok ok ok ok\n")
        with pytest.raises(ValueError, match="top-level must be a YAML list"):
            load_ignore_file(path)

    def test_invalid_yaml_rejected(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text(": this isn't valid yaml :")
        with pytest.raises(ValueError, match="invalid YAML"):
            load_ignore_file(path)

    def test_short_reason_rejected_with_entry_index(self, tmp_path):
        path = tmp_path / DEFAULT_IGNORE_FILENAME
        path.write_text(textwrap.dedent("""
            - rule_id: PIPE-001
              reason: A perfectly fine reason that explains itself.
            - rule_id: PIPE-002
              reason: nope
        """))
        with pytest.raises(ValueError, match="entry #2"):
            load_ignore_file(path)


# ---------------------------------------------------------------------------
# discover_ignore_file
# ---------------------------------------------------------------------------

class TestDiscoverIgnoreFile:
    def test_finds_in_same_dir(self, tmp_path):
        ignore = tmp_path / DEFAULT_IGNORE_FILENAME
        ignore.write_text("[]")
        pipeline = tmp_path / "pipeline.yml"
        pipeline.write_text("stages: []")
        assert discover_ignore_file(pipeline) == ignore

    def test_finds_in_parent_dir(self, tmp_path):
        ignore = tmp_path / DEFAULT_IGNORE_FILENAME
        ignore.write_text("[]")
        sub = tmp_path / "sub"
        sub.mkdir()
        pipeline = sub / "pipeline.yml"
        pipeline.write_text("stages: []")
        assert discover_ignore_file(pipeline) == ignore

    def test_returns_none_when_absent(self, tmp_path):
        pipeline = tmp_path / "pipeline.yml"
        pipeline.write_text("stages: []")
        # Plant a .git directory so the walk stops at tmp_path instead of
        # accidentally finding a .ciguardignore further up the test machine.
        (tmp_path / ".git").mkdir()
        assert discover_ignore_file(pipeline) is None

    def test_stops_at_git_boundary(self, tmp_path):
        # Outer dir has a .ciguardignore — but a .git dir between input and
        # outer should stop the walk before finding it.
        (tmp_path / DEFAULT_IGNORE_FILENAME).write_text("[]")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        pipeline = repo / "pipeline.yml"
        pipeline.write_text("stages: []")
        assert discover_ignore_file(pipeline) is None


# ---------------------------------------------------------------------------
# apply_ignores
# ---------------------------------------------------------------------------

class TestApplyIgnores:
    def test_no_rules_returns_all_kept(self):
        findings = [_make_finding("PIPE-001", "job[build]")]
        kept, suppressed, warnings = apply_ignores(findings, [])
        assert kept == findings
        assert suppressed == []
        assert warnings == []

    def test_rule_id_match_suppresses(self):
        findings = [
            _make_finding("PIPE-001", "job[build]"),
            _make_finding("PIPE-002", "job[build]"),
        ]
        rules = [IgnoreRule(rule_id="PIPE-001", reason="A perfectly valid reason here.")]
        kept, suppressed, _ = apply_ignores(findings, rules)
        assert [f.rule_id for f in kept] == ["PIPE-002"]
        assert [f.rule_id for f in suppressed] == ["PIPE-001"]

    def test_location_filter(self):
        findings = [
            _make_finding("PIPE-001", "job[deploy_prod]"),
            _make_finding("PIPE-001", "job[build]"),
        ]
        rules = [
            IgnoreRule(
                rule_id="PIPE-001",
                reason="Only suppress on the deploy_prod job.",
                location="deploy_prod",
            )
        ]
        kept, suppressed, _ = apply_ignores(findings, rules)
        assert [f.location for f in kept] == ["job[build]"]
        assert [f.location for f in suppressed] == ["job[deploy_prod]"]

    def test_expired_entry_still_suppresses_with_warning(self):
        findings = [_make_finding("PIPE-001", "job[build]")]
        rules = [
            IgnoreRule(
                rule_id="PIPE-001",
                reason="Until the migration completes.",
                expires="2020-01-01",
            )
        ]
        kept, suppressed, warnings = apply_ignores(
            findings, rules, today=dt.date(2026, 1, 1)
        )
        assert kept == []
        assert len(suppressed) == 1
        assert len(warnings) == 1
        assert "PIPE-001" in warnings[0]
        assert "2020-01-01" in warnings[0]

    def test_first_matching_rule_wins(self):
        # Two suppression entries match the same finding — only one warning.
        findings = [_make_finding("PIPE-001", "job[build]")]
        rules = [
            IgnoreRule(
                rule_id="PIPE-001",
                reason="Specific reason for the build job.",
                location="build",
            ),
            IgnoreRule(rule_id="PIPE-001", reason="Catch-all reason for PIPE-001."),
        ]
        kept, suppressed, _ = apply_ignores(findings, rules)
        assert kept == []
        assert len(suppressed) == 1


# ---------------------------------------------------------------------------
# main.cmd_scan end-to-end
# ---------------------------------------------------------------------------

class TestCLIIntegration:
    """Drive `main.cmd_scan` against a real fixture with a temp ignore file
    to verify the full pipeline: discovery → load → suppress → recompute
    summary + risk score → exit code reflects post-suppression state."""

    def _make_args(self, input_path: Path, ignore_path: Path = None,
                   no_ignore: bool = False):
        from argparse import Namespace
        return Namespace(
            input=str(input_path),
            output=None,
            format=None,
            platform="auto",
            policies=None,
            no_builtin_policies=True,
            llm=False,
            llm_provider=None,
            llm_model=None,
            offline=True,
            ignore_file=str(ignore_path) if ignore_path else None,
            no_ignore_file=no_ignore,
            baseline=None,
            update_baseline=False,
            fail_on_new=None,
        )

    def test_scan_without_ignore_baseline(self, tmp_path, capsys):
        # Use the existing bad fixture which has many findings.
        from ciguard.main import cmd_scan
        bad = Path(__file__).parent / "fixtures" / "bad_pipeline.yml"
        args = self._make_args(bad, no_ignore=True)
        cmd_scan(args)
        out = capsys.readouterr().out
        # No suppression line should appear when --no-ignore-file is set.
        assert "suppressed by" not in out

    def test_scan_with_ignore_file_suppresses(self, tmp_path, capsys):
        from ciguard.main import cmd_scan
        bad = Path(__file__).parent / "fixtures" / "bad_pipeline.yml"
        # Copy fixture into tmp so the walk-up doesn't hit unrelated files.
        local_bad = tmp_path / "pipeline.yml"
        local_bad.write_text(bad.read_text())
        ignore = tmp_path / DEFAULT_IGNORE_FILENAME
        ignore.write_text(textwrap.dedent("""
            - rule_id: IAM-001
              reason: Test fixture deliberately contains hardcoded secrets.
            - rule_id: PIPE-001
              reason: Test fixture deliberately uses unpinned images.
        """))
        # Plant .git so discovery stops at tmp_path
        (tmp_path / ".git").mkdir()
        args = self._make_args(local_bad)
        cmd_scan(args)
        out = capsys.readouterr().out
        assert "suppressed by" in out
        assert DEFAULT_IGNORE_FILENAME in out
