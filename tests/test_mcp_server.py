"""
Tests for the v0.8.0 MCP server tool dispatch.

The actual MCP stdio transport is the SDK's concern and is not unit-tested
here. What we DO test is the in-process tool handler dispatch — the same
functions the SDK calls when an MCP client invokes a tool. This is the
correct cut: it isolates ciguard logic from SDK plumbing while still
exercising every tool's full code path.

Covers:
  - All 5 tools register
  - ciguard.list_rules returns the catalog with platform / severity filters
  - ciguard.explain_rule returns metadata for a known rule, error for unknown
  - ciguard.scan returns a Report dict with findings / risk_score / summary
  - ciguard.scan respects --no-ignore-file and applies .ciguardignore otherwise
  - ciguard.scan_repo walks a directory and returns per-file + aggregate
  - ciguard.diff_baseline returns new / resolved / unchanged-count + score_delta
  - The Tool schemas are well-formed for every registered tool
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.mcp.server import (
    SERVER_NAME,
    _MCP_AVAILABLE,
    _all_tools,
    _dispatch,
    build_server,
)
from ciguard.rule_catalog import get_catalog, reset_catalog


# Gate the SDK-dependent tests on the optional [mcp] extra. The dispatch
# tests work without the SDK (they exercise pure Python handlers), but
# anything that touches mcp.types.Tool or mcp.server.Server requires the
# package. Skipping rather than failing when the extra isn't installed
# keeps `pytest` clean for users who didn't `pip install ciguard[mcp]`.
_requires_sdk = pytest.mark.skipif(
    not _MCP_AVAILABLE,
    reason="MCP SDK not installed (optional extra: pip install 'ciguard[mcp]')",
)


FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


class TestRuleCatalog:
    def setup_method(self):
        reset_catalog()

    def test_catalog_populated(self):
        catalog = get_catalog()
        assert len(catalog) >= 30, (
            f"catalog should harvest >=30 rules from bad fixtures, got {len(catalog)}"
        )

    def test_catalog_includes_every_platform(self):
        catalog = get_catalog()
        platforms_seen = {p for spec in catalog.values() for p in spec.platforms}
        assert "gitlab-ci" in platforms_seen
        assert "github-actions" in platforms_seen
        assert "jenkins" in platforms_seen

    def test_catalog_pipe001_is_complete(self):
        catalog = get_catalog()
        spec = catalog["PIPE-001"]
        assert spec.name == "Unpinned Docker Image"
        assert spec.severity == "High"
        assert spec.category == "Pipeline Integrity"
        assert spec.remediation, "remediation string must be non-empty"
        assert spec.compliance, "compliance dict must have at least one framework"


# ---------------------------------------------------------------------------
# Tool registry shape
# ---------------------------------------------------------------------------


class TestToolRegistry:
    @_requires_sdk
    def test_all_five_tools_registered(self):
        names = {t.name for t in _all_tools()}
        assert names == {
            "ciguard.scan",
            "ciguard.scan_repo",
            "ciguard.explain_rule",
            "ciguard.diff_baseline",
            "ciguard.list_rules",
        }

    @_requires_sdk
    def test_every_tool_has_schema_with_required_fields(self):
        for tool in _all_tools():
            assert tool.description, f"{tool.name} missing description"
            assert tool.inputSchema, f"{tool.name} missing inputSchema"
            assert tool.inputSchema.get("type") == "object"

    @_requires_sdk
    def test_build_server_returns_server_instance(self):
        server = build_server()
        assert server.name == SERVER_NAME

    def test_unknown_tool_returns_error(self):
        result = _dispatch("ciguard.does_not_exist", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]


# ---------------------------------------------------------------------------
# ciguard.list_rules
# ---------------------------------------------------------------------------


class TestListRules:
    def test_no_filter_returns_all(self):
        result = _dispatch("ciguard.list_rules", {})
        assert result["count"] == len(result["rules"])
        assert result["count"] >= 30

    def test_platform_filter_gitlab(self):
        result = _dispatch("ciguard.list_rules", {"platform": "gitlab-ci"})
        assert all("gitlab-ci" in r["platforms"] for r in result["rules"])

    def test_platform_filter_jenkins(self):
        result = _dispatch("ciguard.list_rules", {"platform": "jenkins"})
        assert all("jenkins" in r["platforms"] for r in result["rules"])
        assert any(r["rule_id"].startswith("JKN-") for r in result["rules"])

    def test_severity_filter_critical(self):
        result = _dispatch("ciguard.list_rules", {"severity": "Critical"})
        assert all(r["severity"] == "Critical" for r in result["rules"])
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# ciguard.explain_rule
# ---------------------------------------------------------------------------


class TestExplainRule:
    def test_known_rule_returns_metadata(self):
        result = _dispatch("ciguard.explain_rule", {"rule_id": "PIPE-001"})
        assert result["rule_id"] == "PIPE-001"
        assert result["name"] == "Unpinned Docker Image"
        assert result["severity"] == "High"
        assert result["compliance"]["iso_27001"], "PIPE-001 should map to ISO 27001 controls"

    def test_unknown_rule_returns_helpful_error(self):
        result = _dispatch("ciguard.explain_rule", {"rule_id": "DOES-NOT-EXIST"})
        assert "error" in result
        assert "hint" in result, "unknown rule error should include a recovery hint"

    def test_strips_whitespace(self):
        result = _dispatch("ciguard.explain_rule", {"rule_id": "  PIPE-001  "})
        assert result["rule_id"] == "PIPE-001"


# ---------------------------------------------------------------------------
# ciguard.scan
# ---------------------------------------------------------------------------


class TestScan:
    def test_scan_returns_report_dict(self):
        result = _dispatch("ciguard.scan", {
            "file_path": str(FIXTURES / "bad_pipeline.yml"),
            "offline": True,
            "no_ignore_file": True,
        })
        assert "findings" in result
        assert len(result["findings"]) > 0
        assert "risk_score" in result
        assert "summary" in result

    def test_scan_missing_file_returns_error(self):
        result = _dispatch("ciguard.scan", {
            "file_path": "/tmp/does-not-exist-ciguard-test.yml",
        })
        assert "error" in result

    def test_scan_with_ignore_file_suppresses(self, tmp_path):
        # Copy a bad fixture so we can plant a sibling .ciguardignore
        # without mutating the shared fixture.
        bad = (FIXTURES / "bad_pipeline.yml").read_text()
        local = tmp_path / "pipeline.yml"
        local.write_text(bad)
        ignore = tmp_path / ".ciguardignore"
        ignore.write_text(textwrap.dedent("""
            - rule_id: IAM-001
              reason: Test fixture deliberately contains hardcoded secrets.
        """))
        # Plant .git so discovery stops here, not in some parent dir.
        (tmp_path / ".git").mkdir()
        result = _dispatch("ciguard.scan", {
            "file_path": str(local),
            "offline": True,
        })
        assert result.get("ignore_file_path"), "ignore_file_path should be set"
        assert len(result["suppressed"]) > 0, "IAM-001 findings should be suppressed"
        assert all(f["rule_id"] != "IAM-001" for f in result["findings"]), \
            "IAM-001 should not appear in active findings"


# ---------------------------------------------------------------------------
# ciguard.scan_repo
# ---------------------------------------------------------------------------


class TestScanRepo:
    def test_scan_repo_discovers_and_scans(self, tmp_path):
        # Set up a tiny repo with one .gitlab-ci.yml + one workflow file.
        (tmp_path / ".gitlab-ci.yml").write_text(textwrap.dedent("""
            stages: [build]
            build:
              stage: build
              image: alpine:latest
              script: ['true']
        """))
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(textwrap.dedent("""
            name: ci
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                permissions: write-all
                steps:
                  - uses: actions/checkout@main
        """))
        result = _dispatch("ciguard.scan_repo", {
            "repo_path": str(tmp_path),
            "offline": True,
            "no_ignore_file": True,
        })
        assert result["files_scanned"] == 2
        platforms = {f["platform"] for f in result["files"]}
        assert platforms == {"gitlab-ci", "github-actions"}
        assert result["total_findings"] > 0

    def test_scan_repo_fail_on_high(self, tmp_path):
        (tmp_path / ".gitlab-ci.yml").write_text(textwrap.dedent("""
            stages: [build]
            build:
              stage: build
              image: alpine:latest
              script: ['true']
        """))
        result = _dispatch("ciguard.scan_repo", {
            "repo_path": str(tmp_path),
            "offline": True,
            "no_ignore_file": True,
            "fail_on": "High",
        })
        # alpine:latest → PIPE-001 High → fails_threshold=True
        assert result["fails_threshold"] is True

    def test_scan_repo_missing_path_errors(self):
        result = _dispatch("ciguard.scan_repo", {
            "repo_path": "/tmp/does-not-exist-ciguard-test-repo",
        })
        assert "error" in result


# ---------------------------------------------------------------------------
# ciguard.diff_baseline
# ---------------------------------------------------------------------------


class TestDiffBaseline:
    def test_diff_returns_zero_changes_against_self(self, tmp_path):
        # Seed a baseline from the bad pipeline, then diff against the
        # same pipeline → zero new, zero resolved.
        from ciguard.analyzer.baseline import write_baseline
        from ciguard.analyzer.engine import AnalysisEngine
        from ciguard.parser.gitlab_parser import GitLabCIParser

        bad = FIXTURES / "bad_pipeline.yml"
        report = AnalysisEngine(enable_sca=False).analyse(
            GitLabCIParser().parse_file(bad), bad.name
        )
        baseline = tmp_path / "baseline.json"
        write_baseline(report, baseline)

        result = _dispatch("ciguard.diff_baseline", {
            "file_path": str(bad),
            "baseline_path": str(baseline),
            "offline": True,
        })
        assert result["new"] == []
        assert result["resolved"] == []
        assert result["score_delta"] == 0.0
        assert result["unchanged_count"] > 0

    def test_diff_with_missing_baseline_errors(self, tmp_path):
        result = _dispatch("ciguard.diff_baseline", {
            "file_path": str(FIXTURES / "bad_pipeline.yml"),
            "baseline_path": str(tmp_path / "nope.json"),
        })
        assert "error" in result


# ---------------------------------------------------------------------------
# Integration: serialised dispatch (the call_tool decorator returns
# JSON-encoded text content; verify our dict outputs serialise cleanly).
# ---------------------------------------------------------------------------


class TestEnterpriseGate:
    """`CIGUARD_MCP_DISABLED` env var gates the `ciguard mcp` subcommand
    so corporate sysadmins can prevent local MCP servers via MDM / Group
    Policy. Tests cover the truthy values, falsy values, and unset case."""

    def _run_main(self, env_value, monkeypatch):
        from ciguard.main import main
        if env_value is None:
            monkeypatch.delenv("CIGUARD_MCP_DISABLED", raising=False)
        else:
            monkeypatch.setenv("CIGUARD_MCP_DISABLED", env_value)
        monkeypatch.setattr("sys.argv", ["ciguard", "mcp"])
        # Stub the actual stdio runner so we don't block on real stdin.
        called = {"count": 0}
        def _fake_run_stdio():
            called["count"] += 1
        import ciguard.mcp.server as srv_mod
        monkeypatch.setattr(srv_mod, "run_stdio", _fake_run_stdio)
        rc = main()
        return rc, called["count"]

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "on"])
    def test_truthy_values_block_subcommand(self, value, monkeypatch, capsys):
        rc, called = self._run_main(value, monkeypatch)
        err = capsys.readouterr().err
        assert rc == 2, f"expected exit 2 for CIGUARD_MCP_DISABLED={value!r}"
        assert called == 0, "run_stdio must not be called when disabled"
        assert "disabled by policy" in err

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
    def test_falsy_or_empty_values_allow_subcommand(self, value, monkeypatch):
        rc, called = self._run_main(value, monkeypatch)
        assert rc == 0, f"expected exit 0 for CIGUARD_MCP_DISABLED={value!r}"
        assert called == 1, "run_stdio should be called when not disabled"

    def test_unset_env_var_allows_subcommand(self, monkeypatch):
        rc, called = self._run_main(None, monkeypatch)
        assert rc == 0
        assert called == 1


class TestJSONSerialisation:
    @pytest.mark.parametrize("tool,args", [
        ("ciguard.list_rules", {}),
        ("ciguard.explain_rule", {"rule_id": "PIPE-001"}),
        ("ciguard.scan", {"file_path": str(FIXTURES / "bad_pipeline.yml"),
                          "offline": True, "no_ignore_file": True}),
    ])
    def test_dispatch_result_is_json_serialisable(self, tool, args):
        result = _dispatch(tool, args)
        # Reproduce what call_tool() does in build_server().
        encoded = json.dumps(result, indent=2, default=str)
        assert encoded
        assert json.loads(encoded) == json.loads(encoded)  # round-trip ok
