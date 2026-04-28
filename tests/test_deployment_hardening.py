"""Tests for the v0.9.1 deployment-hardening surfaces:

- #9  CIGUARD_WEB_TOKEN bearer-token auth on web API
- #10 CIGUARD_MCP_ROOT workspace allowlist on MCP scan tools
- #13 CIGUARD_NO_SCANNERS kill-switch
- #12 LLM redaction + --llm-consent gate

Issue #11 (Dockerfile base bump) is verified by the regression-cycle1 job
(CYCLE-1-002 PoC re-runs against the fresh build).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest


# ---- Issue #9: web API auth -------------------------------------------------


class TestWebAuth:
    """Bearer-token gate via CIGUARD_WEB_TOKEN."""

    def _client(self):
        from fastapi.testclient import TestClient
        from ciguard.web.app import app
        return TestClient(app)

    def test_no_token_set_means_no_auth(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_WEB_TOKEN", raising=False)
        client = self._client()
        # /api/health is always ungated regardless
        assert client.get("/api/health").status_code == 200
        # /api/report/missing returns 404 (not 401) — auth is off
        r = client.get("/api/report/does-not-exist")
        assert r.status_code == 404

    def test_token_set_blocks_unauthenticated(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_WEB_TOKEN", "s3cret")
        client = self._client()
        r = client.get("/api/report/anything")
        assert r.status_code == 401
        assert r.headers.get("www-authenticate") == "Bearer"

    def test_token_set_accepts_correct_bearer(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_WEB_TOKEN", "s3cret")
        client = self._client()
        # Hit a gated route with the right token. /api/report/{id} returns
        # 404 for an unknown id, which proves we passed the auth gate.
        r = client.get(
            "/api/report/missing",
            headers={"Authorization": "Bearer s3cret"},
        )
        assert r.status_code == 404

    def test_token_set_rejects_wrong_bearer(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_WEB_TOKEN", "s3cret")
        client = self._client()
        r = client.get(
            "/api/report/missing",
            headers={"Authorization": "Bearer not-the-token"},
        )
        assert r.status_code == 401

    def test_health_endpoint_always_ungated(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_WEB_TOKEN", "s3cret")
        client = self._client()
        # No Authorization header, but health still 200 — by design (k8s probes)
        assert client.get("/api/health").status_code == 200

    def test_warn_loopback_no_warning(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_WEB_TOKEN", raising=False)
        from ciguard.web.auth import warn_if_public_bind_unauthenticated
        assert warn_if_public_bind_unauthenticated("127.0.0.1") is None
        assert warn_if_public_bind_unauthenticated("::1") is None
        assert warn_if_public_bind_unauthenticated("localhost") is None

    def test_warn_public_bind_no_token(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_WEB_TOKEN", raising=False)
        from ciguard.web.auth import warn_if_public_bind_unauthenticated
        msg = warn_if_public_bind_unauthenticated("0.0.0.0")
        assert msg is not None
        assert "CIGUARD_WEB_TOKEN" in msg

    def test_warn_public_bind_with_token_silent(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_WEB_TOKEN", "s3cret")
        from ciguard.web.auth import warn_if_public_bind_unauthenticated
        assert warn_if_public_bind_unauthenticated("0.0.0.0") is None


# ---- Issue #10: MCP workspace allowlist -------------------------------------


class TestMCPWorkspaceAllowlist:
    """CIGUARD_MCP_ROOT defence-in-depth on CYCLE-1-001."""

    def test_no_root_set_allows_anything(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CIGUARD_MCP_ROOT", raising=False)
        from ciguard.mcp.server import _enforce_workspace
        assert _enforce_workspace(tmp_path) is None
        assert _enforce_workspace(Path("/etc")) is None

    def test_root_set_allows_path_inside(self, tmp_path, monkeypatch):
        sub = tmp_path / "inside"
        sub.mkdir()
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(tmp_path))
        from ciguard.mcp.server import _enforce_workspace
        assert _enforce_workspace(sub) is None

    def test_root_set_blocks_path_outside(self, tmp_path, monkeypatch):
        outside = tmp_path / "outside"
        outside.mkdir()
        # Make root a sibling sub-directory
        root = tmp_path / "allowed"
        root.mkdir()
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(root))
        from ciguard.mcp.server import _enforce_workspace
        deny = _enforce_workspace(outside)
        assert deny is not None
        assert "CIGUARD_MCP_ROOT" in deny["error"]

    def test_root_set_blocks_traversal(self, tmp_path, monkeypatch):
        # Even with `..` in the path, resolve() collapses before the prefix check.
        root = tmp_path / "allowed"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        traversal = root / ".." / "outside"
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(root))
        from ciguard.mcp.server import _enforce_workspace
        deny = _enforce_workspace(traversal)
        assert deny is not None
        assert "outside" in deny["error"].lower() or "CIGUARD_MCP_ROOT" in deny["error"]

    def test_scan_tool_honours_allowlist(self, tmp_path, monkeypatch):
        # Place a real workflow inside the allowlist + scan it.
        root = tmp_path / "allowed"
        root.mkdir()
        wf = root / "workflow.yml"
        wf.write_text("name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(root))
        from ciguard.mcp.server import _tool_scan
        result = _tool_scan({"file_path": str(wf), "platform": "github-actions", "offline": True})
        assert "error" not in result, result

    def test_scan_tool_blocks_path_outside_allowlist(self, tmp_path, monkeypatch):
        root = tmp_path / "allowed"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        wf = outside / "workflow.yml"
        wf.write_text("name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(root))
        from ciguard.mcp.server import _tool_scan
        result = _tool_scan({"file_path": str(wf), "platform": "github-actions"})
        assert "error" in result
        assert "CIGUARD_MCP_ROOT" in result["error"]


# ---- Issue #13: --no-scanners kill-switch -----------------------------------


class TestNoScanners:
    def test_disabled_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CIGUARD_NO_SCANNERS", "1")
        from ciguard.scanners.runner import run_all_scanners
        # Should short-circuit to [] without iterating scanners.
        assert run_all_scanners(tmp_path) == []

    def test_enabled_default_runs(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CIGUARD_NO_SCANNERS", raising=False)
        from ciguard.scanners.runner import run_all_scanners
        # Will return [] because the binaries aren't on the runner's PATH,
        # but the function should at least iterate (no env-gate short-circuit).
        # We can't observe iteration directly without internals, so just check
        # the return type and that it didn't raise.
        result = run_all_scanners(tmp_path)
        assert isinstance(result, list)

    def test_truthy_values(self, monkeypatch):
        from ciguard.scanners.runner import _scanners_disabled
        for v in ["1", "true", "True", "YES", "on"]:
            monkeypatch.setenv("CIGUARD_NO_SCANNERS", v)
            assert _scanners_disabled(), v
        for v in ["0", "false", "no", "off", ""]:
            monkeypatch.setenv("CIGUARD_NO_SCANNERS", v)
            assert not _scanners_disabled(), v


# ---- Issue #12: LLM redaction + consent -------------------------------------


class TestLLMRedaction:
    def _make_finding(self):
        from ciguard.models.pipeline import (
            Category, ComplianceMapping, Finding, Severity,
        )
        return Finding(
            id="f1",
            rule_id="GHA-IAM-001",
            name="Test rule",
            severity=Severity.HIGH,
            category=Category.IDENTITY_ACCESS,
            location="my-secret-pipeline.yml::deploy.steps[2]",
            description="desc",
            evidence="MY_TOKEN=ghp_abc****",
            remediation="rem",
            compliance=ComplianceMapping(),
        )

    def test_evidence_always_stripped(self):
        from ciguard.llm.enricher import _sanitise_finding
        out = _sanitise_finding(self._make_finding(), redact_locations=False)
        assert "evidence" not in out
        assert out["location"] == "my-secret-pipeline.yml::deploy.steps[2]"

    def test_redact_locations_hashes_path(self):
        from ciguard.llm.enricher import _sanitise_finding
        out = _sanitise_finding(self._make_finding(), redact_locations=True)
        assert "evidence" not in out
        assert out["location"].startswith("redacted:")
        assert "my-secret-pipeline" not in out["location"]
        assert "deploy.steps" not in out["location"]

    def test_redact_is_stable(self):
        from ciguard.llm.enricher import _redact
        assert _redact("foo.yml") == _redact("foo.yml")
        assert _redact("foo.yml") != _redact("bar.yml")
        assert _redact("foo.yml").startswith("redacted:")

    def test_consent_gate_blocks_llm_without_flag(self, tmp_path, monkeypatch):
        # Run cmd_scan with --llm but no --llm-consent → exit 1 + stderr explainer
        import subprocess
        wf = tmp_path / "workflow.yml"
        wf.write_text("name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")  # ensure key existence isn't the cause
        result = subprocess.run(
            [sys.executable, "-m", "ciguard.main", "scan", "--input", str(wf),
             "--llm", "--llm-provider", "anthropic", "--offline"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "--llm-consent" in result.stderr
        assert "rule names" in result.stderr or "metadata" in result.stderr
