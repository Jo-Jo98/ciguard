"""
Tests for the MCP redaction layer + audit log (Slice 15).

These cover the unit-level shape of the transforms and the end-to-end
contract via `_dispatch()`. The full MCP server integration tests live in
`test_mcp_server.py`; this file is the redaction / audit micro-spec.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.mcp import audit_log, redaction
from ciguard.mcp.server import _dispatch

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# resolve_level — env-var parsing
# ---------------------------------------------------------------------------

class TestResolveLevel:
    def test_default_is_full(self):
        assert redaction.resolve_level(env={}) == redaction.LEVEL_FULL

    def test_explicit_full(self):
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "full"}) == "full"

    def test_explicit_partial(self):
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "partial"}) == "partial"

    def test_explicit_raw(self):
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "raw"}) == "raw"

    def test_case_insensitive(self):
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "RAW"}) == "raw"
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "  Full  "}) == "full"

    def test_unknown_value_falls_back_to_full(self):
        # Conservative-by-default: unknown / typo'd levels DO NOT silently
        # leak through as `raw`. Operator misconfiguration falls toward
        # the safer end of the spectrum.
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "off"}) == "full"
        assert redaction.resolve_level(env={"CIGUARD_MCP_REDACT_LEVEL": "verbose"}) == "full"


# ---------------------------------------------------------------------------
# fingerprint — stability
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_starts_with_marker(self):
        assert redaction.fingerprint("anything").startswith(redaction.REDACT_MARKER_PREFIX)

    def test_stable_across_calls(self):
        a = redaction.fingerprint("image: alpine:latest")
        b = redaction.fingerprint("image: alpine:latest")
        assert a == b

    def test_different_inputs_different_outputs(self):
        a = redaction.fingerprint("image: alpine:latest")
        b = redaction.fingerprint("image: alpine:3.18")
        assert a != b

    def test_8_char_hex_after_marker(self):
        out = redaction.fingerprint("x")
        assert len(out) == len(redaction.REDACT_MARKER_PREFIX) + 8


# ---------------------------------------------------------------------------
# redact() — per-level transforms
# ---------------------------------------------------------------------------

def _sample_response() -> dict:
    """A representative tool response containing every field the redaction
    layer cares about."""
    return {
        "pipeline_name": "/Users/joe/repos/acme/.gitlab-ci.yml",
        "file_path": "/Users/joe/repos/acme/.gitlab-ci.yml",
        "baseline_path": "/Users/joe/repos/acme/.ciguard/baseline.json",
        "findings": [
            {
                "rule_id": "PIPE-001",
                "evidence": "image: alpine:latest",
                "location": "job[build].image",
            },
            {
                "rule_id": "IAM-001",
                "evidence": "AWS_SECRET_ACCESS_KEY: hunter2",
                "location": "variables.AWS_SECRET_ACCESS_KEY",
            },
        ],
        "score": {"overall": 65.0, "grade": "C"},
    }


class TestRedactFull:
    def test_evidence_replaced_with_fingerprint(self):
        out = redaction.redact(_sample_response(), level="full")
        for f in out["findings"]:
            assert f["evidence"].startswith(redaction.REDACT_MARKER_PREFIX)

    def test_paths_collapsed_to_basename(self):
        out = redaction.redact(_sample_response(), level="full")
        assert out["file_path"] == ".gitlab-ci.yml"
        assert out["baseline_path"] == "baseline.json"
        assert out["pipeline_name"] == ".gitlab-ci.yml"

    def test_non_path_fields_unchanged(self):
        out = redaction.redact(_sample_response(), level="full")
        assert out["findings"][0]["rule_id"] == "PIPE-001"
        assert out["findings"][0]["location"] == "job[build].image"
        assert out["score"]["grade"] == "C"

    def test_input_not_mutated(self):
        original = _sample_response()
        snapshot = json.dumps(original)
        redaction.redact(original, level="full")
        assert json.dumps(original) == snapshot


class TestRedactPartial:
    def test_evidence_preserved(self):
        out = redaction.redact(_sample_response(), level="partial")
        evidences = [f["evidence"] for f in out["findings"]]
        assert "image: alpine:latest" in evidences

    def test_paths_collapsed_to_basename_when_no_mcp_root(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_MCP_ROOT", raising=False)
        out = redaction.redact(_sample_response(), level="partial")
        assert out["file_path"] == ".gitlab-ci.yml"

    def test_paths_relative_to_mcp_root_when_set(self, monkeypatch, tmp_path):
        nested = tmp_path / "acme" / ".gitlab-ci.yml"
        nested.parent.mkdir(parents=True)
        nested.write_text("stages: []\n")
        monkeypatch.setenv("CIGUARD_MCP_ROOT", str(tmp_path))
        payload = {"file_path": str(nested)}
        out = redaction.redact(payload, level="partial")
        assert out["file_path"] == "<repo>/acme/.gitlab-ci.yml"


class TestRedactRaw:
    def test_passes_through(self):
        sample = _sample_response()
        out = redaction.redact(sample, level="raw")
        assert out["file_path"] == sample["file_path"]
        assert out["findings"][0]["evidence"] == sample["findings"][0]["evidence"]


# ---------------------------------------------------------------------------
# Size cap
# ---------------------------------------------------------------------------

class TestSizeCap:
    def test_partial_cap_truncates_findings(self):
        # `partial` preserves evidence, so a large finding count blows the
        # 1 MB cap quickly. Use `location` (not redacted at any level) to
        # push payload size deterministically.
        big_finding = {
            "rule_id": "PIPE-001",
            "evidence": "image: alpine:latest",
            "location": "x" * 10_000,
        }
        payload = {"findings": [dict(big_finding) for _ in range(200)]}
        out = redaction.redact(payload, level="partial")
        assert out.get("truncated") is True
        assert len(out["findings"]) <= 25
        assert "truncation_reason" in out

    def test_full_cap_truncates_when_overrun(self):
        # `full` fingerprints evidence — to overflow 256 KB we need bulk in
        # a non-redacted field. `location` carries through at every level.
        big_finding = {
            "rule_id": "PIPE-001",
            "evidence": "image: alpine:latest",
            "location": "x" * 4_000,
        }
        payload = {"findings": [dict(big_finding) for _ in range(100)]}
        out = redaction.redact(payload, level="full")
        assert out.get("truncated") is True
        assert len(out["findings"]) <= 25

    def test_raw_cap_high_enough_for_normal_responses(self):
        out = redaction.redact(_sample_response(), level="raw")
        assert "truncated" not in out


# ---------------------------------------------------------------------------
# args_summary — the audit-log feed
# ---------------------------------------------------------------------------

class TestArgsSummary:
    def test_paths_redacted_at_full(self):
        summary = redaction.args_summary(
            "ciguard.scan",
            {"file_path": "/Users/joe/secret-project/.gitlab-ci.yml"},
            level="full",
        )
        assert summary["tool"] == "ciguard.scan"
        assert summary["args"]["file_path"] == ".gitlab-ci.yml"

    def test_unknown_keys_passthrough(self):
        # Unknown args (`platform`, `offline`) aren't path-bearing — leave
        # them alone so audit consumers see exactly what was requested.
        summary = redaction.args_summary(
            "ciguard.scan",
            {"file_path": "/x/y.yml", "platform": "gitlab-ci", "offline": True},
            level="full",
        )
        assert summary["args"]["platform"] == "gitlab-ci"
        assert summary["args"]["offline"] is True


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_write_event_appends_jsonl(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(log))
        for i in range(3):
            audit_log.write_event(audit_log.make_event(
                tool="ciguard.scan",
                args_summary={"args": {"file_path": "x.yml"}},
                redact_level="full",
                response_bytes=100 + i,
                had_error=False,
            ))
        lines = log.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        for ln in lines:
            event = json.loads(ln)
            assert event["tool"] == "ciguard.scan"
            assert event["redact_level"] == "full"

    def test_disabled_short_circuits(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(log))
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_DISABLED", "1")
        result = audit_log.write_event(audit_log.make_event(
            tool="ciguard.scan",
            args_summary={"args": {}},
            redact_level="full",
            response_bytes=0,
            had_error=False,
        ))
        assert result is None
        assert not log.exists()

    def test_event_carries_iso_timestamp(self):
        ev = audit_log.make_event(
            tool="ciguard.scan",
            args_summary={"args": {}},
            redact_level="full",
            response_bytes=0,
            had_error=False,
        )
        # Round-trip via fromisoformat — raises if not parseable.
        from datetime import datetime
        datetime.fromisoformat(ev["ts"])


# ---------------------------------------------------------------------------
# End-to-end: _dispatch redacts + audits
# ---------------------------------------------------------------------------

class TestDispatchRedacts:
    def test_default_full_fingerprints_evidence(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_MCP_REDACT_LEVEL", raising=False)
        out = _dispatch("ciguard.scan", {
            "file_path": str(FIXTURES / "bad_pipeline.yml"),
            "offline": True,
            "no_ignore_file": True,
        })
        # Every finding should have a fingerprinted evidence by default.
        evidences = [f.get("evidence", "") for f in out["findings"]]
        assert evidences, "expected findings on bad_pipeline"
        assert all(e.startswith(redaction.REDACT_MARKER_PREFIX) for e in evidences if e)

    def test_raw_level_passes_evidence_through(self, monkeypatch):
        monkeypatch.setenv("CIGUARD_MCP_REDACT_LEVEL", "raw")
        out = _dispatch("ciguard.scan", {
            "file_path": str(FIXTURES / "bad_pipeline.yml"),
            "offline": True,
            "no_ignore_file": True,
        })
        evidences = [f.get("evidence", "") for f in out["findings"]]
        assert any(":" in e or "=" in e for e in evidences if e), \
            "raw level should preserve at least one literal evidence string"

    def test_paths_collapsed_in_full_response(self, monkeypatch):
        monkeypatch.delenv("CIGUARD_MCP_REDACT_LEVEL", raising=False)
        bad = FIXTURES / "bad_pipeline.yml"
        out = _dispatch("ciguard.scan", {
            "file_path": str(bad),
            "offline": True,
            "no_ignore_file": True,
        })
        # `pipeline_name` is in `_PATH_FIELD_NAMES` — should be basename only.
        # Pre-redaction it would carry the absolute path.
        assert "/" not in out["pipeline_name"]


class TestDispatchAudits:
    def test_dispatch_writes_audit_record(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(log))
        monkeypatch.delenv("CIGUARD_MCP_AUDIT_DISABLED", raising=False)
        _dispatch("ciguard.list_rules", {})
        assert log.exists()
        line = log.read_text(encoding="utf-8").splitlines()[-1]
        event = json.loads(line)
        assert event["tool"] == "ciguard.list_rules"
        assert event["redact_level"] in ("full", "partial", "raw")
        assert event["response_bytes"] > 0
        assert event["had_error"] is False

    def test_audit_records_error_responses(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(log))
        monkeypatch.delenv("CIGUARD_MCP_AUDIT_DISABLED", raising=False)
        _dispatch("ciguard.scan", {"file_path": "/tmp/does-not-exist-xyz.yml"})
        line = log.read_text(encoding="utf-8").splitlines()[-1]
        event = json.loads(line)
        assert event["had_error"] is True

    def test_audit_args_obey_redaction_level(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(log))
        monkeypatch.delenv("CIGUARD_MCP_AUDIT_DISABLED", raising=False)
        monkeypatch.delenv("CIGUARD_MCP_REDACT_LEVEL", raising=False)  # default full
        _dispatch("ciguard.scan", {
            "file_path": str(FIXTURES / "bad_pipeline.yml"),
            "offline": True,
        })
        event = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        # `file_path` arg should be basename only at the default `full` level.
        assert event["args"]["file_path"] == "bad_pipeline.yml"
