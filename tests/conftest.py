"""
ciguard test-suite shared fixtures.

Currently a single autouse fixture: redirect the MCP audit log
(`Slice 15`) to a per-test tempfile so test runs don't accumulate
records in `~/.ciguard/mcp-audit.jsonl`. Without this, every CI build
that happens to invoke `_dispatch()` would append to the user's real
audit trail, which (a) leaks test runs into operator forensics and
(b) means tests are non-hermetic w.r.t. that file.

Tests that specifically exercise audit-log behaviour can override
`CIGUARD_MCP_AUDIT_PATH` themselves via `monkeypatch.setenv()`.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_mcp_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("CIGUARD_MCP_AUDIT_PATH", str(tmp_path / "mcp-audit.jsonl"))
