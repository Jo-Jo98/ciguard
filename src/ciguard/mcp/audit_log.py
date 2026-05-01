"""
MCP invocation audit log (Slice 15).

Every tool call lands one JSON Lines record at `~/.ciguard/mcp-audit.jsonl`
(or `$CIGUARD_MCP_AUDIT_PATH` when set). The record captures:

    {
      "ts": "2026-05-02T11:34:21.123456+00:00",   ISO 8601 UTC
      "tool": "ciguard.scan",
      "redact_level": "full",
      "args": {...},                              redacted at the active level
      "response_bytes": 12453,                    post-redaction encoded length
      "had_error": false                          true iff the response carries
                                                  a top-level "error" key
    }

Why a flat JSONL on disk rather than syslog / OTel:

  - Zero infrastructure dependency — works in air-gapped, single-laptop,
    and corp-laptop deployments alike (matches CIGUARD_MCP_DISABLED's
    "MDM-friendly env-var-only policy" framing).
  - Operator can `tail -f` it in real time during incident response.
  - Append-only single file is the simplest possible shape that a SIEM
    (Splunk forwarder / Loki promtail / cloud-init log shipper) can pick up.

Off-by-default? No — this is the audit *floor*, not opt-in instrumentation.
An LLM agent calling the MCP tools is acting on the user's behalf; the user
deserves a tamper-evident record of what was asked, even at `raw` level.
Disable explicitly via `CIGUARD_MCP_AUDIT_DISABLED=1` for ephemeral lab
runs (matches the `CIGUARD_MCP_DISABLED` truthy-value convention).

Threat model: Surface 10 (MCP-mediated data exfiltration) — the audit log
is the after-the-fact detective control that complements `redact()`'s
preventive control.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Truthy value set mirrors `CIGUARD_MCP_DISABLED` for consistency.
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _is_truthy(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def is_disabled(env: Optional[Dict[str, str]] = None) -> bool:
    source = env if env is not None else os.environ
    return _is_truthy(source.get("CIGUARD_MCP_AUDIT_DISABLED"))


def audit_path() -> Path:
    """Resolved log path. Honours `CIGUARD_MCP_AUDIT_PATH` for tests +
    operator overrides; defaults to `~/.ciguard/mcp-audit.jsonl`."""
    raw = os.environ.get("CIGUARD_MCP_AUDIT_PATH")
    if raw and raw.strip():
        return Path(raw).expanduser()
    return Path.home() / ".ciguard" / "mcp-audit.jsonl"


def write_event(event: Dict[str, Any]) -> Optional[Path]:
    """Append one JSONL record. Best-effort — never raises into the caller.
    Audit failures are logged to stderr (visible to operators running
    `ciguard mcp` interactively) but do NOT poison the response.

    Returns the path written to, or `None` when audit is disabled / the
    write failed silently."""
    if is_disabled():
        return None
    path = audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
        return path
    except OSError as exc:
        # Stderr only — do not ever raise out of audit code.
        try:
            import sys
            sys.stderr.write(f"[ciguard-mcp-audit] write failed: {exc}\n")
        except Exception:
            pass
        return None


def make_event(
    *,
    tool: str,
    args_summary: Dict[str, Any],
    redact_level: str,
    response_bytes: int,
    had_error: bool,
) -> Dict[str, Any]:
    """Construct the JSONL record body. Kept as its own function so tests
    can build expected events without going through I/O."""
    return {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "tool": tool,
        "redact_level": redact_level,
        "args": args_summary.get("args", {}),
        "response_bytes": response_bytes,
        "had_error": bool(had_error),
    }


__all__ = [
    "audit_path",
    "is_disabled",
    "make_event",
    "write_event",
]
