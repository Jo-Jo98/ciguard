"""
MCP response redaction (Slice 15).

Every MCP tool response passes through `redact()` before it reaches the
client. Three levels, configured via `CIGUARD_MCP_REDACT_LEVEL`:

    full     (default) — most defensible posture for corporate environments.
                         Absolute paths collapsed to basenames. Every
                         finding's `evidence` field replaced with a stable
                         8-char SHA-256 fingerprint (`redacted:abc12345`)
                         so an LLM client can still de-dupe / reference
                         findings without seeing the underlying string.
                         `pipeline_name` collapsed to the file basename.
                         Response capped at 256 KB.
    partial            — paths relative to CIGUARD_MCP_ROOT (or basename
                         if MCP_ROOT not set). Evidence preserved.
                         Response capped at 1 MB.
    raw                — passthrough. Response capped at 10 MB as a memory-
                         exhaustion floor; otherwise no transform.

Why default `full`: the MCP boundary is the most porous data egress channel
ciguard has (LLM client may persist responses indefinitely, share them with
other agents, summarise them into long-lived chat history). Conservative
default; operators opt down to `partial` / `raw` per environment.

Threat model: Surface 10 (MCP-mediated data exfiltration), see
Project ciguard/THREAT_MODEL.md.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Levels (lowercased for case-insensitive env reads).
LEVEL_FULL = "full"
LEVEL_PARTIAL = "partial"
LEVEL_RAW = "raw"

_VALID_LEVELS = frozenset({LEVEL_FULL, LEVEL_PARTIAL, LEVEL_RAW})

# Per-level response size caps. JSON-serialised byte length is the gate.
# `full` is small because the LLM doesn't need raw text — fingerprints
# carry enough signal for de-dup. `raw` is a safety floor against an
# unbounded scan response OOM-killing the MCP host.
_SIZE_CAPS_BYTES: Dict[str, int] = {
    LEVEL_FULL:    256 * 1024,
    LEVEL_PARTIAL: 1024 * 1024,
    LEVEL_RAW:     10 * 1024 * 1024,
}

# Marker that callers (and tests) can scan for to detect a redacted response.
REDACT_MARKER_PREFIX = "redacted:"

# Field names that hold a finding's raw evidence string. We redact these
# at LEVEL_FULL only.
_EVIDENCE_FIELD_NAMES = frozenset({"evidence"})

# Field names whose value is a filesystem path. We collapse these to basename
# (LEVEL_FULL) or relative-to-MCP-ROOT (LEVEL_PARTIAL). Add aggressively
# when a new tool surfaces another path-bearing field.
_PATH_FIELD_NAMES = frozenset({
    "file_path",
    "baseline_path",
    "ignore_file_path",
    "repo_path",
    "path",
    "pipeline_name",
})


def resolve_level(env: Optional[Dict[str, str]] = None) -> str:
    """Return the active redaction level, reading `CIGUARD_MCP_REDACT_LEVEL`
    from `env` (defaults to `os.environ`). Unknown / empty values fall
    back to `full` — fail-safe-by-default rather than fail-open. The fall-
    back is silent; the audit log records the level actually applied so
    misconfiguration is post-hoc detectable."""
    source = env if env is not None else os.environ
    raw = (source.get("CIGUARD_MCP_REDACT_LEVEL") or "").strip().lower()
    if raw in _VALID_LEVELS:
        return raw
    return LEVEL_FULL


def fingerprint(value: str) -> str:
    """Stable 8-char SHA-256 prefix tagged with the `redacted:` marker.
    Same value → same fingerprint across calls and across machines, so
    an LLM agent can still de-dupe findings without seeing the string."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"{REDACT_MARKER_PREFIX}{digest[:8]}"


def _abbreviate_path(value: str, level: str) -> str:
    """Collapse an absolute path to a less-leaky form per level. Strings
    that don't look like paths pass through unchanged.

    Detection is heuristic — anything that would `Path(...).is_absolute()`
    or starts with `~/`. We don't shell out to `realpath` (CYCLE-1-001
    rationale: never expand user-influenced strings into filesystem ops
    on the redaction path)."""
    if not isinstance(value, str) or not value:
        return value
    if not (value.startswith("/") or value.startswith("~/") or value.startswith("./")
            or (len(value) > 2 and value[1] == ":")):  # win drive letter
        return value
    p = Path(value)
    if level == LEVEL_FULL:
        # Just the basename — strips org/repo/dir layout entirely.
        return p.name or value
    if level == LEVEL_PARTIAL:
        root_raw = os.environ.get("CIGUARD_MCP_ROOT")
        if root_raw:
            try:
                root = Path(root_raw).expanduser().resolve()
                rel = p.expanduser().resolve().relative_to(root)
                return f"<repo>/{rel.as_posix()}"
            except (ValueError, OSError):
                pass
        return p.name or value
    return value          # LEVEL_RAW


def _walk(node: Any, level: str) -> Any:
    """Recursively walk a JSON-serialisable tree applying the per-level
    transforms in place via copy. Pure function — input not mutated."""
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        for k, v in node.items():
            if k in _EVIDENCE_FIELD_NAMES and level == LEVEL_FULL and isinstance(v, str) and v:
                out[k] = fingerprint(v)
            elif k in _PATH_FIELD_NAMES and isinstance(v, str) and level != LEVEL_RAW:
                out[k] = _abbreviate_path(v, level)
            else:
                out[k] = _walk(v, level)
        return out
    if isinstance(node, list):
        return [_walk(item, level) for item in node]
    return node


def _enforce_size_cap(payload: Any, level: str) -> Any:
    """If the JSON-serialised payload exceeds the cap for `level`, clip the
    list-shaped sub-payloads (`findings`, `suppressed`, `new`, `resolved`,
    `rules`) to a small fixed slice and add `truncated: True` plus a
    human-readable `truncation_reason`. We chose truncation over total
    refusal because a truncated response is still actionable; a 413-equiv
    error blocks the workflow entirely.

    Behavioural delta consumers should know about: when the cap fires, each
    list-shaped sub-payload is **clipped to a fixed 25-element slice**
    rather than packed-to-just-under-cap. A reader expecting "almost
    everything minus a few entries" will instead receive a small marker
    sample. This is intentional — packing-to-fit gives LLM clients a
    partial dataset that LOOKS complete (encouraging retries against an
    arbitrarily-trimmed slice), whereas the fixed-25 slice plus the
    `truncated` flag forces consumers to detect "this is not the full
    set" deterministically and either lower the redact level or rerun
    against a narrower scan.

    Caps (per `_SIZE_CAPS_BYTES`):
      - `full`:    256 KB  (after fingerprinting + path abbreviation)
      - `partial`: 1 MB    (evidence preserved; paths abbreviated)
      - `raw`:     10 MB   (passthrough — safety floor only)

    Empirical example (Cycle 1.5 row 10.6, 2026-05-03): 1.6 MB input at
    `partial` collapses to ~27 KB out, not ~1 MB out. Cycle 1.5 row 10.6
    documents the full input/output table. See issue #21 for context."""
    cap = _SIZE_CAPS_BYTES.get(level, _SIZE_CAPS_BYTES[LEVEL_FULL])
    encoded = json.dumps(payload, default=str)
    if len(encoded) <= cap:
        return payload
    if not isinstance(payload, dict):
        return payload          # nothing to truncate; let it through
    truncated = dict(payload)
    truncated["truncated"] = True
    truncated["truncation_reason"] = (
        f"Response exceeded {cap} bytes at redact level {level!r}; "
        "list-shaped fields below have been clipped. Lower CIGUARD_MCP_REDACT_LEVEL "
        "or run a narrower scan if you need the full payload."
    )
    for list_field in ("findings", "suppressed", "new", "resolved", "rules"):
        if isinstance(truncated.get(list_field), list):
            truncated[list_field] = truncated[list_field][:25]
    return truncated


def redact(payload: Any, level: Optional[str] = None) -> Any:
    """Apply per-level redaction transforms + size cap to a tool response.

    `level` overrides the env-var read; pass `None` (default) to read
    `CIGUARD_MCP_REDACT_LEVEL`. Returns a new dict — input is not mutated."""
    active = level if level in _VALID_LEVELS else resolve_level()
    walked = _walk(payload, active)
    return _enforce_size_cap(walked, active)


def args_summary(tool: str, args: Dict[str, Any], level: str) -> Dict[str, Any]:
    """Produce a redaction-aware summary of a tool's args for the audit log.

    The audit log MUST NOT re-leak what the redaction layer just stripped —
    so we apply the SAME transforms to the args we apply to the response.
    Keys are preserved; values are walked through `_walk()` so paths +
    evidence-bearing fields get the redaction treatment they would in any
    response."""
    return {
        "tool": tool,
        "args": _walk(args, level),
    }


__all__ = [
    "LEVEL_FULL",
    "LEVEL_PARTIAL",
    "LEVEL_RAW",
    "REDACT_MARKER_PREFIX",
    "args_summary",
    "fingerprint",
    "redact",
    "resolve_level",
]
