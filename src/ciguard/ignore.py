"""
.ciguardignore loader (v0.7.0).

File-based suppression of ciguard findings. Modelled on Bandit's `# nosec`
inline pattern — adapted for the YAML / external-file shape since pipeline
files (.gitlab-ci.yml / GitHub Actions workflows / Jenkinsfiles) do not have
a universal inline-comment convention ciguard could rely on.

Design constraints (deliberate, see PRD Slice 7):

- **Every entry MUST have a non-trivial `reason`.** Naked rule-id-only
  disables are rejected at load time. This stops the "developer just
  silenced the rule that fired" antipattern and forces a written
  justification that auditors can read.
- **Suppressions are visible in the report.** Suppressed findings are not
  silently dropped — they appear in a dedicated "Suppressed" section so the
  posture is auditable. The report still shows zero "active" findings if
  every finding is suppressed; nothing is hidden.
- **Optional `expires` date.** Suppressions can be time-bounded. Expired
  entries emit a warning but still suppress (the team has already
  acknowledged the finding; the warning is a nudge to revisit, not a
  regression).
- **Optional `location` filter.** Restricts suppression to findings whose
  `location` string contains the supplied substring. Common case: silence
  PIPE-001 only on a specific job, not pipeline-wide.

File format (`.ciguardignore`, YAML list at the repo root or alongside
the pipeline file):

```yaml
- rule_id: PIPE-001
  location: "deploy_prod"
  reason: "We pin to digest in the parent template; this image is intentionally tag-tracked"
  expires: 2026-12-31
- rule_id: SCA-EOL-003
  reason: "Internal mirror keeps an old Python alive past upstream EOL"
```
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import yaml
from pydantic import BaseModel, field_validator


_MIN_REASON_LENGTH = 10
"""Minimum non-whitespace characters in a `reason` field. Enough to force a
real sentence (not "fix later" or "skip"). Tunable; 10 is empirically the
shortest length that consistently produces something an auditor can read."""

DEFAULT_IGNORE_FILENAME = ".ciguardignore"


class IgnoreRule(BaseModel):
    """A single suppression entry parsed from a `.ciguardignore` file."""

    rule_id: str
    reason: str
    location: Optional[str] = None
    expires: Optional[_dt.date] = None

    @field_validator("rule_id")
    @classmethod
    def _rule_id_non_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("rule_id must not be empty")
        return v

    @field_validator("reason")
    @classmethod
    def _reason_substantive(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < _MIN_REASON_LENGTH:
            raise ValueError(
                f"reason must be at least {_MIN_REASON_LENGTH} characters "
                f"of substance (got {len(stripped)!r}). Naked rule-id-only "
                "disables are rejected on purpose — auditors need to read "
                "why a finding was suppressed."
            )
        return stripped

    def matches(self, finding_rule_id: str, finding_location: str) -> bool:
        """True iff this entry applies to a finding with the given rule_id
        and location. Case-sensitive on rule_id; substring match on location
        when set."""
        if self.rule_id != finding_rule_id:
            return False
        if self.location is None:
            return True
        return self.location in finding_location

    def is_expired(self, today: Optional[_dt.date] = None) -> bool:
        if self.expires is None:
            return False
        ref = today or _dt.date.today()
        return ref > self.expires


@dataclass
class IgnoreLoadResult:
    """Result of loading a `.ciguardignore` file. The path is preserved for
    diagnostic / report-rendering purposes."""

    path: Path
    rules: List[IgnoreRule] = field(default_factory=list)
    parse_warnings: List[str] = field(default_factory=list)


def load_ignore_file(path: Path) -> IgnoreLoadResult:
    """Parse a `.ciguardignore` file. Raises `ValueError` for syntactically
    invalid YAML or for entries that violate the design constraints (missing
    `reason`, non-list top level, etc.). Returns an empty result if the file
    is missing — callers that want to require a file should check existence
    first."""
    if not path.exists():
        return IgnoreLoadResult(path=path, rules=[])

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML — {exc}") from exc

    if raw is None:
        return IgnoreLoadResult(path=path, rules=[])

    if not isinstance(raw, list):
        raise ValueError(
            f"{path}: top-level must be a YAML list of suppression entries, "
            f"got {type(raw).__name__}."
        )

    rules: List[IgnoreRule] = []
    warnings: List[str] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path}: entry #{idx + 1} must be a mapping, got "
                f"{type(entry).__name__}."
            )
        if "reason" not in entry or entry["reason"] is None:
            raise ValueError(
                f"{path}: entry #{idx + 1} (rule_id={entry.get('rule_id')!r}) "
                "is missing a `reason` field. Every suppression MUST include "
                "a written justification — naked rule-id-only disables are "
                "rejected by design."
            )
        try:
            rules.append(IgnoreRule(**entry))
        except Exception as exc:
            raise ValueError(f"{path}: entry #{idx + 1} — {exc}") from exc

    return IgnoreLoadResult(path=path, rules=rules, parse_warnings=warnings)


def discover_ignore_file(start: Path) -> Optional[Path]:
    """Walk up from `start` looking for `.ciguardignore`. Stops at the
    filesystem root or at a `.git` directory (the conventional repo
    boundary). Returns the first match, or None."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while True:
        candidate = cur / DEFAULT_IGNORE_FILENAME
        if candidate.is_file():
            return candidate
        if (cur / ".git").exists():
            return None
        if cur.parent == cur:
            return None
        cur = cur.parent


def apply_ignores(
    findings: list,
    rules: List[IgnoreRule],
    today: Optional[_dt.date] = None,
) -> Tuple[list, list, List[str]]:
    """Partition findings into (kept, suppressed) lists and produce a list
    of human-readable warning strings for any expired entries that fired.

    Suppressed findings retain their original Finding objects unmodified —
    callers attach them to `Report.suppressed` so reporters can render the
    audit trail."""
    if not rules:
        return list(findings), [], []

    today = today or _dt.date.today()
    kept: list = []
    suppressed: list = []
    expired_hits: dict = {}  # rule_id+location → entry that fired

    for finding in findings:
        match: Optional[IgnoreRule] = None
        for rule in rules:
            if rule.matches(finding.rule_id, finding.location):
                match = rule
                break
        if match is None:
            kept.append(finding)
            continue
        suppressed.append(finding)
        if match.is_expired(today):
            key = f"{match.rule_id}@{match.location or '*'}"
            expired_hits[key] = match

    warnings = [
        f"Suppression for {entry.rule_id} (location={entry.location or '*'}) "
        f"expired on {entry.expires.isoformat()} — review and renew or remove."
        for entry in expired_hits.values()
    ]
    return kept, suppressed, warnings


__all__ = [
    "DEFAULT_IGNORE_FILENAME",
    "IgnoreLoadResult",
    "IgnoreRule",
    "apply_ignores",
    "discover_ignore_file",
    "load_ignore_file",
]
