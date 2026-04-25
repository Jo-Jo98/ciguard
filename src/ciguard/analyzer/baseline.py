"""
Baseline I/O + delta calculation (v0.5).

A *baseline* is a JSON snapshot of a previous scan's findings keyed by
their stable fingerprints. A *delta* is the result of comparing a fresh
scan against that baseline:

  - **new** — fingerprint present in current, absent from baseline
  - **resolved** — fingerprint present in baseline, absent from current
  - **unchanged** — fingerprint present in both

Why fingerprints rather than `(rule_id, location)` tuples? Because real
pipelines drift in cosmetic ways (line numbers shift, evidence
whitespace varies between scanner versions, file reformatting). The
fingerprint is the single source of identity — see
`models.pipeline._compute_finding_fingerprint`.

Why JSON? Baselines are machine-generated and machine-consumed; CI
systems already shuttle JSON artefacts around. The format is also human-
inspectable for the rare case a developer wants to see what's been
acknowledged.

Default baseline location is `.ciguard/baseline.json` in the repo root,
matching the convention of `.trivyignore`, `.gitignore`, etc. Users can
override with `--baseline <path>` on every CLI command.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from .. import __version__
from ..models.pipeline import Delta, Finding, Report


BASELINE_FORMAT_VERSION = 1


def write_baseline(report: Report, path: Path) -> None:
    """Persist the current scan's findings as the new baseline.

    Stores the full Finding objects (not just fingerprints) so future
    deltas can render details about *resolved* findings — a fingerprint
    alone wouldn't tell you what was fixed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format_version": BASELINE_FORMAT_VERSION,
        "scanner_version": __version__,
        "scan_timestamp": report.scan_timestamp,
        "pipeline_name": report.pipeline_name,
        "platform": report.platform,
        "overall_score": report.risk_score.overall,
        "grade": report.risk_score.grade,
        "findings": [
            f.model_dump(mode="json") for f in report.findings
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict:
    """Read a baseline JSON file. Raises FileNotFoundError if absent —
    callers decide whether that's fatal or a soft 'no baseline configured'."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    fmt = data.get("format_version", 0)
    if fmt > BASELINE_FORMAT_VERSION:
        raise ValueError(
            f"Baseline at {path} was written by a newer ciguard "
            f"(format_version={fmt}, this version supports up to "
            f"{BASELINE_FORMAT_VERSION}). Upgrade ciguard to read it."
        )
    return data


def compute_delta(report: Report, baseline_data: dict, baseline_path: Path) -> Delta:
    """Diff the current scan against `baseline_data` (as returned by
    `load_baseline`) and return a populated Delta."""
    baseline_findings_raw = baseline_data.get("findings", [])
    baseline_fingerprints: Set[str] = {
        Finding(**f).fingerprint for f in baseline_findings_raw
    }
    current_fingerprints: Set[str] = {f.fingerprint for f in report.findings}

    # Index baseline findings by fingerprint so we can return rich Finding
    # objects for *resolved* (rather than just bare fingerprints).
    baseline_by_fp = {
        Finding(**f).fingerprint: Finding(**f) for f in baseline_findings_raw
    }

    new: List[Finding] = [
        f for f in report.findings if f.fingerprint not in baseline_fingerprints
    ]
    unchanged: List[Finding] = [
        f for f in report.findings if f.fingerprint in baseline_fingerprints
    ]
    resolved: List[Finding] = [
        baseline_by_fp[fp]
        for fp in baseline_fingerprints - current_fingerprints
    ]

    score_delta = round(
        report.risk_score.overall - baseline_data.get("overall_score", 0.0),
        1,
    )

    return Delta(
        baseline_path=str(baseline_path),
        baseline_timestamp=baseline_data.get("scan_timestamp", "unknown"),
        baseline_scanner_version=baseline_data.get("scanner_version", "unknown"),
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        score_delta=score_delta,
    )


def default_baseline_path(input_path: Path) -> Path:
    """Convention: `.ciguard/baseline.json` next to the pipeline file's
    repo root (or its containing directory if not in a git repo). Used
    when --baseline is given the empty string or `auto`."""
    candidate = input_path.resolve().parent / ".ciguard" / "baseline.json"
    return candidate
