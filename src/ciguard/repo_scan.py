"""Repository-level pipeline scanning (v0.9.0).

Discovers every pipeline file under a directory tree and scans each one,
returning a per-file summary plus aggregated severity counts. Used by:

  - the `ciguard scan-repo` CLI subcommand (v0.9.0)
  - the `ciguard.scan_repo` MCP tool (v0.8.x — was inlined; now delegates here)

The two callers want exactly the same structure, so the logic lives in a
single place to keep their behaviour in lock-step.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzer.engine import AnalysisEngine
from .discovery import discover_pipeline_files
from .ignore import (
    apply_ignores,
    discover_ignore_file,
    load_ignore_file,
)
from .models.pipeline import Severity
from .parser.github_actions import GitHubActionsParser, detect_format
from .parser.gitlab_parser import GitLabCIParser
from .parser.jenkinsfile import JenkinsfileParser, looks_like_jenkinsfile


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _detect_platform(path: Path, override: str = "auto") -> str:
    if override != "auto":
        return override
    if looks_like_jenkinsfile(path):
        return "jenkins"
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return detect_format(raw) if isinstance(raw, dict) else "gitlab-ci"
    except Exception:
        return "gitlab-ci"


def scan_one(
    path: Path,
    *,
    platform: str = "auto",
    offline: bool = False,
    ignore_file: Optional[Path] = None,
    no_ignore: bool = False,
):
    """Scan a single pipeline file and return the full Report.

    Honours `.ciguardignore` discovery + per-file overrides identically
    to `cmd_scan` in `main.py`. Lifted out of the MCP server module so
    both MCP and the CLI scan-repo path share a single implementation.
    """
    plat = _detect_platform(path, platform)
    if plat == "github-actions":
        target = GitHubActionsParser().parse_file(path)
    elif plat == "jenkins":
        target = JenkinsfileParser().parse_file(path)
    else:
        target = GitLabCIParser().parse_file(path)
    engine = AnalysisEngine(sca_offline=offline)
    report = engine.analyse(target, pipeline_name=path.name)

    if not no_ignore:
        ig_path = ignore_file
        if ig_path is None:
            ig_path = discover_ignore_file(path)
        if ig_path is not None and ig_path.exists():
            try:
                load_result = load_ignore_file(ig_path)
            except ValueError as exc:
                report.ignore_warnings.append(str(exc))
                load_result = None
            if load_result is not None and load_result.rules:
                kept, suppressed, expired = apply_ignores(
                    report.findings, load_result.rules
                )
                report.findings = kept
                report.suppressed = suppressed
                report.ignore_warnings.extend(expired)
                report.ignore_file_path = str(ig_path)
                report.summary = engine._build_summary(report.findings)
                report.risk_score = engine._calculate_risk(report.findings)
    return report


def scan_repo(
    repo_path: Path,
    *,
    offline: bool = False,
    fail_on: Optional[str] = None,
    no_ignore_file: bool = False,
    follow_symlinks: bool = False,
) -> Dict[str, Any]:
    """Discover and scan every pipeline file under `repo_path`.

    Returns a dict with:
      - repo_path:           absolute string of the scan root
      - files_scanned:       int
      - total_findings:      int across all files
      - by_severity:         {Critical|High|Medium|Low|Info: count}
      - fail_on:             the severity threshold passed in, if any
      - fails_threshold:     bool — True iff any finding at-or-above `fail_on`
      - files:               per-file list (path, platform, score, grade,
                             findings_total, findings_by_severity, suppressed,
                             or {error: ...} on parser failure)

    `fail_on` accepts None | "Critical" | "High" | "Medium" | "Low" | "Info".
    """
    repo_path = Path(repo_path).expanduser()
    if not repo_path.exists():
        return {"error": f"Path not found: {repo_path}"}

    discovered = discover_pipeline_files(
        repo_path, follow_symlinks=follow_symlinks
    )
    files: List[Dict[str, Any]] = []
    by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
    total_findings = 0

    for df in discovered:
        try:
            report = scan_one(
                df.path,
                platform=df.platform,
                offline=offline,
                no_ignore=no_ignore_file,
            )
        except Exception as exc:
            files.append({
                "path": str(df.path.relative_to(repo_path)),
                "platform": df.platform,
                "error": str(exc),
            })
            continue
        for f in report.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            total_findings += 1
        files.append({
            "path": str(df.path.relative_to(repo_path)),
            "platform": df.platform,
            "score": report.risk_score.overall,
            "grade": report.risk_score.grade,
            "findings_total": len(report.findings),
            "findings_by_severity": dict(report.summary["by_severity"]),
            "suppressed": len(report.suppressed),
        })

    fails_threshold = False
    if fail_on and fail_on in SEVERITY_ORDER:
        cutoff = SEVERITY_ORDER.index(fail_on)
        for sev_name, count in by_severity.items():
            if sev_name in SEVERITY_ORDER and SEVERITY_ORDER.index(sev_name) <= cutoff and count > 0:
                fails_threshold = True
                break

    return {
        "repo_path": str(repo_path),
        "files_scanned": len(files),
        "total_findings": total_findings,
        "by_severity": by_severity,
        "fail_on": fail_on,
        "fails_threshold": fails_threshold,
        "files": files,
    }
