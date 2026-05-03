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
from .analyzer.sca.cross_pipeline import detect_drift
from .analyzer.sca.image_extractor import ImageReference, extract_images
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
    return_images: bool = False,
):
    """Scan a single pipeline file and return the full Report.

    Honours `.ciguardignore` discovery + per-file overrides identically
    to `cmd_scan` in `main.py`. Lifted out of the MCP server module so
    both MCP and the CLI scan-repo path share a single implementation.

    When `return_images=True`, returns `(report, [ImageReference, ...])`
    instead of bare report — used by `scan_repo()` for SCA-PIN-003
    cross-pipeline drift detection without having to re-parse the file.
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
    if return_images:
        return report, extract_images(target)
    return report


def scan_repo(
    repo_path: Path,
    *,
    offline: bool = False,
    fail_on: Optional[str] = None,
    no_ignore_file: bool = False,
    follow_symlinks: bool = False,
    include_findings: bool = False,
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
      - cross_pipeline_findings: SCA-PIN-003 drift findings — one entry
                             per image name referenced with different
                             tag/digest combinations across >1 file.
                             Empty list when no drift. Counts ARE rolled
                             into total_findings + by_severity so
                             --fail-on Medium gates on them.

    `fail_on` accepts None | "Critical" | "High" | "Medium" | "Low" | "Info".

    When `include_findings=True`, additional fields are added:
      - findings:           flat list across all files; each entry is a
                            Finding `model_dump()` extended with the
                            relative file path. Used by callers that need
                            individual finding objects (the App's PR-comment
                            renderer, baseline-delta diffing).
      - risk_score:         the LOWEST per-file overall score (min — the
                            worst pipeline gates the repo's posture).
                            None if `files_scanned == 0`.
      - grade:              the grade attached to the worst-score file.
                            None if `files_scanned == 0`.

    The default (`include_findings=False`) preserves the v0.9.x dict shape
    that `ciguard scan-repo` CLI and the MCP `scan_repo` tool depend on.
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
    all_findings: List[Dict[str, Any]] = []
    worst: Optional[tuple[float, str]] = None  # (score, grade) of lowest-scoring file
    # SCA-PIN-003 collects every image reference paired with its file so
    # cross-pipeline drift can be detected after the per-file loop.
    file_image_pairs: List[tuple[str, ImageReference]] = []

    for df in discovered:
        rel_path = str(df.path.relative_to(repo_path))
        try:
            scan_result = scan_one(
                df.path,
                platform=df.platform,
                offline=offline,
                no_ignore=no_ignore_file,
                return_images=True,
            )
            report, images = scan_result
            for img in images:
                file_image_pairs.append((rel_path, img))
        except Exception as exc:
            files.append({
                "path": rel_path,
                "platform": df.platform,
                "error": str(exc),
            })
            continue
        for f in report.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            total_findings += 1
            if include_findings:
                f_dict = f.model_dump(mode="json")
                f_dict["file"] = rel_path
                all_findings.append(f_dict)
        file_entry: Dict[str, Any] = {
            "path": rel_path,
            "platform": df.platform,
            "score": report.risk_score.overall,
            "grade": report.risk_score.grade,
            "findings_total": len(report.findings),
            "findings_by_severity": dict(report.summary["by_severity"]),
            "suppressed": len(report.suppressed),
        }
        if include_findings:
            file_entry["findings"] = [
                f.model_dump(mode="json") for f in report.findings
            ]
        files.append(file_entry)
        score = report.risk_score.overall
        if worst is None or score < worst[0]:
            worst = (score, report.risk_score.grade)

    # SCA-PIN-003 — cross-pipeline drift. Runs against every image
    # reference seen across every successfully-parsed pipeline file.
    # Emits a Medium-severity finding per drifting image name; counts
    # roll into total_findings + by_severity so --fail-on Medium gates
    # on them just like in-file findings would.
    drift_findings = detect_drift(file_image_pairs)
    cross_pipeline_findings = [d.to_dict() for d in drift_findings]
    for cf in cross_pipeline_findings:
        sev = cf["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        total_findings += 1

    fails_threshold = False
    if fail_on and fail_on in SEVERITY_ORDER:
        cutoff = SEVERITY_ORDER.index(fail_on)
        for sev_name, count in by_severity.items():
            if sev_name in SEVERITY_ORDER and SEVERITY_ORDER.index(sev_name) <= cutoff and count > 0:
                fails_threshold = True
                break

    result: Dict[str, Any] = {
        "repo_path": str(repo_path),
        "files_scanned": len(files),
        "total_findings": total_findings,
        "by_severity": by_severity,
        "fail_on": fail_on,
        "fails_threshold": fails_threshold,
        "files": files,
        "cross_pipeline_findings": cross_pipeline_findings,
    }
    if include_findings:
        result["findings"] = all_findings
        result["risk_score"] = worst[0] if worst is not None else None
        result["grade"] = worst[1] if worst is not None else None
    return result
