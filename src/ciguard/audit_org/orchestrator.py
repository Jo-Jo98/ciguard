"""
Org-level audit orchestrator (Slice 17).

`audit_org(org, provider, ...)` walks every repo in the org, fetches
the pipeline files via the provider, materialises them into a
tempdir, runs `scan_repo()` against the tempdir, and bundles the
results into an `OrgAuditReport`.

Why materialise to disk: `scan_repo()` is a `Path`-based API used by
the existing `ciguard scan-repo` CLI + the MCP `scan_repo` tool. Rather
than re-plumbing those three callers through an in-memory variant, we
write each repo's pipeline files into a tempdir and call the existing
helper. Keeps the org audit honest — every per-file finding the org
audit reports is the same finding `scan-repo` would have reported run
locally against a clone.

Filtering: `include` / `exclude` are regex patterns on `full_name`
(`owner/name`). `limit` caps the number of repos audited (after
filtering, before scanning). Forks + archived repos default to
skipped because they typically host stale pipelines that shouldn't
move the org's posture score; both can be re-enabled with explicit
flags. The exclusions are recorded on the report so the auditor sees
how the universe was narrowed.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, List, Optional

from ..discovery import discover_pipeline_files
from ..models.org_audit import OrgAuditReport, RepoScanRecord
from ..repo_scan import scan_one, scan_repo
from ..reporter import html_interactive
from .images import extract_repo_images
from .provider import OrgProvider, OrgProviderError


def audit_org(
    org: str,
    provider: OrgProvider,
    *,
    include: Optional[str] = None,
    exclude: Optional[str] = None,
    limit: Optional[int] = None,
    include_archived: bool = False,
    include_forks: bool = False,
    offline: bool = False,
    repo_map_dir: Optional[Path] = None,
) -> OrgAuditReport:
    """Walk every repo in `org`, scan pipeline files, return aggregate.

    `offline=True` skips the SCA network calls inside `scan_repo()` —
    EOL/CVE enrichment falls back to the cache. The provider HTTP
    calls are NOT gated by `offline` — listing + fetching the
    pipeline files is the org audit's reason for being, and there's
    no useful fallback to a stale cache for that.

    `repo_map_dir` writes one `html-interactive` pipeline map per
    pipeline file under `<dir>/repos/<owner>__<name>/<stem>.html` so
    the org dashboard can link to a per-repo drill-down. None
    (default) skips map rendering — the dashboard alone is the
    deliverable. Errors in the per-file map render are silently
    swallowed so a single bad file doesn't blank the whole audit.
    """
    include_re = re.compile(include) if include else None
    exclude_re = re.compile(exclude) if exclude else None

    report = OrgAuditReport(
        org=org,
        provider=getattr(provider, "name", "unknown"),
        repo_filter={
            "include": include,
            "exclude": exclude,
            "limit": limit,
            "include_archived": include_archived,
            "include_forks": include_forks,
        },
    )

    try:
        all_repos = provider.list_repos(org)
    except OrgProviderError as exc:
        report.errors.append({"phase": "list_repos", "error": str(exc)})
        return report

    skipped_archived = 0
    skipped_forks = 0
    selected = []
    for repo_info in all_repos:
        if include_re and not include_re.search(repo_info.full_name):
            continue
        if exclude_re and exclude_re.search(repo_info.full_name):
            continue
        if repo_info.archived and not include_archived:
            skipped_archived += 1
            continue
        if repo_info.fork and not include_forks:
            skipped_forks += 1
            continue
        selected.append(repo_info)
        if limit is not None and len(selected) >= limit:
            break

    report.skipped_archived = skipped_archived
    report.skipped_forks = skipped_forks

    for repo_info in selected:
        record = RepoScanRecord(
            repo=repo_info.full_name,
            default_branch=repo_info.default_branch,
            private=repo_info.private,
            archived=repo_info.archived,
            fork=repo_info.fork,
            description=repo_info.description,
        )
        try:
            files = provider.fetch_pipeline_files(repo_info.full_name)
        except OrgProviderError as exc:
            record.error = str(exc)
            report.errors.append({
                "repo": repo_info.full_name,
                "phase": "fetch_pipeline_files",
                "error": str(exc),
            })
            report.repos.append(record)
            continue

        record.pipeline_file_count = len(files)
        if not files:
            # Repo has no recognised pipeline files — record presence
            # but skip the scan. Common case for empty / docs-only repos.
            report.repos.append(record)
            continue

        scan_result, images, maps = _scan_and_extract(
            files, offline=offline,
            repo=repo_info.full_name,
            repo_map_dir=repo_map_dir,
        )
        record.scan = scan_result
        record.images = images
        record.maps = maps
        report.repos.append(record)

    return report


def _scan_and_extract(
    files: List[Any],            # PipelineFile, but typing-loose to keep the import surface tight
    *,
    offline: bool,
    repo: str,
    repo_map_dir: Optional[Path] = None,
) -> tuple:
    """Materialise pipeline files into a tempdir, run `scan_repo()`,
    harvest the cross-org image inventory off the same tree, and
    optionally render one html-interactive map per pipeline file.
    Returns `(scan_dict, image_records, map_records)`.

    Map rendering is best-effort — if it fails for one file, the
    other files still render and the dashboard still ships.
    """
    map_records: List[dict] = []
    with tempfile.TemporaryDirectory(prefix="ciguard-audit-org-") as tmp:
        tmpdir = Path(tmp)
        for f in files:
            target = tmpdir / f.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f.content, encoding="utf-8")
        scan_dict = scan_repo(
            tmpdir,
            offline=offline,
            fail_on=None,
            no_ignore_file=True,
        )
        try:
            image_records = extract_repo_images(tmpdir)
        except Exception:
            # Image extraction is best-effort — the scan path is the
            # authoritative posture surface. A failure here shouldn't
            # mask the rest of the audit.
            image_records = []
        if repo_map_dir is not None:
            map_records = _render_repo_maps(tmpdir, repo, repo_map_dir, offline=offline)
    return scan_dict, image_records, map_records


# Filesystem-safe transform of `owner/name` for the maps dir layout.
# Slashes break path semantics; everything else passes through. Reuses
# the same shape across owner + name so the dashboard's link
# construction stays simple.
def _safe_repo_dirname(repo: str) -> str:
    return repo.replace("/", "__")


def _safe_file_stem(path: str) -> str:
    """Translate a pipeline file's repo-relative path to a filesystem-
    friendly stem. `.github/workflows/ci.yml` →
    `github_workflows__ci.yml`. Keeps the file structure visible in
    the maps directory listing without nesting deeper than one level."""
    # Drop a leading dot on hidden dirs (`.github` → `github`) so the
    # output dir doesn't have hidden subdirs that look-the-same to
    # `ls`. Then collapse path separators.
    parts = [p.lstrip(".") for p in path.split("/") if p]
    if not parts:
        return "pipeline"
    return "__".join(parts)


def _render_repo_maps(
    tmpdir: Path,
    repo: str,
    repo_map_dir: Path,
    *,
    offline: bool,
) -> List[dict]:
    """Render one html-interactive page per discovered pipeline file
    in `tmpdir`. Returns a list of `{path, file, href}` dicts the
    dashboard uses to link to each map.

    `path` is the source pipeline file's repo-relative path; `file`
    is the rendered HTML file's name; `href` is the dashboard-
    relative URL."""
    out: List[dict] = []
    repo_dir = repo_map_dir / "repos" / _safe_repo_dirname(repo)
    repo_dir.mkdir(parents=True, exist_ok=True)
    for df in discover_pipeline_files(tmpdir):
        rel_path = str(df.path.relative_to(tmpdir))
        try:
            report = scan_one(
                df.path,
                platform=df.platform,
                offline=offline,
                no_ignore=True,
            )
        except Exception:
            # Per-file failure logs no error to the report (the scan
            # path already captured it) — we just don't render a map
            # for this file.
            continue
        try:
            file_name = _safe_file_stem(rel_path) + ".html"
            dest = repo_dir / file_name
            html_interactive.write_report(report, dest)
        except Exception:
            continue
        out.append({
            "path": rel_path,
            "file": file_name,
            "href": f"repos/{_safe_repo_dirname(repo)}/{file_name}",
        })
    return out
