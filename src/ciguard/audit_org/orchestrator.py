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
from typing import Any, Dict, List, Optional

from ..models.org_audit import OrgAuditReport, RepoScanRecord
from ..repo_scan import scan_repo
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
) -> OrgAuditReport:
    """Walk every repo in `org`, scan pipeline files, return aggregate.

    `offline=True` skips the SCA network calls inside `scan_repo()` —
    EOL/CVE enrichment falls back to the cache. The provider HTTP
    calls are NOT gated by `offline` — listing + fetching the
    pipeline files is the org audit's reason for being, and there's
    no useful fallback to a stale cache for that.
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

        record.scan = _scan_repo_files(files, offline=offline)
        report.repos.append(record)

    return report


def _scan_repo_files(
    files: List[Any],            # PipelineFile, but typing-loose to keep the import surface tight
    *,
    offline: bool,
) -> Dict[str, Any]:
    """Materialise pipeline files into a tempdir and invoke `scan_repo()`.
    Returns the same dict shape `scan_repo` always returns. The tempdir
    is cleaned up on exit; per-finding evidence is captured in the
    returned dict before the dir disappears."""
    with tempfile.TemporaryDirectory(prefix="ciguard-audit-org-") as tmp:
        tmpdir = Path(tmp)
        for f in files:
            target = tmpdir / f.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f.content, encoding="utf-8")
        return scan_repo(
            tmpdir,
            offline=offline,
            fail_on=None,
            no_ignore_file=True,
        )
