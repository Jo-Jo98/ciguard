"""
Org-level audit report data model (Slice 17).

The org audit walks every repo in a GitHub org (or GitLab group) and
produces a posture dashboard that combines the per-repo scan output
into an org-wide picture: which repos have findings, how the grades
distribute, where the inconsistencies sit (base images, pin discipline,
infrastructure versions). Distinct from the per-pipeline `Report`
(parsed from one CI file), the per-org `InventoryReport` (live admin-API
audit of CI/CD tooling), and the cross-pipeline `Topology` (operator-
asserted deployment graph).

Entities:
- `RepoScanRecord` — one repo's scan-repo output + metadata
- `OrgAuditReport` — aggregate root: org id, list of records, summary
  statistics, inconsistency callouts

Pure data — analysis lives in `ciguard.audit_org.analysis`. Renderer
in `ciguard.reporter.org_audit_html`. Orchestration in
`ciguard.audit_org.orchestrator`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Severity order matches the rest of ciguard (Critical→Info). Used for
# grade distributions + sort orders. Keep in sync with `Severity` enum
# in `models.pipeline`.
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
GRADE_ORDER = ("A", "B", "C", "D", "F")


class RepoScanRecord(BaseModel):
    """One repo's scan-repo output bundled with provider metadata.

    `scan` is the raw `scan_repo()` dict (see `repo_scan.py`). We keep
    it as a dict rather than a pydantic model because (a) the existing
    consumers (HTML reporter, MCP) all consume it as a dict and (b)
    it's already serialisable. `error` is set when the repo couldn't
    be scanned at all (no clone access, fetch failure, no pipeline
    files); per-file scan errors live inside `scan["files"]`.
    """
    repo: str                     # `owner/name`
    default_branch: Optional[str] = None
    private: bool = False
    archived: bool = False
    fork: bool = False
    description: Optional[str] = None
    scan: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    pipeline_file_count: int = 0   # how many CI files we found in the repo

    @property
    def total_findings(self) -> int:
        if not self.scan:
            return 0
        return int(self.scan.get("total_findings", 0))

    @property
    def grade(self) -> Optional[str]:
        """Worst grade across pipeline files in this repo, or None when
        the repo has no scannable files / errored out. We pick the worst
        because the org dashboard wants 'how bad is this repo at its
        weakest point' as a single signal."""
        if not self.scan:
            return None
        files = self.scan.get("files") or []
        grades = [f.get("grade") for f in files if isinstance(f, dict) and f.get("grade")]
        if not grades:
            return None
        # GRADE_ORDER is best→worst; pick the last (worst).
        for grade in reversed(GRADE_ORDER):
            if grade in grades:
                return grade
        return None


class OrgAuditReport(BaseModel):
    """Aggregate root for an org-level audit run."""
    org: str
    provider: str = "github"      # `github` for now; `gitlab` follows
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    repos: List[RepoScanRecord] = Field(default_factory=list)
    repo_filter: Optional[Dict[str, Any]] = None  # {include, exclude, limit}
    skipped_archived: int = 0
    skipped_forks: int = 0
    errors: List[Dict[str, str]] = Field(default_factory=list)

    # ---- aggregate accessors ----

    @property
    def repos_scanned(self) -> int:
        return sum(1 for r in self.repos if r.scan is not None)

    @property
    def repos_with_findings(self) -> int:
        return sum(1 for r in self.repos if r.total_findings > 0)

    @property
    def total_findings(self) -> int:
        return sum(r.total_findings for r in self.repos)

    @property
    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
        for r in self.repos:
            if not r.scan:
                continue
            for sev, n in (r.scan.get("by_severity") or {}).items():
                if sev in out:
                    out[sev] += int(n or 0)
        return out

    @property
    def grade_distribution(self) -> Dict[str, int]:
        """How many repos sit at each grade. Repos with no scannable
        files are bucketed under `'?'` so the dashboard sums to the
        total repo count."""
        out: Dict[str, int] = {g: 0 for g in GRADE_ORDER}
        out["?"] = 0
        for r in self.repos:
            grade = r.grade
            if grade in out:
                out[grade] += 1
            else:
                out["?"] += 1
        return out

    @property
    def platforms_detected(self) -> Dict[str, int]:
        """Per-platform pipeline-file counts across the org. Useful
        signal for 'are we one-platform-per-org or do we have a mix?'
        — common org-shape question."""
        out: Dict[str, int] = {}
        for r in self.repos:
            if not r.scan:
                continue
            for f in (r.scan.get("files") or []):
                if isinstance(f, dict):
                    plat = f.get("platform") or "unknown"
                    out[plat] = out.get(plat, 0) + 1
        return out
