"""
ciguard org-level audit (Slice 17).

Walks every repo in a GitHub organisation (or GitLab group), runs
`scan_repo()` against the pipeline files in each, and rolls the
results up into a multi-repo posture dashboard.

Distinct from the rest of ciguard:
- `scan` runs against ONE pipeline file
- `scan-repo` runs against ONE repository's tree
- `audit-org` runs across N repositories under one organisation,
  with cross-repo aggregation answering 'where are the gaps and the
  inconsistencies?'

The `OrgProvider` Protocol is the abstraction seam — GitHubOrgProvider
ships first; GitLab / Bitbucket / Azure DevOps fit the same shape
(`list_repos(org)` + `fetch_pipeline_files(repo)`).

Public surface:
- `audit_org(org, provider, ...)` — the orchestrator
- `OrgProvider` Protocol — for tests + future provider implementations
- `GitHubOrgProvider` — concrete GitHub.com / GHE implementation
- `github_org_provider_from_env()` — convenience factory matching
  the `topology.verify` convention (`CIGUARD_GITHUB_TOKEN` env var)
- `OrgProviderError` — raised on platform-API failures
"""
from .orchestrator import audit_org
from .provider import (
    GitHubOrgProvider,
    OrgProvider,
    OrgProviderError,
    PipelineFile,
    RepoInfo,
    github_org_provider_from_env,
)

__all__ = [
    "GitHubOrgProvider",
    "OrgProvider",
    "OrgProviderError",
    "PipelineFile",
    "RepoInfo",
    "audit_org",
    "github_org_provider_from_env",
]
