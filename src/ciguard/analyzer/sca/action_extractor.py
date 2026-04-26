"""
GitHub Actions reference extraction for SCA-CVE-001.

Walks a parsed `Workflow` and pulls out every `uses:` reference, structured
into the `(owner/repo, version, ref_kind, location)` shape SCA-CVE-001 needs
for OSV.dev lookups.

A `uses:` value can take several shapes:

  uses: actions/checkout@v4                         # tag (mutable)
  uses: actions/checkout@v4.1.0                     # specific tag
  uses: actions/checkout@a1b2c3d...0123 (40 hex)    # commit SHA (immutable)
  uses: actions/checkout@main                       # branch (mutable, dangerous)
  uses: org/repo/.github/workflows/x.yml@v1         # reusable workflow
  uses: ./local-action                              # local path (no @ref)
  uses: ./.github/actions/my-action                 # local path
  uses: docker://ghcr.io/owner/image:tag            # Docker action

For SCA-CVE-001 we care about marketplace-published actions and reusable
workflows pinned to a tag/version we can query OSV with. We deliberately
SKIP:
  - SHA-pinned refs (can't resolve SHA → version cheaply; this is
    Dependabot's lane).
  - Local refs (`./...`) — no upstream to query.
  - Docker-action refs (`docker://...`) — different ecosystem.
  - Branch-style refs (`@main`, `@master`, `@develop`) — no version.

Reusable workflows look like `org/repo/.github/workflows/x.yml@ref`. OSV's
GHSA index treats them under the same `org/repo` package as the actions
published from that repo, so we collapse `org/repo/.github/...` → `org/repo`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from ...models.workflow import Workflow

# Branch names we treat as "no version, skip". Includes the most common
# default branches plus a few others projects use as floating refs.
_BRANCH_REFS: set[str] = {
    "main", "master", "develop", "dev", "trunk", "default", "next",
}

# Anything that's purely "v" + version digits is a tag we can query.
# Examples: v1, v4.0.0, 2025.04.0, 1.2, 4. Also accept refs without leading
# `v` if they look version-shaped: 1.2.3, 4.0.0.
_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)*(?:[.-][a-zA-Z0-9]+)*$")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class ActionReference:
    """A single GHA `uses:` reference, normalised for OSV lookup."""
    raw: str                        # full original `uses:` string
    location: str                   # job/step path for the report
    owner_repo: str                 # `actions/checkout` style
    version: str                    # the @ref portion (tag/version only — never a SHA)
    is_reusable_workflow: bool      # was the original `org/repo/.github/workflows/x.yml`?

    @property
    def normalised_version(self) -> str:
        """Strip a leading `v` for OSV queries — OSV's GitHub Actions
        ecosystem indexes versions without the `v` prefix in most entries
        but accepts both. Strip to be consistent with the cache key."""
        return self.version.lstrip("v")


def parse_uses(raw: str, location: str) -> Optional[ActionReference]:
    """Parse a `uses:` value into an `ActionReference` if it points at a
    queryable upstream marketplace action / reusable workflow with a
    version-shaped ref. Returns `None` for everything we can't or shouldn't
    look up (SHA-pinned, local, docker, branch refs)."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    # Local refs.
    if raw.startswith("./") or raw.startswith("../"):
        return None
    # Docker actions.
    if raw.startswith("docker://"):
        return None
    if "@" not in raw:
        # No version pin at all — out of scope (PIPE-style rules already
        # handle missing pins on actions where applicable).
        return None
    pkg_part, ref = raw.rsplit("@", 1)
    pkg_part = pkg_part.strip()
    ref = ref.strip()
    if not pkg_part or not ref:
        return None

    # Reusable workflow shape: `org/repo/.github/workflows/x.yml`.
    is_workflow = "/.github/workflows/" in pkg_part
    if is_workflow:
        owner_repo = pkg_part.split("/.github/workflows/", 1)[0]
    else:
        # Marketplace action: must be `owner/repo` (exactly two segments
        # before any subpath). Reject anything that doesn't split cleanly.
        parts = pkg_part.split("/")
        if len(parts) < 2:
            return None
        owner_repo = "/".join(parts[:2])

    if "/" not in owner_repo:
        return None

    # Skip SHA-pinned refs — Dependabot's lane.
    if _SHA_RE.match(ref):
        return None
    # Skip branch-style refs.
    if ref.lower() in _BRANCH_REFS:
        return None
    # Only proceed if the ref looks version-shaped.
    if not _VERSION_RE.match(ref):
        return None

    return ActionReference(
        raw=raw,
        location=location,
        owner_repo=owner_repo,
        version=ref,
        is_reusable_workflow=is_workflow,
    )


def extract_action_references(workflow: Workflow) -> List[ActionReference]:
    """Walk a Workflow and return every queryable `uses:` reference.

    Includes both step-level (`steps[*].uses`) and job-level
    (`jobs.<id>.uses` reusable workflow calls). Returns an empty list for
    workflows with no marketplace/reusable references.
    """
    out: List[ActionReference] = []
    for job in workflow.jobs:
        if job.uses:
            ref = parse_uses(job.uses, f"job[{job.id}].uses")
            if ref:
                out.append(ref)
        for idx, step in enumerate(job.steps):
            if step.uses:
                step_label = step.name or f"step[{idx}]"
                ref = parse_uses(
                    step.uses,
                    f"job[{job.id}].{step_label}",
                )
                if ref:
                    out.append(ref)
    return out
