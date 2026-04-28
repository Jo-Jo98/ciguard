"""
Pipeline file auto-discovery (v0.8.0).

Walks a directory tree and returns every pipeline file ciguard can scan.
Used by the MCP server's `scan_repo` tool — and a future Slice 9
`ciguard scan-repo` CLI subcommand will use the same helper.

Discovery is deliberately conservative: filename + content sniff only,
no parsing here. The caller dispatches to the right parser per platform.

Conventions matched:
  - GitLab CI:        `.gitlab-ci.yml` at any depth
  - GitHub Actions:   `.github/workflows/*.yml` and `*.yaml`
  - Jenkins:          `Jenkinsfile`, `Jenkinsfile.*`, `*.jenkinsfile`,
                      `*.groovy` (with content sniff to filter out
                      non-pipeline groovy)

Excludes by default: `.git/`, `node_modules/`, `venv/`, `.venv/`,
`__pycache__/`, `.tox/`, `dist/`, `build/`, `.pytest_cache/`. Pass
`exclude_dirs=...` to override.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set

import re

# We deliberately do NOT use `parser.jenkinsfile.looks_like_jenkinsfile`
# here because that helper accepts any `.groovy` suffix unconditionally
# (it's the right behaviour for the explicit `--input` CLI path, where
# the user has already pointed at a single file). For repo discovery
# we need to be stricter: a Gradle / Spring / Grails project full of
# `.groovy` files should not be flooded with "Jenkinsfile" hits. We
# require an actual `pipeline {` or `node('...') {` token to classify.
_PIPELINE_MARKER = re.compile(r"\b(pipeline\s*\{|node\s*\()")

_DEFAULT_EXCLUDES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
}


@dataclass(frozen=True)
class DiscoveredFile:
    """A pipeline file found by the discovery walk. `platform` is one of
    `gitlab-ci`, `github-actions`, `jenkins`."""

    path: Path
    platform: str


def _is_excluded(part: str, exclude_dirs: Set[str]) -> bool:
    return part in exclude_dirs


def discover_pipeline_files(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
    follow_symlinks: bool = False,
) -> List[DiscoveredFile]:
    """Walk `root` and return every recognised pipeline file.

    `follow_symlinks` defaults to False: symlinked directories AND symlinked
    files are skipped. This prevents path-escape attacks where an attacker
    plants a symlink in a directory the user (or AI agent) scans, causing
    discovery to read pipeline-shaped files from outside `root`. Callers
    with a legitimate reason to follow can opt in explicitly.

    Defence-in-depth: even with `follow_symlinks=True`, results are
    filtered to those whose `.resolve()` lies under `root.resolve()`.
    """
    excludes = set(exclude_dirs) if exclude_dirs is not None else set(_DEFAULT_EXCLUDES)
    if not root.exists():
        return []

    try:
        root_resolved = root.resolve()
    except OSError:
        return []

    found: List[DiscoveredFile] = []
    visited_dirs: Set[Path] = set()

    def walk(d: Path) -> None:
        # Skip symlinked directories unless explicitly opted in.
        if not follow_symlinks and d.is_symlink():
            return
        try:
            resolved = d.resolve()
        except OSError:
            return
        if resolved in visited_dirs:
            return
        visited_dirs.add(resolved)

        try:
            entries = list(d.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            if entry.is_dir():
                if _is_excluded(entry.name, excludes):
                    continue
                walk(entry)
                continue
            if not entry.is_file():
                continue
            # Skip symlinked files too (a symlink can target a regular file
            # outside root that iterdir() reports as a file).
            if not follow_symlinks and entry.is_symlink():
                continue

            platform = _classify(entry)
            if platform is not None:
                found.append(DiscoveredFile(path=entry, platform=platform))

    walk(root)

    # Belt-and-braces: filter results to those that actually live under the
    # resolved root. Catches any symlink-following surface the walker missed
    # (e.g. opt-in `follow_symlinks=True` callers).
    def _under_root(p: Path) -> bool:
        try:
            p.resolve().relative_to(root_resolved)
            return True
        except (OSError, ValueError):
            return False

    found = [df for df in found if _under_root(df.path)]

    # Stable sort for deterministic output: by path string.
    found.sort(key=lambda df: str(df.path))
    return found


def _classify(path: Path) -> Optional[str]:
    name = path.name

    # GitLab CI
    if name == ".gitlab-ci.yml" or name == ".gitlab-ci.yaml":
        return "gitlab-ci"

    # GitHub Actions — must live under a `.github/workflows/` segment
    parts = path.parts
    for idx, part in enumerate(parts):
        if part == ".github" and idx + 1 < len(parts) and parts[idx + 1] == "workflows":
            if name.endswith(".yml") or name.endswith(".yaml"):
                return "github-actions"
            break

    # Jenkins — filename-first
    if name == "Jenkinsfile" or name.startswith("Jenkinsfile."):
        return "jenkins"
    if name.endswith(".jenkinsfile"):
        return "jenkins"

    # Groovy needs a content sniff — most .groovy files in a repo are
    # NOT Jenkinsfiles (Gradle, Spring, Grails, etc.). Only classify
    # when the file actually contains `pipeline {` or `node('...') {`.
    if name.endswith(".groovy"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
            if _PIPELINE_MARKER.search(head):
                return "jenkins"
        except OSError:
            # Best-effort content sniff. Permission denied / I/O error on a
            # discovery walk is not fatal — fall through and skip the file.
            pass

    return None


__all__ = ["DiscoveredFile", "discover_pipeline_files"]
