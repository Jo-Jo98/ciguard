"""
Cross-pipeline scan aggregation (Slice 16, session 3).

Joins a `Topology` (from `ciguard.topology.yml`) with a `scan-repo`
aggregate result (per-file scan reports) to answer the auditor's
'which environment carries the most risk?' question.

Pure function, no I/O. The renderer consumes the resulting dict; the
CLI handles file reading.

Output shape:

    {
        "by_env": {
            "<env_id>": {
                "Critical": N, "High": N, "Medium": N, "Low": N, "Info": N,
                "total": N,
                "files": [<repo-relative paths that matched>],
            },
            ...
        },
        "by_edge": {
            "<service_id>::<env_id>": {
                "Critical": N, ..., "total": N,
                "file": "<the matched pipeline path>",
            },
            ...
        },
        "unmatched_pipelines": [
            "<asserted pipeline path with no scan record>", ...
        ],
        "unmatched_files": [
            "<scanned file with no asserted DeployEdge>", ...
        ],
    }

Why both `unmatched_pipelines` and `unmatched_files`: drift detection.

  - An asserted edge whose pipeline is gone from the repo (rename /
    deletion) shows up in `unmatched_pipelines`. The audit narrative
    flags it as 'topology says X deploys to prod via Y, but Y was not
    found by scan-repo'.
  - A scanned pipeline file with no DeployEdge claiming it shows up in
    `unmatched_files`. The narrative flags it as 'this pipeline runs
    but the topology doesn't say what it deploys to'.

Both are auditor-relevant; the renderer surfaces them.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from ..models.topology import Topology

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _zero_counts() -> Dict[str, int]:
    return {sev: 0 for sev in _SEVERITIES}


def aggregate_scan_into_topology(
    topology: Topology,
    scan_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Join `scan_result` (output of `scan_repo()`) with `topology` to
    produce per-env and per-(service, env) finding aggregates plus
    drift lists. Returns the structure documented in the module
    docstring."""
    files = scan_result.get("files", []) or []
    # Index scan files by repo-relative path for O(1) lookup.
    by_path: Dict[str, Dict[str, Any]] = {}
    for f in files:
        if isinstance(f, dict) and isinstance(f.get("path"), str):
            by_path[f["path"]] = f

    edges = topology.deploy_edges
    matched_paths: set[str] = set()

    by_env: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {**_zero_counts(), "total": 0, "files": []}
    )
    by_edge: Dict[str, Dict[str, Any]] = {}
    unmatched_pipelines: List[str] = []

    for edge in edges:
        if not edge.pipeline:
            # Edge without a pipeline path can't be matched by file —
            # not drift, just under-specified. Skip silently.
            continue
        scan = by_path.get(edge.pipeline)
        if scan is None:
            unmatched_pipelines.append(edge.pipeline)
            continue
        matched_paths.add(edge.pipeline)
        sev_counts = scan.get("findings_by_severity") or {}
        edge_total = 0
        edge_record = {**_zero_counts(), "total": 0, "file": edge.pipeline}
        for sev in _SEVERITIES:
            n = int(sev_counts.get(sev, 0) or 0)
            edge_record[sev] = n
            edge_total += n
        edge_record["total"] = edge_total

        env_record = by_env[edge.environment]
        for sev in _SEVERITIES:
            env_record[sev] = env_record.get(sev, 0) + edge_record[sev]
        env_record["total"] = env_record.get("total", 0) + edge_total
        if edge.pipeline not in env_record["files"]:
            env_record["files"].append(edge.pipeline)

        # Composite key — `tuple` keys aren't JSON-serialisable, so
        # encode as `<svc>::<env>`. The HTML renderer + tests parse
        # this back when needed.
        key = f"{edge.service}::{edge.environment}"
        by_edge[key] = edge_record

    unmatched_files = [
        path for path in by_path.keys() if path not in matched_paths
    ]
    unmatched_files.sort()

    return {
        "by_env": dict(by_env),
        "by_edge": by_edge,
        "unmatched_pipelines": unmatched_pipelines,
        "unmatched_files": unmatched_files,
    }
