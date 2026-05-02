"""
Tests for the cross-pipeline scan aggregator (Slice 16, session 3).

Covers the three pieces of the new contract:
  - per-environment severity totals (sum across every pipeline that
    deploys to that env, dedup-counted across services)
  - per-(service, env) severity counts
  - drift lists (asserted pipelines not scanned + scanned files with
    no DeployEdge)

Plus the HTML overlay assertions live in `test_topology_html.py` —
this file focuses on the data layer.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.models.topology import (
    DeployEdge,
    Environment,
    Service,
    Topology,
)
from ciguard.topology import aggregate_scan_into_topology, load


FIXTURES = Path(__file__).parent / "fixtures" / "topology"


def _scan_result(*files):
    """Build a scan-repo-shaped dict from a list of (path, sev_counts) tuples."""
    return {
        "repo_path": "/x",
        "files_scanned": len(files),
        "total_findings": sum(sum(c.values()) for _, c in files),
        "by_severity": {},
        "fail_on": None,
        "fails_threshold": False,
        "files": [
            {
                "path": path,
                "platform": "gitlab-ci",
                "score": 0,
                "grade": "F",
                "findings_total": sum(counts.values()),
                "findings_by_severity": counts,
                "suppressed": 0,
            }
            for path, counts in files
        ],
    }


# ---------------------------------------------------------------------------
# Per-edge counts
# ---------------------------------------------------------------------------

class TestPerEdgeCounts:
    def test_matched_edge_carries_severity_counts(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod",
                pipeline=".github/workflows/deploy.yml",
                gates=["manual_approval"],
            )],
        )
        scan = _scan_result(
            (".github/workflows/deploy.yml",
             {"Critical": 1, "High": 2, "Medium": 0, "Low": 3, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["by_edge"]["api::prod"]["Critical"] == 1
        assert agg["by_edge"]["api::prod"]["High"] == 2
        assert agg["by_edge"]["api::prod"]["Low"] == 3
        assert agg["by_edge"]["api::prod"]["total"] == 6

    def test_edge_without_pipeline_path_skipped(self):
        # No pipeline path → can't be matched, but isn't drift either.
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod", pipeline=None,
            )],
        )
        scan = _scan_result()
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["by_edge"] == {}
        assert agg["unmatched_pipelines"] == []


# ---------------------------------------------------------------------------
# Per-environment totals
# ---------------------------------------------------------------------------

class TestPerEnvTotals:
    def test_aggregates_across_multiple_services(self):
        t = Topology(
            services=[Service(id="api"), Service(id="web")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[
                DeployEdge(service="api", environment="prod",
                           pipeline="api.yml", gates=["manual_approval"]),
                DeployEdge(service="web", environment="prod",
                           pipeline="web.yml", gates=["manual_approval"]),
            ],
        )
        scan = _scan_result(
            ("api.yml", {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
            ("web.yml", {"Critical": 0, "High": 3, "Medium": 0, "Low": 0, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        prod = agg["by_env"]["prod"]
        assert prod["Critical"] == 1
        assert prod["High"] == 3
        assert prod["total"] == 4
        # `files` records each matched pipeline (no double-counting).
        assert sorted(prod["files"]) == ["api.yml", "web.yml"]

    def test_environments_with_no_matched_edges_omitted(self):
        # Test env exists but no DeployEdge matches a scanned file → no
        # entry in by_env at all (rather than zero counts).
        t = Topology(
            services=[Service(id="api")],
            environments=[
                Environment(id="dev", tier="development"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[
                DeployEdge(service="api", environment="prod",
                           pipeline="prod.yml", gates=["manual_approval"]),
            ],
        )
        scan = _scan_result(
            ("prod.yml", {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        assert "dev" not in agg["by_env"]
        assert "prod" in agg["by_env"]


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

class TestDrift:
    def test_unmatched_pipeline_when_asserted_file_missing(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod",
                pipeline="renamed-or-deleted.yml", gates=["manual_approval"],
            )],
        )
        scan = _scan_result()
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["unmatched_pipelines"] == ["renamed-or-deleted.yml"]

    def test_unmatched_files_when_orphan_workflow_scanned(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod",
                pipeline="declared.yml", gates=["manual_approval"],
            )],
        )
        scan = _scan_result(
            ("declared.yml", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
            ("orphan.yml",   {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["unmatched_files"] == ["orphan.yml"]

    def test_drift_lists_empty_when_perfectly_aligned(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod",
                pipeline="deploy.yml", gates=["manual_approval"],
            )],
        )
        scan = _scan_result(
            ("deploy.yml", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["unmatched_pipelines"] == []
        assert agg["unmatched_files"] == []

    def test_pipeline_shared_across_services_counts_once_in_unmatched_files(self):
        # Two DeployEdges referencing the same pipeline file — both get
        # the same severity counts; the file isn't drift.
        t = Topology(
            services=[Service(id="api"), Service(id="worker")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[
                DeployEdge(service="api", environment="prod",
                           pipeline="shared.yml", gates=["manual_approval"]),
                DeployEdge(service="worker", environment="prod",
                           pipeline="shared.yml", gates=["manual_approval"]),
            ],
        )
        scan = _scan_result(
            ("shared.yml", {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}),
        )
        agg = aggregate_scan_into_topology(t, scan)
        assert agg["unmatched_files"] == []
        # `files` per env should also dedup: only one entry for shared.yml.
        assert agg["by_env"]["prod"]["files"] == ["shared.yml"]
        # But by_env total counts the findings only once because the
        # underlying scan only counted them once per file.
        assert agg["by_env"]["prod"]["total"] == 2  # api + worker each contribute 1


# ---------------------------------------------------------------------------
# Empty inputs
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_empty_scan_result_no_crash(self):
        t = load(FIXTURES / "sample.topology.yml")
        agg = aggregate_scan_into_topology(t, {"files": []})
        assert agg["by_env"] == {}
        assert agg["by_edge"] == {}
        # All asserted pipelines are unmatched.
        assert len(agg["unmatched_pipelines"]) == len(
            [e for e in t.deploy_edges if e.pipeline]
        )

    def test_empty_topology_no_crash(self):
        scan = _scan_result(("anywhere.yml", {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}))
        agg = aggregate_scan_into_topology(Topology(), scan)
        assert agg["by_env"] == {}
        assert agg["by_edge"] == {}
        assert agg["unmatched_files"] == ["anywhere.yml"]
