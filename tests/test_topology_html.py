"""
Tests for the standalone topology HTML reporter (Slice 16, session 2).

Pure-function reporter — no JavaScript, no headless browser needed.
Assertions exercise the rendered string for the structural elements
that matter for the audit narrative: the swimlane grid, the gateless
warnings banner, the bottom panels, and the print-mode CSS.

The tests reuse the sample topology fixture from session 1 to avoid
re-asserting model-construction invariants (those live in
test_topology.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ciguard.models.topology import (
    DeployEdge,
    EnvTransition,
    Environment,
    NetworkSegment,
    SecretScope,
    Service,
    Topology,
)
from ciguard.reporter import topology_html
from ciguard.topology import load

FIXTURES = Path(__file__).parent / "fixtures" / "topology"


@pytest.fixture
def sample() -> Topology:
    return load(FIXTURES / "sample.topology.yml")


# ---------------------------------------------------------------------------
# Document shape
# ---------------------------------------------------------------------------


class TestDocument:
    def test_returns_html5(self, sample):
        out = topology_html.render(sample)
        assert out.startswith("<!DOCTYPE html>")
        assert "<title>ciguard topology</title>" in out
        assert "</html>" in out

    def test_summary_line_includes_counts(self, sample):
        out = topology_html.render(sample)
        # Sample fixture has 3 services + 4 environments + 5 deploy edges.
        assert "3 services" in out
        assert "4 environments" in out
        assert "5 deploy edges" in out

    def test_print_media_block_present(self, sample):
        out = topology_html.render(sample)
        assert "@media print" in out


# ---------------------------------------------------------------------------
# Swimlane grid
# ---------------------------------------------------------------------------


class TestSwimlane:
    def test_environments_ordered_by_tier(self, sample):
        out = topology_html.render(sample)
        # The sample has dev / test / staging / prod — they should appear
        # in that order left-to-right inside the table.
        idx_dev = out.find('class="env-id">dev<')
        idx_test = out.find('class="env-id">test<')
        idx_stg = out.find('class="env-id">staging<')
        idx_prod = out.find('class="env-id">prod<')
        assert -1 < idx_dev < idx_test < idx_stg < idx_prod

    def test_production_env_header_marked(self, sample):
        out = topology_html.render(sample)
        # The `prod` column header should pick up the `prod` CSS class.
        assert 'env-header prod' in out

    def test_services_with_no_edges_omitted(self):
        # Service `lonely` has no deploy_edges → must NOT appear in the grid.
        t = Topology(
            services=[
                Service(id="api"), Service(id="lonely"),
            ],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
        )
        out = topology_html.render(t)
        assert 'service-id">api<' in out
        assert 'service-id">lonely<' not in out

    def test_deploy_cell_with_gates_renders_gate_chips(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api", environment="prod",
                pipeline=".github/workflows/deploy-prod.yml",
                gates=["manual_approval", "branch_protection"],
            )],
        )
        out = topology_html.render(t)
        assert "manual_approval" in out
        assert "branch_protection" in out
        assert ".github/workflows/deploy-prod.yml" in out

    def test_gateless_prod_deploy_marked_danger(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="api", environment="prod", gates=[])],
        )
        out = topology_html.render(t)
        # Both: a `cell deploy danger` class AND the no-gates badge.
        assert "cell deploy danger" in out
        assert "no gates" in out

    def test_empty_cell_for_non_deploy(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[
                Environment(id="dev", tier="development"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
        )
        out = topology_html.render(t)
        # `dev` cell for `api` is empty.
        assert "cell empty" in out


# ---------------------------------------------------------------------------
# Transition row
# ---------------------------------------------------------------------------


class TestTransitions:
    def test_adjacent_transition_renders_arrow(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[
                Environment(id="staging", tier="staging"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
            transitions=[EnvTransition(**{"from": "staging", "to": "prod",
                                          "gates": ["manual_approval"]})],
        )
        out = topology_html.render(t)
        assert "trans-arrow ok" in out
        # The transition gate label should appear in the transition row.
        assert "manual_approval" in out

    def test_gateless_transition_rendered_danger(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[
                Environment(id="staging", tier="staging"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
            transitions=[EnvTransition(**{"from": "staging", "to": "prod"})],
        )
        out = topology_html.render(t)
        assert "trans-arrow danger" in out


# ---------------------------------------------------------------------------
# Top-of-page warnings banner
# ---------------------------------------------------------------------------


class TestWarningsBanner:
    def test_banner_renders_for_gateless_prod_edge(self):
        t = Topology(
            services=[Service(id="worker")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="worker", environment="prod", gates=[])],
        )
        out = topology_html.render(t)
        assert "Posture warnings" in out
        assert "worker" in out
        assert "no gates" in out

    def test_banner_renders_for_gateless_transition_to_prod(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[
                Environment(id="dev", tier="development"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
            transitions=[EnvTransition(**{"from": "dev", "to": "prod"})],
        )
        out = topology_html.render(t)
        assert "Posture warnings" in out
        assert "no approval gate" in out

    def test_banner_omitted_when_clean(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
        )
        out = topology_html.render(t)
        assert "Posture warnings" not in out


# ---------------------------------------------------------------------------
# Bottom panels
# ---------------------------------------------------------------------------


class TestPanels:
    def test_secret_scope_panel_renders(self, sample):
        out = topology_html.render(sample)
        assert "Secret-scope blast radius" in out
        assert "prod-db" in out
        assert "shared-monitoring" in out

    def test_secret_panel_omitted_when_no_scopes(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="api", environment="prod",
                                     gates=["manual_approval"])],
        )
        out = topology_html.render(t)
        assert "Secret-scope blast radius" not in out

    def test_network_panel_renders_reachability(self, sample):
        out = topology_html.render(sample)
        assert "Network reachability" in out
        # `shared` reaches `production` in the sample fixture.
        assert "shared" in out and "production" in out

    def test_isolated_segment_marked(self):
        t = Topology(
            network_segments=[NetworkSegment(id="dmz", can_reach=[])],
        )
        out = topology_html.render(t)
        assert "isolated" in out


# ---------------------------------------------------------------------------
# HTML escaping — defence against operator-supplied evil
# ---------------------------------------------------------------------------


class TestEscaping:
    def test_service_id_escaped(self):
        t = Topology(
            services=[Service(id="api<script>alert(1)</script>")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(
                service="api<script>alert(1)</script>",
                environment="prod",
                gates=["manual_approval"],
            )],
        )
        out = topology_html.render(t)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------


class TestWriteReport:
    def test_creates_parent_dir(self, sample, tmp_path):
        target = tmp_path / "deep" / "nested" / "topology.html"
        result = topology_html.write_report(sample, target)
        assert result == target
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


# ---------------------------------------------------------------------------
# Scan-aggregate overlay (Slice 16, session 3)
# ---------------------------------------------------------------------------


class TestAggregateOverlay:
    def _topology(self) -> Topology:
        return Topology(
            services=[Service(id="api"), Service(id="web")],
            environments=[
                Environment(id="staging", tier="staging"),
                Environment(id="prod", tier="production"),
            ],
            deploy_edges=[
                DeployEdge(service="api", environment="prod",
                           pipeline="api-deploy.yml",
                           gates=["manual_approval"]),
                DeployEdge(service="web", environment="prod",
                           pipeline="web-deploy.yml",
                           gates=["manual_approval"]),
                DeployEdge(service="api", environment="staging",
                           pipeline="api-staging.yml",
                           gates=["branch_protection"]),
            ],
        )

    def _aggregate(self):
        return {
            "by_env": {
                "prod": {
                    "Critical": 1, "High": 2, "Medium": 0, "Low": 0, "Info": 0,
                    "total": 3, "files": ["api-deploy.yml", "web-deploy.yml"],
                },
                "staging": {
                    "Critical": 0, "High": 0, "Medium": 0, "Low": 1, "Info": 0,
                    "total": 1, "files": ["api-staging.yml"],
                },
            },
            "by_edge": {
                "api::prod": {
                    "Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
                    "total": 1, "file": "api-deploy.yml",
                },
                "web::prod": {
                    "Critical": 0, "High": 2, "Medium": 0, "Low": 0, "Info": 0,
                    "total": 2, "file": "web-deploy.yml",
                },
                "api::staging": {
                    "Critical": 0, "High": 0, "Medium": 0, "Low": 1, "Info": 0,
                    "total": 1, "file": "api-staging.yml",
                },
            },
            "unmatched_pipelines": [],
            "unmatched_files": [],
        }

    def test_severity_chips_render_per_cell(self):
        t = self._topology()
        out = topology_html.render(t, self._aggregate())
        # Critical and High are surfaced via single-letter chips.
        assert "1 C" in out         # api::prod 1 Critical
        assert "2 H" in out         # web::prod 2 High
        assert "1 L" in out         # api::staging 1 Low

    def test_env_header_carries_totals_strip(self):
        t = self._topology()
        out = topology_html.render(t, self._aggregate())
        # `class="env-totals"` only appears inside an env header when the
        # overlay actually populated it (the bare `env-totals` class
        # appears in the CSS regardless).
        assert 'class="env-totals"' in out

    def test_summary_line_includes_matched_findings_count(self):
        t = self._topology()
        out = topology_html.render(t, self._aggregate())
        assert "4 matched findings" in out  # 3 prod + 1 staging

    def test_clean_cell_marker_when_aggregate_present_but_no_findings(self):
        # Aggregate present, but a particular edge has zero findings.
        t = self._topology()
        agg = self._aggregate()
        agg["by_edge"]["api::staging"] = {
            **{sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")},
            "total": 0, "file": "api-staging.yml",
        }
        out = topology_html.render(t, agg)
        assert ">clean<" in out  # the clean-cell marker

    def test_drift_panel_renders_unmatched_pipelines(self):
        t = self._topology()
        agg = self._aggregate()
        agg["unmatched_pipelines"] = ["renamed.yml"]
        out = topology_html.render(t, agg)
        assert "Drift between asserted topology and scan" in out
        assert "renamed.yml" in out

    def test_drift_panel_renders_unmatched_files(self):
        t = self._topology()
        agg = self._aggregate()
        agg["unmatched_files"] = ["orphan.yml"]
        out = topology_html.render(t, agg)
        assert "no DeployEdge" in out
        assert "orphan.yml" in out

    def test_drift_panel_omitted_when_perfectly_aligned(self):
        t = self._topology()
        out = topology_html.render(t, self._aggregate())
        assert "Drift between asserted topology and scan" not in out

    def test_no_overlay_when_aggregate_is_none(self):
        # Backwards compat — render(topology) without an aggregate must
        # still work and must not emit the overlay-only classes.
        # We check `class="..."` (rendered usage) rather than bare class
        # names because the CSS rules are always inlined.
        t = self._topology()
        out = topology_html.render(t)
        assert 'class="env-totals"' not in out
        assert 'class="findings clean"' not in out
        assert "matched findings (scan overlay)" not in out
