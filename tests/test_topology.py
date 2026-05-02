"""
Tests for the multi-environment topology model + YAML loader (Slice 16,
session 1).

Three layers:
- Model — pydantic validation, cross-reference integrity, query helpers
- Loader — YAML parse, error wrapping, discovery walk
- Realistic fixture — `tests/fixtures/topology/sample.topology.yml`
  exercises every entity type at least once
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

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
from ciguard.topology import discover, load, TopologyLoadError

FIXTURES = Path(__file__).parent / "fixtures" / "topology"


# ---------------------------------------------------------------------------
# Model — entity construction + cross-reference validation
# ---------------------------------------------------------------------------

class TestTopologyConstruction:
    def test_empty_topology_valid(self):
        t = Topology()
        assert t.services == []
        assert t.environments == []

    def test_minimal_valid(self):
        t = Topology(
            services=[Service(id="api")],
            environments=[Environment(id="prod", tier="production")],
            deploy_edges=[DeployEdge(service="api", environment="prod")],
        )
        assert t.deploy_edges[0].service == "api"

    def test_duplicate_service_id_rejected(self):
        with pytest.raises(ValidationError, match="duplicate id"):
            Topology(services=[Service(id="api"), Service(id="api")])

    def test_duplicate_env_id_rejected(self):
        with pytest.raises(ValidationError, match="duplicate id"):
            Topology(environments=[Environment(id="prod"), Environment(id="prod")])

    def test_deploy_edge_unknown_service_rejected(self):
        with pytest.raises(ValidationError, match="unknown service"):
            Topology(
                environments=[Environment(id="prod")],
                deploy_edges=[DeployEdge(service="ghost", environment="prod")],
            )

    def test_deploy_edge_unknown_env_rejected(self):
        with pytest.raises(ValidationError, match="unknown environment"):
            Topology(
                services=[Service(id="api")],
                deploy_edges=[DeployEdge(service="api", environment="ghost")],
            )

    def test_transition_unknown_env_rejected(self):
        with pytest.raises(ValidationError, match="unknown from_env"):
            Topology(
                environments=[Environment(id="prod")],
                transitions=[EnvTransition(**{"from": "ghost", "to": "prod"})],
            )

    def test_secret_scope_unknown_service_rejected(self):
        with pytest.raises(ValidationError, match="unknown service"):
            Topology(
                environments=[Environment(id="prod")],
                secret_scopes=[
                    SecretScope(id="x", environments=["prod"], services=["ghost"]),
                ],
            )

    def test_environment_unknown_segment_rejected(self):
        with pytest.raises(ValidationError, match="unknown network segment"):
            Topology(environments=[
                Environment(id="prod", network_segment="ghost"),
            ])

    def test_network_segment_unknown_target_rejected(self):
        with pytest.raises(ValidationError, match="can_reach unknown"):
            Topology(network_segments=[
                NetworkSegment(id="a", can_reach=["ghost"]),
            ])


class TestTransitionAlias:
    def test_from_keyword_via_alias(self):
        # `from` is reserved in Python — pydantic alias lets the YAML use it.
        t = EnvTransition(**{"from": "dev", "to": "prod"})
        assert t.from_env == "dev"
        assert t.to_env == "prod"


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_topology() -> Topology:
    return load(FIXTURES / "sample.topology.yml")


class TestQueries:
    def test_pipelines_for_environment(self, sample_topology):
        prod_edges = sample_topology.pipelines_for_environment("prod")
        # api + web + worker all deploy to prod in the fixture.
        assert {e.service for e in prod_edges} == {"api", "web", "worker"}

    def test_pipelines_for_environment_empty(self, sample_topology):
        assert sample_topology.pipelines_for_environment("test") == []

    def test_services_sharing_secret(self, sample_topology):
        services = sample_topology.services_sharing_secret("prod-db")
        assert set(services) == {"api", "worker"}

    def test_services_sharing_secret_unknown_raises(self, sample_topology):
        with pytest.raises(KeyError):
            sample_topology.services_sharing_secret("does-not-exist")

    def test_transitions_without_gates(self, sample_topology):
        gateless = sample_topology.transitions_without_gates()
        # Fixture has dev→prod with no gates as the deliberate red flag.
        assert any(t.from_env == "dev" and t.to_env == "prod" for t in gateless)
        # staging→prod has a gate — must NOT appear.
        assert not any(t.from_env == "staging" and t.to_env == "prod" for t in gateless)

    def test_reachable_segments(self, sample_topology):
        # `shared → production`; `production` is isolated.
        assert sample_topology.reachable_segments("shared") == {"production"}
        assert sample_topology.reachable_segments("production") == set()

    def test_reachable_segments_unknown_raises(self, sample_topology):
        with pytest.raises(KeyError):
            sample_topology.reachable_segments("ghost")

    def test_production_environments(self, sample_topology):
        prods = sample_topology.production_environments()
        assert [e.id for e in prods] == ["prod"]


class TestProductionTierMatching:
    def test_matches_alternate_prod_names(self):
        t = Topology(environments=[
            Environment(id="a", tier="prod"),
            Environment(id="b", tier="production"),
            Environment(id="c", tier="LIVE"),       # case-insensitive
            Environment(id="d", tier="staging"),    # not prod
        ])
        ids = {e.id for e in t.production_environments()}
        assert ids == {"a", "b", "c"}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class TestLoad:
    def test_loads_sample_fixture(self):
        t = load(FIXTURES / "sample.topology.yml")
        assert len(t.services) == 3
        assert len(t.environments) == 4
        assert len(t.deploy_edges) == 5

    def test_missing_file_wrapped_error(self, tmp_path):
        with pytest.raises(TopologyLoadError, match="file not found"):
            load(tmp_path / "nope.yml")

    def test_invalid_yaml_wrapped(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("services:\n  - id: api\n  oops bad indent\n")
        with pytest.raises(TopologyLoadError, match="invalid YAML"):
            load(path)

    def test_top_level_must_be_mapping(self, tmp_path):
        path = tmp_path / "list.yml"
        path.write_text("- one\n- two\n")
        with pytest.raises(TopologyLoadError, match="top-level must be a mapping"):
            load(path)

    def test_schema_violation_wrapped(self, tmp_path):
        path = tmp_path / "schema.yml"
        path.write_text(
            "services:\n  - id: api\n"
            "deploy_edges:\n  - service: api\n    environment: ghost\n"
        )
        with pytest.raises(TopologyLoadError, match="schema invalid"):
            load(path)

    def test_empty_file_yields_empty_topology(self, tmp_path):
        path = tmp_path / "empty.yml"
        path.write_text("")
        t = load(path)
        assert t.services == []


class TestDiscover:
    def test_finds_in_same_dir(self, tmp_path):
        (tmp_path / "ciguard.topology.yml").write_text("services: []\n")
        assert discover(tmp_path) == tmp_path / "ciguard.topology.yml"

    def test_walks_up_to_parent(self, tmp_path):
        (tmp_path / "ciguard.topology.yml").write_text("services: []\n")
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert discover(nested) == tmp_path / "ciguard.topology.yml"

    def test_stops_at_git_marker(self, tmp_path):
        # Place .git so discovery stops in the inner repo (no topology found
        # there) instead of walking up to a parent that has one.
        (tmp_path / "ciguard.topology.yml").write_text("services: []\n")
        inner = tmp_path / "subrepo"
        inner.mkdir()
        (inner / ".git").mkdir()
        nested = inner / "deep"
        nested.mkdir()
        assert discover(nested) is None

    def test_returns_none_when_absent(self, tmp_path):
        assert discover(tmp_path) is None

    def test_accepts_a_file_path_as_start(self, tmp_path):
        # Operators sometimes pass a file path; we walk up from its parent.
        (tmp_path / "ciguard.topology.yml").write_text("services: []\n")
        a_file = tmp_path / "main.py"
        a_file.write_text("# placeholder\n")
        assert discover(a_file) == tmp_path / "ciguard.topology.yml"
