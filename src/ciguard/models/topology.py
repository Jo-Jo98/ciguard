"""
Multi-environment topology data model (Slice 16, session 1).

The topology is the *cross-pipeline* picture: which services exist, which
environments they deploy to, which gates separate environment transitions,
which secret scopes are shared, which environments can reach which others
at the network level.

Distinct from the per-pipeline `Report` model (parsed from a single CI
file) and the per-org `InventoryReport` (live admin-API audit). The
topology is the *operator-asserted* graph that sits above both — what
the human in the loop says is true. Subsequent sessions in Slice 16
will (a) auto-derive a partial topology from `scan-repo` output, then
(b) cross-check against live deployment-environment / branch-protection
APIs to flag drift between asserted and actual.

Entities (each gets its own pydantic model):
- `Service`      — a deployable unit (typically one repo's worth of code)
- `Environment`  — `dev` / `test` / `staging` / `prod`-style target
- `DeployEdge`   — service S deploys to environment E via pipeline file P
- `EnvTransition`— promotion path env A → env B with required gates
- `SecretScope`  — named secret group + which envs/services can read it
- `NetworkSegment` — env grouping by reachability (production / shared / dmz)
- `Topology`     — aggregate root + integrity validation
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Identifiers — all entity IDs are short kebab-case strings, matched
# case-sensitively. We don't validate format aggressively because
# operator-supplied topology files in real organisations vary; instead
# we assert uniqueness within each entity collection in Topology.
# ---------------------------------------------------------------------------


class Service(BaseModel):
    """A deployable unit. Maps 1:1 with a repo in most cases; multi-service
    repos can declare multiple. The `id` is the cross-reference target —
    `DeployEdge.service` and `SecretScope.services` resolve via this id."""
    id: str
    name: Optional[str] = None
    repo: Optional[str] = None        # `org/repo` or full URL
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class Environment(BaseModel):
    """A deployment target. `tier` is the DORA-style classification; the
    audit narrative uses tier (not id) when it talks about 'production'
    vs 'non-production' so the same model serves orgs that name their
    prod environment `prod` / `production` / `live` / `prd`."""
    id: str
    tier: Optional[str] = None        # e.g. development / staging / production
    region: Optional[str] = None      # e.g. eu-west-1 / us-east-1
    network_segment: Optional[str] = None  # references NetworkSegment.id
    description: Optional[str] = None


class DeployEdge(BaseModel):
    """Service S is deployed to environment E by pipeline file P, gated by
    G. `pipeline` is a repo-relative path (e.g. `.github/workflows/deploy-prod.yml`)
    so cross-referencing with a `scan-repo` output is mechanical.

    Gates are free-form strings from a recognised vocabulary:
    `manual_approval`, `required_reviewer`, `branch_protection`,
    `required_status_check`, `wait_timer`, `deployment_environment_protection`.
    Unknown strings are accepted (operators may have org-specific gate
    names) but the audit narrative only highlights recognised ones."""
    service: str                      # → Service.id
    environment: str                  # → Environment.id
    pipeline: Optional[str] = None    # repo-relative path
    gates: List[str] = Field(default_factory=list)


class EnvTransition(BaseModel):
    """Promotion path between two environments. `from_env` → `to_env`,
    gated by `gates`. Captures the auditor's question 'what stops a
    staging build from going straight to prod?' — the answer is the
    `gates` list (or its absence)."""
    from_env: str = Field(alias="from")
    to_env: str = Field(alias="to")
    gates: List[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class SecretScope(BaseModel):
    """A named bag of secrets + which envs/services can read it. Useful
    for blast-radius questions: 'if this secret leaks, which services /
    environments are exposed?'"""
    id: str
    description: Optional[str] = None
    environments: List[str] = Field(default_factory=list)  # → Environment.id list
    services: List[str] = Field(default_factory=list)      # → Service.id list


class NetworkSegment(BaseModel):
    """Network reachability grouping. Environments belong to at most one
    segment via `Environment.network_segment`. `can_reach` is the list
    of OTHER segments this segment can initiate connections to. Empty =
    isolated. The graph is intentionally directional — `production`
    typically can't reach `dev`, but a CI runner segment can reach both."""
    id: str
    description: Optional[str] = None
    can_reach: List[str] = Field(default_factory=list)


class Topology(BaseModel):
    """Aggregate root. Holds every entity collection + integrity-validates
    cross-references at construction time so a malformed topology fails
    loud at load, not at query time."""
    services: List[Service] = Field(default_factory=list)
    environments: List[Environment] = Field(default_factory=list)
    deploy_edges: List[DeployEdge] = Field(default_factory=list)
    transitions: List[EnvTransition] = Field(default_factory=list)
    secret_scopes: List[SecretScope] = Field(default_factory=list)
    network_segments: List[NetworkSegment] = Field(default_factory=list)

    @field_validator("services", "environments", "secret_scopes", "network_segments")
    @classmethod
    def _ids_unique(cls, v):
        seen: Set[str] = set()
        for entity in v:
            if entity.id in seen:
                raise ValueError(f"duplicate id: {entity.id!r}")
            seen.add(entity.id)
        return v

    @model_validator(mode="after")
    def _cross_references_resolve(self):
        service_ids = {s.id for s in self.services}
        env_ids = {e.id for e in self.environments}
        segment_ids = {n.id for n in self.network_segments}

        for env in self.environments:
            if env.network_segment and env.network_segment not in segment_ids:
                raise ValueError(
                    f"environment {env.id!r} references unknown network "
                    f"segment {env.network_segment!r}"
                )
        for edge in self.deploy_edges:
            if edge.service not in service_ids:
                raise ValueError(
                    f"deploy_edge references unknown service {edge.service!r}"
                )
            if edge.environment not in env_ids:
                raise ValueError(
                    f"deploy_edge references unknown environment {edge.environment!r}"
                )
        for transition in self.transitions:
            if transition.from_env not in env_ids:
                raise ValueError(
                    f"transition references unknown from_env "
                    f"{transition.from_env!r}"
                )
            if transition.to_env not in env_ids:
                raise ValueError(
                    f"transition references unknown to_env {transition.to_env!r}"
                )
        for scope in self.secret_scopes:
            for sid in scope.services:
                if sid not in service_ids:
                    raise ValueError(
                        f"secret_scope {scope.id!r} references unknown "
                        f"service {sid!r}"
                    )
            for eid in scope.environments:
                if eid not in env_ids:
                    raise ValueError(
                        f"secret_scope {scope.id!r} references unknown "
                        f"environment {eid!r}"
                    )
        for seg in self.network_segments:
            for target in seg.can_reach:
                if target not in segment_ids:
                    raise ValueError(
                        f"network_segment {seg.id!r} can_reach unknown "
                        f"segment {target!r}"
                    )
        return self

    # ------------------------------------------------------------------
    # Query helpers — answer the auditor questions named in the
    # audit-scope spec without callers having to walk the graph by hand.
    # ------------------------------------------------------------------

    def pipelines_for_environment(self, env_id: str) -> List[DeployEdge]:
        """'Which pipelines deploy to <env>?' Returns every DeployEdge
        whose `environment` matches."""
        return [e for e in self.deploy_edges if e.environment == env_id]

    def services_sharing_secret(self, secret_scope_id: str) -> List[str]:
        """'Which services share secret scope <id>?' Returns the explicit
        services list (not transitively expanded via env membership)."""
        for scope in self.secret_scopes:
            if scope.id == secret_scope_id:
                return list(scope.services)
        raise KeyError(secret_scope_id)

    def transitions_without_gates(self) -> List[EnvTransition]:
        """'Which env→env transitions have no approval gate?' Returns
        every transition with an empty `gates` list. The audit narrative
        flags these as a posture concern (typically dev→staging is OK
        but staging→prod without a gate is a finding)."""
        return [t for t in self.transitions if not t.gates]

    def reachable_segments(self, segment_id: str) -> Set[str]:
        """Transitive closure of `can_reach` from `segment_id`. Returns
        every segment reachable via any chain of `can_reach` edges
        (excluding the source itself unless cyclically reachable)."""
        graph: Dict[str, List[str]] = {
            s.id: list(s.can_reach) for s in self.network_segments
        }
        if segment_id not in graph:
            raise KeyError(segment_id)
        visited: Set[str] = set()
        stack = list(graph[segment_id])
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            stack.extend(graph.get(node, []))
        return visited

    def production_environments(self) -> List[Environment]:
        """Convenience: every Environment whose `tier` matches the
        production-naming vocabulary. Used by the audit narrative when
        it talks about 'prod' without forcing operators to use a
        specific id."""
        prod_tiers = {"production", "prod", "live"}
        return [e for e in self.environments if (e.tier or "").lower() in prod_tiers]
