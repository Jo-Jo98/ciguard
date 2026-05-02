"""
YAML loader for `ciguard.topology.yml`.

The file is the operator's hand-asserted picture of what their
deployment graph looks like. Subsequent Slice 16 sessions will add
auto-discovery (from `scan-repo` output) and live-API verification
(GitHub deployment environments, GitLab environments) — but the
operator-supplied YAML stays the canonical source of truth, because
intent ('staging→prod requires manual approval') can't always be
inferred from configuration.

Schema (top-level keys all optional):

    services:
      - id: api
        name: User API
        repo: org/api
        tags: [backend]

    environments:
      - id: dev
        tier: development
        region: eu-west-1
      - id: prod
        tier: production
        region: eu-west-1
        network_segment: production

    deploy_edges:
      - service: api
        environment: prod
        pipeline: .github/workflows/deploy-prod.yml
        gates: [manual_approval, required_reviewer]

    transitions:
      - from: staging
        to: prod
        gates: [manual_approval]

    secret_scopes:
      - id: prod-secrets
        environments: [prod]
        services: [api]

    network_segments:
      - id: production
        can_reach: []
      - id: shared
        can_reach: [production]

`TopologyLoadError` wraps every failure mode (file missing, YAML parse
error, schema mismatch, cross-reference unresolved) with the file path
prepended so error messages point at the actual `.yml` file.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from ..models.topology import Topology

TOPOLOGY_FILENAME = "ciguard.topology.yml"


class TopologyLoadError(Exception):
    """Raised when a topology file can't be loaded. Wraps the underlying
    cause (FileNotFoundError / yaml.YAMLError / pydantic ValidationError)
    with a path prefix so operators can find the file fast."""


def load(path: Path) -> Topology:
    """Parse and validate a topology YAML file. Returns a `Topology`
    model with cross-references already resolved (model_validator runs
    at construction)."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise TopologyLoadError(f"{path}: file not found") from exc
    except OSError as exc:
        raise TopologyLoadError(f"{path}: {exc}") from exc
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise TopologyLoadError(f"{path}: invalid YAML — {exc}") from exc
    if not isinstance(data, dict):
        raise TopologyLoadError(
            f"{path}: top-level must be a mapping, got {type(data).__name__}"
        )
    try:
        return Topology.model_validate(data)
    except ValidationError as exc:
        raise TopologyLoadError(f"{path}: schema invalid — {exc}") from exc


def discover(start: Path) -> Optional[Path]:
    """Walk up from `start` looking for `ciguard.topology.yml`. Stops at
    a `.git` directory or the filesystem root. Returns the path or None
    when no file is found. Mirrors the `.ciguardignore` discovery
    convention so operators don't need to learn a different rule."""
    start = Path(start).resolve()
    if start.is_file():
        start = start.parent
    cur = start
    while True:
        candidate = cur / TOPOLOGY_FILENAME
        if candidate.exists():
            return candidate
        if (cur / ".git").exists():
            return None
        if cur.parent == cur:          # filesystem root
            return None
        cur = cur.parent
