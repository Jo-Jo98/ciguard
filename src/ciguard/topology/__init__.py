"""
ciguard topology (Slice 16).

Loader + query helpers for the cross-pipeline topology graph. The
pydantic model itself lives in `ciguard.models.topology`; this package
holds the operator-facing surface (YAML loader, validation, future
auto-discovery from `scan-repo` output, future live-API integrations
with GitHub deployment-environments + GitLab environments).

Public surface today:
- `load(path)` — parse a `ciguard.topology.yml` into a validated `Topology`
- `discover(start)` — walk up from `start` looking for `ciguard.topology.yml`,
  same convention as `.ciguardignore`
"""
from .aggregate import aggregate_scan_into_topology
from .loader import discover, load, TopologyLoadError

__all__ = [
    "TopologyLoadError",
    "aggregate_scan_into_topology",
    "discover",
    "load",
]
