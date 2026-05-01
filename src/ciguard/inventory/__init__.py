"""
ciguard infrastructure inventory (Slice 14b).

Audits the CI/CD *tooling* a customer runs by hitting each tool's
admin API for its version + edition. Cross-references with endoflife.date
to surface EOL/EOS warnings.

Distinct from the rest of ciguard, which scans pipeline *files*. This
module talks to live infrastructure. Every probe is an opt-in: ciguard
only contacts a tool when the operator provides URL + credentials via
env vars. No discovery, no port-scanning — strict env-var gate.

Auth model: each probe declares `required_env` (URL + creds). Missing
any required var → `configured=False`, no network call, silent skip.
Per-tool env-var convention: `CIGUARD_<TOOL>_URL` / `_USER` / `_TOKEN`
or `_PASSWORD`. Documented per probe.

Network model: synchronous HTTP via stdlib `urllib.request` (mirrors
the SCA `osv.py` / `endoflife.py` pattern — no extra deps). Each probe
has its own 8-second default timeout + 5 MB response cap.

Public surface:
- `InventoryRunner.run()` returns an `InventoryReport` covering every
  probe ciguard ships, configured or not. Operator-facing entry point.
- `ALL_PROBES` list — registry of probes for testing + introspection.
"""
from .probes import (
    ALL_PROBES,
    InventoryRunner,
    Probe,
    ProbeError,
)

# Import side-effect: each probe module registers itself into ALL_PROBES.
# Order here is the priority order from the audit-scope spec.
from . import jenkins as _jenkins  # noqa: F401
from . import gitlab as _gitlab  # noqa: F401
from . import github_enterprise as _github_enterprise  # noqa: F401
from . import nexus as _nexus  # noqa: F401
from . import artifactory as _artifactory  # noqa: F401
from . import sonarqube as _sonarqube  # noqa: F401
from . import argocd as _argocd  # noqa: F401
from . import harbor as _harbor  # noqa: F401

__all__ = [
    "ALL_PROBES",
    "InventoryRunner",
    "Probe",
    "ProbeError",
]
