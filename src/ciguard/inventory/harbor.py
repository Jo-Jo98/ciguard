"""
Harbor (CNCF container registry) probe.

Endpoint: `<HARBOR_URL>/api/v2.0/systeminfo` — returns a system-info
object including `harbor_version` (versions in the form `v2.10.1-abc`).
Auth: HTTP Basic — username + password (or token-as-password). Read-only
robot account with project-level pull permissions is sufficient.

Some Harbor deployments expose `/api/v2.0/systeminfo/getcert` etc.; we
only call `systeminfo` for the version. The `external_url` /
`auth_mode` fields are recorded in `raw` for forensic interest but not
surfaced as columns.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class HarborProbe:
    tool: str = "harbor"
    required_env: List[str] = [
        "CIGUARD_HARBOR_URL",
        "CIGUARD_HARBOR_USER",
        "CIGUARD_HARBOR_PASSWORD",
    ]
    endoflife_product: Optional[str] = "harbor"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_HARBOR_URL"].rstrip("/")
        user = env["CIGUARD_HARBOR_USER"]
        password = env["CIGUARD_HARBOR_PASSWORD"]
        url = f"{base}/api/v2.0/systeminfo"
        payload = http_get_json(url, auth=(user, password))
        if not isinstance(payload, dict):
            raise ProbeError("Harbor `/api/v2.0/systeminfo` returned a non-dict body")
        version = payload.get("harbor_version")
        if not version:
            raise ProbeError(
                "Harbor `/api/v2.0/systeminfo` had no `harbor_version` field"
            )
        # Harbor versions look like `v2.10.1-abc1234`. Strip the leading 'v'
        # AND the trailing build hash so endoflife matching works.
        version = str(version).lstrip("vV").split("-", 1)[0]
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=version,
            raw={"harbor": payload},
        )


register(HarborProbe())
