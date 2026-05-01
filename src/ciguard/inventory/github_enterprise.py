"""
GitHub Enterprise probe.

Endpoint: `<GHE_URL>/api/v3/meta` — returns `{installed_version, ...}`
on GitHub Enterprise Server (NOT github.com). Auth: bearer token via
`Authorization: token <PAT>`. The PAT only needs the default `repo`
scope to read `/meta`.

Note: github.com's `/api/v3/meta` returns a 404 — this probe is
exclusively for self-hosted GHE. Operators pointing it at github.com
will get a clear "endpoint not found" error message.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class GitHubEnterpriseProbe:
    tool: str = "github-enterprise"
    required_env: List[str] = [
        "CIGUARD_GHE_URL",
        "CIGUARD_GHE_TOKEN",
    ]
    # endoflife.date tracks GHE Server as `github-enterprise-server`.
    endoflife_product: Optional[str] = "github-enterprise-server"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_GHE_URL"].rstrip("/")
        token = env["CIGUARD_GHE_TOKEN"]
        url = f"{base}/api/v3/meta"
        payload = http_get_json(url, headers={"Authorization": f"token {token}"})
        if not isinstance(payload, dict):
            raise ProbeError("GHE /api/v3/meta returned a non-dict body")
        version = payload.get("installed_version")
        if not version:
            raise ProbeError(
                "GHE /api/v3/meta had no `installed_version` — "
                "is this actually GitHub Enterprise Server? github.com "
                "does NOT expose this field."
            )
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=str(version),
            raw={"ghe": payload},
        )


register(GitHubEnterpriseProbe())
