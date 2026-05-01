"""
ArgoCD probe.

Endpoint: `<ARGOCD_URL>/api/version` — returns `{Version, BuildDate,
GitCommit, GoVersion, Compiler, Platform, KustomizeVersion, ...}`.

Auth: bearer JWT via `Authorization: Bearer <token>` where `<token>`
is an ArgoCD API token (User → Generate Token). ArgoCD's `/api/version`
returns the version even WITHOUT auth on most installs, but enterprise
installs front it with an SSO/OIDC proxy that requires the token to
pass through — we always send it.

The `BuildDate` field is informational only — recorded in `raw` for
audits but not surfaced as a column.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class ArgoCDProbe:
    tool: str = "argocd"
    required_env: List[str] = [
        "CIGUARD_ARGOCD_URL",
        "CIGUARD_ARGOCD_TOKEN",
    ]
    endoflife_product: Optional[str] = "argo-cd"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_ARGOCD_URL"].rstrip("/")
        token = env["CIGUARD_ARGOCD_TOKEN"]
        url = f"{base}/api/version"
        payload = http_get_json(url, headers={"Authorization": f"Bearer {token}"})
        if not isinstance(payload, dict):
            raise ProbeError("ArgoCD `/api/version` returned a non-dict body")
        # ArgoCD historically used `Version`; newer builds also expose
        # lowercase `version`. Accept both.
        version = payload.get("Version") or payload.get("version")
        if not version:
            raise ProbeError(
                "ArgoCD `/api/version` had no `Version` field — is the "
                "URL pointing at the API server (not a UI proxy)?"
            )
        # Strip the leading 'v' if present so the EOL lookup matches
        # endoflife.date's `cycle` format (`2.10` not `v2.10`).
        version = str(version).lstrip("vV")
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=version,
            raw={"argocd": payload},
        )


register(ArgoCDProbe())
