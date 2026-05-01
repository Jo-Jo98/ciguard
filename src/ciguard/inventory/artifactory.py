"""
JFrog Artifactory probe.

Endpoint: `<ARTIFACTORY_URL>/artifactory/api/system/version` — returns
`{version, revision, license}`. (Older deployments expose the same
endpoint at `/api/system/version` without the `/artifactory` prefix;
operators with that layout pass that path in `CIGUARD_ARTIFACTORY_URL`.)

Auth: bearer token via `Authorization: Bearer <token>` (recommended for
Artifactory 7.x access tokens) OR HTTP Basic (`<user>:<password>`,
needed for older 6.x installations). We accept both shapes — if both
`_TOKEN` and `_USER`/`_PASSWORD` env vars are present, token wins.

Edition / license info: the `license` field surfaces the entitlement
(`Pro` / `Enterprise` / `Enterprise Plus` / `OSS`) — recorded as
`edition`. The `revision` field is build-internal and ignored.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class ArtifactoryProbe:
    tool: str = "artifactory"
    # URL is required; auth is (token) OR (user + password). Validated
    # in probe() because the runner's `required_env` check is strict-AND.
    required_env: List[str] = ["CIGUARD_ARTIFACTORY_URL"]
    endoflife_product: Optional[str] = "artifactory"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_ARTIFACTORY_URL"].rstrip("/")
        token = env.get("CIGUARD_ARTIFACTORY_TOKEN")
        user = env.get("CIGUARD_ARTIFACTORY_USER")
        password = env.get("CIGUARD_ARTIFACTORY_PASSWORD")
        if not token and not (user and password):
            raise ProbeError(
                "set CIGUARD_ARTIFACTORY_TOKEN (recommended for 7.x) OR "
                "CIGUARD_ARTIFACTORY_USER + CIGUARD_ARTIFACTORY_PASSWORD"
            )
        # Support both `<base>/api/system/version` (operator pre-prefixed) and
        # `<base>/artifactory/api/system/version` (default install layout).
        # Detect pre-prefix by checking the URL *path* — substring matching
        # against the full URL is unsafe (`/artifactory` matches `//host`).
        from urllib.parse import urlsplit
        parts = urlsplit(base)
        if parts.path.rstrip("/").endswith("/artifactory") or "/artifactory/" in parts.path:
            url = f"{base}/api/system/version"
        else:
            url = f"{base}/artifactory/api/system/version"
        if token:
            payload = http_get_json(url, headers={"Authorization": f"Bearer {token}"})
        else:
            payload = http_get_json(url, auth=(user, password))
        if not isinstance(payload, dict):
            raise ProbeError("Artifactory response was not a JSON object")
        version = payload.get("version")
        if not version:
            raise ProbeError("Artifactory `/api/system/version` had no `version` field")
        edition = payload.get("license")
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=str(version),
            edition=str(edition) if edition else None,
            license=str(edition) if edition else None,
            raw={"artifactory": payload},
        )


register(ArtifactoryProbe())
