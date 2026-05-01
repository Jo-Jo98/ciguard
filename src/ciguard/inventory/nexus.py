"""
Sonatype Nexus Repository Manager probe.

Endpoint: `<NEXUS_URL>/service/rest/v1/status` — returns a status object
with no version directly. The actual version lives at the `Server` HTTP
header on every response, but our urlopen helper doesn't expose
headers, so we hit `<NEXUS_URL>/service/rest/v1/status/check` instead
which returns a JSON dict that includes the version on Nexus 3.x in
the `nexus_version` field of `node.api`. Newer versions expose
`/service/rest/v1/system/info` which has a `version` field directly.

Nexus 3.x — defaults to Pro vs OSS detection via the `edition` field
in the system-info response.

Auth: HTTP Basic — username + password (Nexus's API doesn't accept
tokens for the status endpoint without `Settings → API → user-tokens`
being enabled). Read-only role with `nx-component-upload-config-read`
plus `nx-script-read` is sufficient.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class NexusProbe:
    tool: str = "nexus"
    required_env: List[str] = [
        "CIGUARD_NEXUS_URL",
        "CIGUARD_NEXUS_USER",
        "CIGUARD_NEXUS_PASSWORD",
    ]
    endoflife_product: Optional[str] = "nexus"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_NEXUS_URL"].rstrip("/")
        user = env["CIGUARD_NEXUS_USER"]
        password = env["CIGUARD_NEXUS_PASSWORD"]
        # `/service/rest/v1/system/info` requires nx-system-info-read; on
        # most installs the read-only audit user has this. Falls back to
        # `/status/check` if 403.
        info_url = f"{base}/service/rest/v1/system/info"
        try:
            payload = http_get_json(info_url, auth=(user, password))
        except ProbeError as exc:
            if "HTTP 403" in str(exc) or "HTTP 404" in str(exc):
                # Older Nexus or no system-info permission — try status/check
                # which only needs nx-status-read.
                check_url = f"{base}/service/rest/v1/status/check"
                payload = http_get_json(check_url, auth=(user, password))
            else:
                raise
        if not isinstance(payload, dict):
            raise ProbeError("Nexus response was not a JSON object")
        version = (
            payload.get("version")
            or _nested_get(payload, ["nexus", "version"])
            or _nested_get(payload, ["node", "api", "nexus_version"])
        )
        if not version:
            raise ProbeError(
                "Nexus response did not include a recognisable version field "
                "(checked top-level `version`, `nexus.version`, "
                "`node.api.nexus_version`)"
            )
        edition = payload.get("edition")
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=str(version),
            edition=str(edition) if edition else None,
            raw={"nexus": payload},
        )


def _nested_get(payload: dict, path: List[str]):
    cur = payload
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
        if cur is None:
            return None
    return cur


register(NexusProbe())
