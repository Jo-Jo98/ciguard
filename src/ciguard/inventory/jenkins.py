"""
Jenkins probe.

Endpoint: `<JENKINS_URL>/api/json` — returns server metadata including
a `version` field in the response. Auth: HTTP Basic with `<user>:<token>`
where `<token>` is a Jenkins API token (User → Configure → API Token).
The token is preferred over the user's password — Jenkins recommends
this and corp Jenkins instances usually require it for API calls.

Plugin inventory is reachable at `/pluginManager/api/json?depth=1` but
needs the `Overall/Administer` permission. We don't request it by
default (least-privilege); operators wanting plugin visibility can opt
in via a future flag.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class JenkinsProbe:
    tool: str = "jenkins"
    required_env: List[str] = [
        "CIGUARD_JENKINS_URL",
        "CIGUARD_JENKINS_USER",
        "CIGUARD_JENKINS_TOKEN",
    ]
    endoflife_product: Optional[str] = "jenkins"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_JENKINS_URL"].rstrip("/")
        user = env["CIGUARD_JENKINS_USER"]
        token = env["CIGUARD_JENKINS_TOKEN"]
        url = f"{base}/api/json"
        payload = http_get_json(url, auth=(user, token))
        version = None
        if isinstance(payload, dict):
            # Jenkins returns version in `useCrumbs` adjacent fields, but
            # the most reliable place is the `X-Jenkins` HTTP response
            # header — sadly stdlib `urlopen` doesn't expose it via our
            # current helper. Fall back to the manage page mode.
            version = payload.get("version")
            if not version:
                # Jenkins LTS often omits `version` from /api/json; surface
                # a clear error rather than silent skip — operator can
                # add the appropriate role.
                raise ProbeError(
                    "Jenkins /api/json returned no `version` field — "
                    "either an unsupported version or insufficient role "
                    "(needs Overall/Read at minimum)"
                )
        if not version:
            raise ProbeError("Jenkins /api/json returned a non-dict body")
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=str(version),
            raw={"jenkins": payload if isinstance(payload, dict) else {}},
        )


register(JenkinsProbe())
