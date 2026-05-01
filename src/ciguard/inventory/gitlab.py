"""
GitLab self-host probe.

Endpoint: `<GITLAB_URL>/api/v4/version` — returns `{version, revision,
enterprise}`. Auth: `PRIVATE-TOKEN` header with a personal access token
(read_api scope is sufficient).

The `enterprise` field distinguishes EE from CE — relevant because the
EOL cycles for EE tend to lag CE on the same `version` string. We
report it as `edition` for the operator's audit narrative.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import http_get_json, register, ProbeError


class GitLabSelfHostProbe:
    tool: str = "gitlab-self-host"
    required_env: List[str] = [
        "CIGUARD_GITLAB_URL",
        "CIGUARD_GITLAB_TOKEN",
    ]
    endoflife_product: Optional[str] = "gitlab"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_GITLAB_URL"].rstrip("/")
        token = env["CIGUARD_GITLAB_TOKEN"]
        url = f"{base}/api/v4/version"
        payload = http_get_json(url, headers={"PRIVATE-TOKEN": token})
        if not isinstance(payload, dict):
            raise ProbeError("GitLab /api/v4/version returned a non-dict body")
        version = payload.get("version")
        if not version:
            raise ProbeError("GitLab /api/v4/version response had no `version`")
        edition_flag = payload.get("enterprise")
        edition = "EE" if edition_flag else "CE"
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=str(version),
            edition=edition,
            raw={"gitlab": payload},
        )


register(GitLabSelfHostProbe())
