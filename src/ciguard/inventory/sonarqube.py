"""
SonarQube probe.

Endpoint: `<SONAR_URL>/api/server/version` — returns the version string
as plain text (NOT JSON). A small special-case in the probe handles the
text response. Auth: HTTP Basic with `<token>:` (token as username,
empty password) per SonarQube's documented API auth pattern.

Anonymous SonarQube installs return the version without auth — the
probe still passes the token because most enterprise installs require
it, and SonarQube ignores extra Authorization headers when anonymous.

Edition (Community / Developer / Enterprise / Data Center) lives at
`/api/system/info` which requires `Administer System` permission. Not
queried by default (least-privilege); future opt-in flag could surface it.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Dict, List, Optional

from ..models.inventory import InventoryEntry
from .probes import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    register,
    ProbeError,
)


class SonarQubeProbe:
    tool: str = "sonarqube"
    required_env: List[str] = [
        "CIGUARD_SONAR_URL",
        "CIGUARD_SONAR_TOKEN",
    ]
    endoflife_product: Optional[str] = "sonarqube"

    def probe(self, env: Dict[str, str]) -> InventoryEntry:
        base = env["CIGUARD_SONAR_URL"].rstrip("/")
        token = env["CIGUARD_SONAR_TOKEN"]
        url = f"{base}/api/server/version"
        # Plain-text response, not JSON — call urllib directly.
        import base64
        auth_token = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Authorization": f"Basic {auth_token}",
            "Accept": "text/plain",
        })
        try:
            # B310: operator-supplied URL via env var; documented entry surface.
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:  # nosec B310
                if resp.status != 200:
                    raise ProbeError(f"HTTP {resp.status}")
                body = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ProbeError("response exceeded size cap")
                version = body.decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as exc:
            msg = f"HTTP {exc.code}"
            if exc.code in (401, 403):
                msg += " — check token (must be a SonarQube user token, not a project token)"
            raise ProbeError(msg)
        except urllib.error.URLError as exc:
            raise ProbeError(f"network error: {exc.reason}")
        except (TimeoutError, OSError) as exc:
            raise ProbeError(f"connection failed: {exc}")
        if not version:
            raise ProbeError("SonarQube `/api/server/version` returned an empty body")
        return InventoryEntry(
            tool=self.tool,
            base_url=base,
            configured=True,
            version=version,
            raw={"sonarqube": {"version": version}},
        )


register(SonarQubeProbe())
