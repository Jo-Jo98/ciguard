"""
Probe protocol + HTTP helper + runner orchestration.

A `Probe` is one tool's "go ask the admin API for the version" plug-in:

  - `tool` — short canonical id (`jenkins`, `gitlab-self-host`, ...)
  - `required_env` — the env vars that must be set for this probe to run
  - `endoflife_product` — endoflife.date slug to cross-reference (or None)
  - `probe(env)` — read env, call the admin API, return an `InventoryEntry`

The `InventoryRunner` walks every probe registered in `ALL_PROBES`,
honours the env-var gate (silently skips unconfigured probes), and
collects results into one `InventoryReport`.

Why the env-var gate is silent: an unconfigured tool means "we don't
audit this here". An error in a configured tool is loud. The two
states must not be confusable in the audit narrative.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol

from ..analyzer.sca.endoflife import EndOfLifeClient
from ..models.inventory import InventoryEntry, InventoryReport

USER_AGENT = "ciguard-inventory/0.1 (+https://github.com/Jo-Jo98/ciguard)"
DEFAULT_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class ProbeError(Exception):
    """Raised by a probe when the API call ran but the response is unusable
    (bad JSON, missing version field). Caught by the runner and surfaced
    via `InventoryEntry.error`."""


class Probe(Protocol):
    """Static surface a probe must expose."""
    tool: str
    required_env: List[str]
    endoflife_product: Optional[str]

    def probe(self, env: Dict[str, str]) -> InventoryEntry: ...


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def http_get_json(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[tuple[str, str]] = None,
) -> Any:
    """GET `url`, expect JSON, return parsed payload. Raises ProbeError on
    HTTP failure / non-JSON body / oversize response.

    Auth is HTTP basic via `Authorization` header — same shape every
    admin API in our priority list accepts (Jenkins token-as-password,
    GitLab personal-access-token, GHE PAT, Nexus / Artifactory user+pw).
    Bearer-token shape is built by the caller passing `headers=...`.
    """
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if auth is not None:
        import base64
        user, secret = auth
        token = base64.b64encode(f"{user}:{secret}".encode("utf-8")).decode("ascii")
        req_headers["Authorization"] = f"Basic {token}"
    req = urllib.request.Request(url, headers=req_headers)
    try:
        # B310: urls are operator-supplied via env vars; this is the
        # documented entry surface. Same trust model as the SCA clients.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status != 200:
                raise ProbeError(f"HTTP {resp.status}")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ProbeError(
                    f"response exceeded {MAX_RESPONSE_BYTES} bytes — refusing"
                )
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProbeError(f"response is not valid JSON: {exc}")
    except urllib.error.HTTPError as exc:
        # Surface auth failures + 404s as actionable error messages.
        msg = f"HTTP {exc.code}"
        if exc.code in (401, 403):
            msg += " — check credentials / token scope"
        elif exc.code == 404:
            msg += " — endpoint not found (wrong URL or unsupported version?)"
        raise ProbeError(msg)
    except urllib.error.URLError as exc:
        raise ProbeError(f"network error: {exc.reason}")
    except (TimeoutError, OSError) as exc:
        raise ProbeError(f"connection failed: {exc}")


# ---------------------------------------------------------------------------
# EOL enrichment
# ---------------------------------------------------------------------------

def _days_until(date_field: object, today: datetime) -> Optional[int]:
    """Days from `today` until `date_field` (ISO date string). Negative =
    past the date. None if missing / unparseable. Mirrors the SCA helper
    of the same name."""
    if not date_field or date_field is False:
        return None
    try:
        d = datetime.fromisoformat(str(date_field)).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (d - today).days


def enrich_with_eol(
    entry: InventoryEntry,
    eol_client: EndOfLifeClient,
    *,
    today: Optional[datetime] = None,
) -> InventoryEntry:
    """Look up `entry.tool`'s endoflife.date cycle for `entry.version` and
    populate the EOL/EOS fields. Returns the same entry mutated for
    convenience. Silent skip when there's no version, no product slug,
    or endoflife has no matching cycle."""
    if not entry.version or entry.error:
        return entry
    # The Probe stores its endoflife product slug on the class; the runner
    # passes it in via `entry.raw['_endoflife_product']`.
    product = entry.raw.get("_endoflife_product")
    if not product:
        return entry
    cycles = eol_client.cycles_for_product(product)
    if not cycles:
        return entry
    cycle = EndOfLifeClient.find_cycle(cycles, entry.version)
    if not cycle:
        # Try matching the major.minor only — vendors often publish patch
        # versions (`2.426.3`) but endoflife tracks at `2.426`.
        parts = entry.version.split(".")
        if len(parts) >= 2:
            cycle = EndOfLifeClient.find_cycle(cycles, ".".join(parts[:2]))
    if not cycle:
        return entry
    now = today or datetime.now(tz=timezone.utc)
    eol_raw = cycle.get("eol")
    if eol_raw and eol_raw is not False:
        entry.eol_date = str(eol_raw)
        entry.days_until_eol = _days_until(eol_raw, now)
    support_raw = cycle.get("support")
    if support_raw and support_raw is not False:
        entry.eos_date = str(support_raw)
        entry.days_until_eos = _days_until(support_raw, now)
    return entry


# ---------------------------------------------------------------------------
# Probe registry — populated by individual probe modules
# ---------------------------------------------------------------------------

ALL_PROBES: List[Probe] = []


def register(probe: Probe) -> Probe:
    """Decorator-style registration so probes can be defined module-locally
    and collected at import time."""
    ALL_PROBES.append(probe)
    return probe


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class InventoryRunner:
    """Walks `ALL_PROBES`, returns one `InventoryReport`.

    Constructor args:
      - `probes` — explicit list to run; defaults to `ALL_PROBES` (the
        global registry). Tests pass a smaller list.
      - `env` — env-var source; defaults to `os.environ`. Tests pass a
        synthetic dict so they don't depend on shell state.
      - `eol_cache_dir` — passed through to the shared `EndOfLifeClient`
        so cross-tool runs share the on-disk cache.
      - `eol_offline` — when True, skip the network for EOL enrichment.
    """

    def __init__(
        self,
        probes: Optional[Iterable[Probe]] = None,
        *,
        env: Optional[Dict[str, str]] = None,
        eol_cache_dir: Optional[Path] = None,
        eol_offline: bool = False,
    ) -> None:
        self.probes = list(probes) if probes is not None else list(ALL_PROBES)
        self.env: Dict[str, str] = dict(env) if env is not None else dict(os.environ)
        cache_dir = eol_cache_dir or (Path.home() / ".ciguard" / "cache")
        self.eol_client = EndOfLifeClient(cache_dir=cache_dir, offline=eol_offline)

    def _is_configured(self, probe: Probe) -> bool:
        return all(self.env.get(k) for k in probe.required_env)

    def run(self) -> InventoryReport:
        """Run every probe (configured or not). Each probe contributes one
        entry; unconfigured probes get a stub entry with `configured=False`.
        Errors thrown by a probe land in the entry's `error` field — the
        runner never crashes on a single probe failure."""
        entries: List[InventoryEntry] = []
        for probe in self.probes:
            if not self._is_configured(probe):
                entries.append(InventoryEntry(
                    tool=probe.tool,
                    configured=False,
                    notes=[f"required env: {', '.join(probe.required_env)}"],
                ))
                continue
            try:
                entry = probe.probe(self.env)
            except ProbeError as exc:
                entry = InventoryEntry(
                    tool=probe.tool,
                    configured=True,
                    error=str(exc),
                )
            except Exception as exc:  # pragma: no cover — last-resort guard
                entry = InventoryEntry(
                    tool=probe.tool,
                    configured=True,
                    error=f"unexpected: {type(exc).__name__}: {exc}",
                )
            # Stash the endoflife slug so enrich_with_eol can read it
            # without needing to look the probe up by name.
            entry.raw.setdefault("_endoflife_product", probe.endoflife_product)
            enrich_with_eol(entry, self.eol_client)
            entries.append(entry)
        return InventoryReport(entries=entries)
