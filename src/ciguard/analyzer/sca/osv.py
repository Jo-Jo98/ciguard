"""
OSV.dev client + on-disk cache.

OSV.dev is Google's federated open-vulnerability database. It aggregates
GitHub Security Advisories, PyPA advisories, RustSec, npm advisories, etc.
into one queryable API with consistent ecosystem-aware semantics.

For ciguard v0.6.1 we use the `GitHub Actions` ecosystem only. A query like:

    POST https://api.osv.dev/v1/query
    { "package": {"name": "actions/checkout", "ecosystem": "GitHub Actions"},
      "version": "4.0.0" }

returns:

    { "vulns": [
        { "id": "GHSA-xxxx", "summary": "...", "details": "...",
          "aliases": ["CVE-2024-..."],
          "database_specific": {"severity": "MODERATE", ...},
          "affected": [...] },
        ... ] }

Empty `vulns` (or no `vulns` key) means no known advisories at that version.

Caching: file-based at `<cache_dir>/osv-github-actions-<package>.json` with
a 24h TTL (matches endoflife.py). Pipeline scans must stay fast and OSV's
rate limit (~1000/min) is not the bottleneck — laptop network latency is.
Cache misses fall back to network; network errors fall back to a stale
cache if available, otherwise return `None` (rule skips silently).

Offline mode (`--offline` CLI flag): never hits the network. Uses cache if
present, returns `None` otherwise.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

API_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "ciguard-sca/0.6 (+https://github.com/Jo-Jo98/ciguard)"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
DEFAULT_TIMEOUT_SECONDS = 8

# OSV.dev ecosystem string for GitHub Actions advisories. Case-sensitive.
ECOSYSTEM_GITHUB_ACTIONS = "GitHub Actions"


class OSVClient:
    """Thin wrapper around the OSV.dev /v1/query API with an on-disk cache.
    One client instance is shared across all SCA-CVE rule invocations in a
    single scan so cache state and offline mode are consistent."""

    def __init__(
        self,
        cache_dir: Path,
        offline: bool = False,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.cache_dir = cache_dir
        self.offline = offline
        self.ttl_seconds = ttl_seconds
        self.timeout_seconds = timeout_seconds
        # In-memory cache so repeated lookups in one scan don't re-read disk.
        self._mem: dict[str, Optional[list[dict]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def vulns_for_action(self, package: str, version: str) -> Optional[list[dict]]:
        """Return the OSV vuln list for a `(actions/checkout, 4.0.0)` style
        query. Returns `[]` when the package is known to OSV with no
        advisories at that version, `None` when we couldn't reach the data
        at all (offline + no cache, network error + no cache, malformed
        response). Callers should distinguish these — `[]` is "clean",
        `None` is "unknown"."""
        return self._query(ECOSYSTEM_GITHUB_ACTIONS, package, version)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cache_key(self, ecosystem: str, package: str, version: str) -> str:
        # Slashes in `actions/checkout` would break the filename; substitute.
        # Spaces in ecosystem ("GitHub Actions") likewise.
        eco = ecosystem.lower().replace(" ", "-")
        pkg = package.replace("/", "__")
        return f"osv-{eco}-{pkg}-{version}"

    def _cache_path(self, ecosystem: str, package: str, version: str) -> Path:
        return self.cache_dir / f"{self._cache_key(ecosystem, package, version)}.json"

    def _query(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> Optional[list[dict]]:
        mem_key = self._cache_key(ecosystem, package, version)
        if mem_key in self._mem:
            return self._mem[mem_key]
        cached = self._read_cache(ecosystem, package, version)
        if cached is not None and not self._cache_stale(ecosystem, package, version):
            self._mem[mem_key] = cached
            return cached
        if self.offline:
            self._mem[mem_key] = cached
            return cached
        fetched = self._fetch(ecosystem, package, version)
        if fetched is not None:
            self._write_cache(ecosystem, package, version, fetched)
            self._mem[mem_key] = fetched
            return fetched
        # Network error → fall back to stale cache if any.
        self._mem[mem_key] = cached
        return cached

    def _read_cache(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> Optional[list[dict]]:
        path = self._cache_path(ecosystem, package, version)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(
        self,
        ecosystem: str,
        package: str,
        version: str,
        data: list[dict],
    ) -> None:
        path = self._cache_path(ecosystem, package, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass

    def _cache_stale(self, ecosystem: str, package: str, version: str) -> bool:
        path = self._cache_path(ecosystem, package, version)
        if not path.exists():
            return True
        age = time.time() - path.stat().st_mtime
        return age > self.ttl_seconds

    def _fetch(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> Optional[list[dict]]:
        body = json.dumps({
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }).encode("utf-8")
        req = urllib.request.Request(
            API_URL,
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status != 200:
                    return None
                payload = json.loads(resp.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    return None
                vulns = payload.get("vulns")
                if vulns is None:
                    return []  # known clean — distinct from "unknown"
                if not isinstance(vulns, list):
                    return None
                return vulns
        except (urllib.error.HTTPError, urllib.error.URLError,
                json.JSONDecodeError, TimeoutError, OSError):
            return None


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

# Map OSV / GHSA severity labels to ciguard Severity. OSV doesn't always
# include severity inline; when missing, callers fall back to MEDIUM.
_OSV_TO_CIGUARD_SEVERITY: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


def normalise_severity(vuln: dict) -> str:
    """Inspect an OSV vuln dict and return the highest matching ciguard
    Severity name (`"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`).

    OSV exposes severity in two places:
      1. `database_specific.severity` (label string from upstream — GHSA
         uses this).
      2. `severity` array containing CVSS vectors (`type: "CVSS_V3"`,
         `score: "CVSS:3.1/..."`). Score parsing is non-trivial; we lean on
         the label first and only synthesise from CVSS as a fallback.

    Returns `"MEDIUM"` when no signal is present — safe default that won't
    drown in noise but still surfaces the finding."""
    db = vuln.get("database_specific") or {}
    label = db.get("severity")
    if isinstance(label, str):
        mapped = _OSV_TO_CIGUARD_SEVERITY.get(label.upper())
        if mapped:
            return mapped
    # Try CVSS score band as a fallback.
    sev_array = vuln.get("severity") or []
    if isinstance(sev_array, list):
        for entry in sev_array:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            if isinstance(score, str) and score.startswith("CVSS:"):
                # CVSS vector string — we only need the qualitative band.
                # Look for /S:H or /AV:N high-impact hints; this is rough
                # but better than always returning MEDIUM.
                if "/I:H" in score and "/A:H" in score and "/C:H" in score:
                    return "CRITICAL"
                if "/I:H" in score or "/C:H" in score:
                    return "HIGH"
    return "MEDIUM"
